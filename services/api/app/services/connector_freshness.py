"""Freshness SLO computation for connector instances (Workstream 5).

The plan calls for green/yellow/red badges on every connector card driven
by ``now() - last_event_at`` against a per-class expected cadence. This
module is the canonical source-of-truth for that rule: keep it pure,
synchronous, and tightly tested so the API endpoint stays a thin
projection over ``Connector`` rows.

Two design decisions worth calling out:

1. **The expected-cadence table is keyed by connector category, not by
   connector_type.** The plan explicitly calls out per-class cadence
   ("5 min for EDR, 1 hr for vuln scanners"). Categories are stable
   (``cloud``, ``edr``, ``iam``, ``network``, ``saas``, ``siem``, ``vcs``,
   plus ``vuln``/``email``/``ticketing`` once those P0 connectors land)
   and cheap to extend. Hard-coding per-vendor numbers would force a
   release every time a new connector ships.

2. **A connector with no events ever (``last_event_at IS NULL``) is
   ``unknown``, not red.** A brand-new install that has never polled
   should not paint red on the dashboard the moment it lands — that
   would generate noise in the very onboarding flow Workstream 1 is
   trying to make feel seamless. Red is reserved for "we *had* events
   and they stopped".

Status ladder
-------------

* ``unknown``  — no ``last_event_at`` (connector hasn't seen its first
                 event, or the row was just created).
* ``green``    — fresh: ``age <= cadence``.
* ``yellow``   — late but not panic: ``cadence < age <= 2 * cadence``.
* ``red``      — stale: ``age > 2 * cadence``.

The 2x multiplier matches the plan's posture of "tolerate one missed
poll cycle before paging the operator". Operators can tune cadence
overrides per-instance via ``connector_config.expected_cadence_seconds``
(WS5 follow-up); the override path lands in the resolver below so the
default table stays the floor.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

# ----------------------------------------------------------------- cadence table

# Per-category cadence in seconds. Keep these conservative so the badge
# stays green during a normal poll cycle (default poll interval is 300s
# in services/connectors/app/scheduler.py — anything tighter than that
# would flap green/yellow on every empty poll).
#
# The category names exactly match ``Connector.category`` values used by
# the catalog (see services/api/app/data/connector_catalog_fallback.json
# and services/connectors/app/connectors/<id>.py::connector_category).
# A category not in this table falls through to ``_DEFAULT_CADENCE_S``.
_CADENCE_BY_CATEGORY: dict[str, int] = {
    # EDR/XDR: alerts are time-critical; 5 min cadence per the plan.
    "edr": 5 * 60,
    # SIEM: 15 min cadence — search-job APIs (Sumo, Chronicle, Splunk)
    # are batched, and the existing scheduler default polls every 5 min,
    # so 15 min gives ~3 poll cycles of slack before flagging yellow.
    "siem": 15 * 60,
    # Identity / SSO: 30 min cadence. Audit log volume is bursty — the
    # cadence should tolerate a quiet window without flapping red on a
    # weekend morning.
    "iam": 30 * 60,
    # SaaS audit logs (Slack, Salesforce, Auth0, M365): 30 min — same
    # reasoning as IAM.
    "saas": 30 * 60,
    # Network / DNS (Cisco Umbrella, Cloudflare): 30 min, batched APIs.
    "network": 30 * 60,
    # Cloud posture / CSPM (AWS GuardDuty, Lacework, Azure Defender):
    # 30 min — findings refresh on the order of tens of minutes.
    "cloud": 30 * 60,
    # VCS (GitHub, Atlassian, GitLab once it lands): 15 min — push
    # events are dense for active repos.
    "vcs": 15 * 60,
    # Vuln scanners (Tenable, Snyk, Qualys): 60 min per the plan. Scans
    # legitimately run on hour-long cadences.
    "vuln": 60 * 60,
    # Email security (Mimecast, Defender for O365): 15 min — phishing
    # alerts are time-critical.
    "email": 15 * 60,
    # Ticketing (Jira, ServiceNow, PagerDuty): 30 min. ITSM systems
    # rarely fire every minute and the noise floor for these is high.
    "ticketing": 30 * 60,
}

# Catch-all when ``Connector.category`` is unknown (legacy rows, brand-new
# category before this table is updated). 30 min is the median across the
# table above and is conservative enough not to false-alarm.
_DEFAULT_CADENCE_S = 30 * 60

# Multiplier for the yellow→red boundary. 2x ≈ "we tolerated one missed
# cycle, now we're paging".
_RED_MULTIPLIER = 2.0


# ----------------------------------------------------------------- public API


@dataclass(frozen=True)
class FreshnessSLO:
    """Freshness verdict for a single connector instance.

    Frozen so the response builder can't accidentally mutate it after
    the fact. ``status`` is one of ``unknown|green|yellow|red`` and is
    the only field the UI actually needs to color the badge — the rest
    are surfaced for the "why is this yellow?" tooltip.
    """

    status: str
    expected_cadence_seconds: int
    seconds_since_last_event: int | None
    # Echoed back so the UI can render "Expected within 5 min" without
    # re-doing the lookup. Also useful for tests.
    category: str

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the shape FastAPI surfaces in JSON responses."""
        return {
            "status": self.status,
            "expected_cadence_seconds": self.expected_cadence_seconds,
            "seconds_since_last_event": self.seconds_since_last_event,
            "category": self.category,
        }


def expected_cadence_seconds(
    category: str | None,
    *,
    override_seconds: int | None = None,
) -> int:
    """Resolve the expected cadence for a category, honoring an override.

    Operators can override the default per-instance via
    ``connector_config.expected_cadence_seconds`` once that knob is
    surfaced in the wizard (WS5 follow-up). Until then the override is
    ``None`` and we always return the table value. Negative or zero
    overrides are silently rejected — they would force the SLO into
    permanent red and almost certainly mean a typo.
    """
    if override_seconds is not None and override_seconds > 0:
        return int(override_seconds)
    if not category:
        return _DEFAULT_CADENCE_S
    return _CADENCE_BY_CATEGORY.get(category.lower(), _DEFAULT_CADENCE_S)


def compute_freshness(
    *,
    category: str | None,
    last_event_at: datetime | None,
    now: datetime | None = None,
    override_seconds: int | None = None,
) -> FreshnessSLO:
    """Compute the freshness SLO for a connector instance.

    Pure function: takes the three inputs the rule depends on and
    returns the verdict. No DB access, no clock side-effects (``now``
    is injectable so tests can pin time deterministically). The caller
    (the connectors API endpoint) is responsible for projecting this
    onto the response model.
    """
    cadence = expected_cadence_seconds(category, override_seconds=override_seconds)
    cat = (category or "").lower() or "unknown"

    if last_event_at is None:
        # Brand-new connector that has never seen an event. Don't paint
        # red — the onboarding flow polls /last_event_at to wait for
        # this exact transition.
        return FreshnessSLO(
            status="unknown",
            expected_cadence_seconds=cadence,
            seconds_since_last_event=None,
            category=cat,
        )

    # Be defensive against drivers that strip tzinfo. ``Connector.last_event_at``
    # is declared ``DateTime(timezone=True)`` so this should be a no-op
    # in practice, but a naive datetime would otherwise raise on subtraction.
    ts = last_event_at if last_event_at.tzinfo else last_event_at.replace(tzinfo=UTC)
    current = now if now is not None else datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)

    age = max(0, int((current - ts).total_seconds()))
    if age <= cadence:
        status = "green"
    elif age <= int(cadence * _RED_MULTIPLIER):
        status = "yellow"
    else:
        status = "red"

    return FreshnessSLO(
        status=status,
        expected_cadence_seconds=cadence,
        seconds_since_last_event=age,
        category=cat,
    )
