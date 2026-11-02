"""The runtime-usage overlay: of what was granted, what was actually used.

Depth plan wave 2, Phase 1.1.

An effective-permission answer says what an identity *could* do. The access
review in 1.2 and the right-sizing recommendation both turn on the other
half — what it *did* — and the only place that exists is the event lake,
where every cloud and identity audit event the platform ingests lands with
its action already normalised onto ``raw_events.action``.

The one thing this module must never do
---------------------------------------
Report "used nothing" when it means "could not look". The lake is a
``full``-profile component, so on a CORE install there is nothing to query,
and an empty result there is not a measurement. Every function here returns
a :class:`UsageCollection` carrying ``measured``, and the store it writes to
keeps the same distinction: an absent row means not observed, and whether
that means "not used" or "not measured" is answered by whether a collection
ran at all.

The failure this prevents is concrete and large: a right-sizing finding
built on an unmeasured empty set recommends revoking every permission in the
estate, and it recommends it with exactly the same confidence as a correct
finding.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.clickhouse import execute_lake_query
from app.services.identity_privilege_store import record_usage

logger = structlog.get_logger(__name__)

__all__ = ["DEFAULT_WINDOW_DAYS", "UsageCollection", "collect_usage_for_tenant"]

#: The trailing window a right-sizing finding is computed over. Ninety days
#: rather than thirty because quarterly work is real: an access review that
#: calls a permission unused after a month flags every quarter-close job in
#: the estate, and a review that cries wolf is one nobody runs twice.
DEFAULT_WINDOW_DAYS = 90

#: Cap on rows pulled from one lake query. A principal with more distinct
#: actions than this is a wildcard-admin whose right-sizing answer is "this
#: is everything" either way, so truncating costs nothing and an unbounded
#: scan on a shared lake costs real money.
MAX_ACTIONS_PER_PRINCIPAL = 500

#: Which lake ``connector_type`` values belong to which posture provider.
#: Explicit rather than inferred: ``aws_cloudtrail`` and ``aws_security_hub``
#: both start ``aws_``, and only one of them carries API actions.
PROVIDER_CONNECTORS: dict[str, tuple[str, ...]] = {
    "aws": ("aws_cloudtrail", "aws_eventbridge"),
    "azure": ("azure_entra", "azure_activity", "azure_monitor"),
    "gcp": ("gcp_audit", "gcp_scc"),
    "gws": ("google_workspace",),
    "github": ("github",),
    "okta": ("okta",),
}


@dataclass(frozen=True)
class UsageCollection:
    """One collection run, and whether it measured anything at all."""

    measured: bool
    principals: int = 0
    rows_written: int = 0
    window_start: datetime | None = None
    window_end: datetime | None = None
    #: Why nothing was measured, when nothing was. Present so a caller can
    #: render the reason rather than a zero.
    reason: str | None = None
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "measured": self.measured,
            "principals": self.principals,
            "rows_written": self.rows_written,
            "window_start": self.window_start.isoformat() if self.window_start else None,
            "window_end": self.window_end.isoformat() if self.window_end else None,
            "reason": self.reason,
            "notes": list(self.notes),
        }


async def collect_usage_for_tenant(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID,
    provider: str,
    principals: list[str],
    window_days: int = DEFAULT_WINDOW_DAYS,
) -> UsageCollection:
    """Observe which actions ``principals`` exercised, and record them.

    Returns ``measured=False`` with a reason whenever the lake could not be
    asked. The caller must propagate that rather than treating zero rows as
    an observation.
    """
    connectors = PROVIDER_CONNECTORS.get(provider)
    if not connectors:
        return UsageCollection(measured=False, reason=f"no lake connector types are mapped to provider {provider!r}")
    names = [p.strip() for p in principals if p and p.strip()]
    if not names:
        return UsageCollection(measured=False, reason="no principals were supplied")

    window_end = datetime.now(tz=UTC)
    window_start = window_end - timedelta(days=max(1, window_days))

    sql = """
        SELECT user_name, action, count() AS uses,
               min(event_time) AS first_used, max(event_time) AS last_used
        FROM aisoc.raw_events
        WHERE tenant_id = %(tenant_id)s
          AND event_time >= %(window_start)s
          AND event_time <= %(window_end)s
          AND connector_type IN %(connectors)s
          AND lower(user_name) IN %(principals)s
          AND action != ''
        GROUP BY user_name, action
        ORDER BY uses DESC
        LIMIT %(limit)s
    """
    params = {
        "tenant_id": str(tenant_id),
        "window_start": window_start,
        "window_end": window_end,
        "connectors": tuple(connectors),
        "principals": tuple(n.lower() for n in names),
        "limit": MAX_ACTIONS_PER_PRINCIPAL * max(1, len(names)),
    }

    try:
        result = await execute_lake_query(sql, params=params)
    except Exception as exc:  # noqa: BLE001 — an unreachable lake is not an empty one
        logger.warning("identity_usage.lake_unavailable", provider=provider, error=type(exc).__name__)
        return UsageCollection(
            measured=False,
            reason=(
                f"the event lake could not be queried ({type(exc).__name__}). Usage is unknown, not zero; "
                f"the lake is a `full`-profile component and is absent on a CORE install."
            ),
            window_start=window_start,
            window_end=window_end,
        )

    columns = list(result.columns or [])
    by_principal: dict[str, dict[str, tuple[int, datetime | None, datetime | None]]] = {}
    for row in result.rows or ():
        record = dict(zip(columns, row, strict=False))
        principal = str(record.get("user_name") or "").strip()
        action = str(record.get("action") or "").strip()
        if not principal or not action:
            continue
        by_principal.setdefault(principal, {})[action] = (
            int(record.get("uses") or 0),
            _as_dt(record.get("first_used")),
            _as_dt(record.get("last_used")),
        )

    written = 0
    for principal, observations in by_principal.items():
        written += await record_usage(
            db,
            tenant_id=tenant_id,
            provider=provider,
            principal_id=principal,
            observations=observations,
            window_start=window_start,
            window_end=window_end,
        )

    notes: list[str] = []
    silent = sorted({n.lower() for n in names} - {p.lower() for p in by_principal})
    if silent:
        # A principal with zero events in the window is a measured
        # observation -- the lake answered and it did nothing -- and that is
        # the dormant-admin finding 1.2 looks for. Recorded as a note rather
        # than as rows, because there is no action to write a row against.
        notes.append(f"{len(silent)} principal(s) had no recorded activity in the window: {', '.join(silent[:10])}")

    return UsageCollection(
        measured=True,
        principals=len(by_principal),
        rows_written=written,
        window_start=window_start,
        window_end=window_end,
        notes=notes,
    )


def _as_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None
