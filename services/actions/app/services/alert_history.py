"""Closed-finding history readers: the analyst labels replay evaluation grades against.

Gap-closure Phase 1.1.

AiSOC can already push a verdict *into* somebody else's SIEM
(:mod:`app.services.disposition_writeback`). This module is the other
direction: read back the findings a customer's own analysts already closed, so
triage can be measured against their decisions on their data before anyone is
asked to trust it.

Why the taxonomy work lives here and not in each client
=======================================================

The five clients own the credential path and the HTTP, and nothing else. Every
vendor label lands in one table in this module for two reasons. A per-client
mapping is five places to disagree about what "benign positive" means, and the
writeback in the opposite direction already reads one canonical vocabulary, so
a second one would let a verdict mean one thing going out and another coming
back.

The rule that matters most
==========================

**A label outside the canonical set becomes** :data:`UNLABELED` **and is
excluded from accuracy. It is never guessed at.**

This is the difference between an evaluation and a sales sheet. Splunk ES
disposition 5 is literally named "Other" and disposition 6 "Undetermined";
Sentinel and Defender both ship an explicit ``Undetermined`` / ``Unknown``
classification. An analyst who selected one of those said "I do not know", and
folding that into ``true_positive`` because the finding happened to be closed
would manufacture agreement out of an analyst's admission of uncertainty. The
scoring layer counts these separately and reports them, so a customer whose
history is mostly unlabeled sees that fact rather than a confident number
derived from a handful of rows.

:data:`UNLABELED` is deliberately **not** a member of
``CANONICAL_DISPOSITIONS``. Anything that treats it as a verdict fails a
membership check rather than silently scoring it.

A note on Elastic
=================

Four of the five vendors ship a first-class disposition field. Elastic Security
does not: a signal carries ``kibana.alert.workflow_status`` of ``open``,
``acknowledged`` or ``closed``, and closing one records no reason. So the
honest Elastic reader returns :data:`UNLABELED` for every closed signal unless
the deployment has adopted a workflow tag, and
:func:`map_elastic_disposition` reads that tag against a documented
convention. Inventing an Elastic taxonomy so the column looked as full as the
other four would have made every Elastic row a fabricated label.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.services.disposition_writeback import (
    BENIGN,
    BENIGN_TRUE_POSITIVE,
    CANONICAL_DISPOSITIONS,
    FALSE_POSITIVE,
    TRUE_POSITIVE,
)

#: An analyst closed the finding without recording a disposition this platform
#: can name. Excluded from accuracy rather than guessed. Deliberately not a
#: member of ``CANONICAL_DISPOSITIONS``.
UNLABELED = "unlabeled"

__all__ = [
    "UNLABELED",
    "ClosedFinding",
    "map_defender_disposition",
    "map_elastic_disposition",
    "map_qradar_disposition",
    "map_sentinel_disposition",
    "map_splunk_disposition",
    "parse_defender_alert",
    "parse_elastic_signal",
    "parse_qradar_offense",
    "parse_sentinel_incident",
    "parse_splunk_notable",
]


@dataclass(frozen=True)
class ClosedFinding:
    """One finding a human already closed, with the label they chose.

    ``raw`` carries the vendor payload untouched so the replay runner can hand
    it to the same connector ``normalize()`` production uses, rather than
    normalizing a second way here and grading the agent on an input shape it
    never sees in production.
    """

    vendor: str
    finding_id: str
    title: str
    #: Canonical disposition, or :data:`UNLABELED`.
    disposition: str
    #: The vendor's own label, kept verbatim. A reader who disagrees with a
    #: mapping needs to see what was actually recorded, and an unmapped label
    #: is worth reporting back rather than discarding.
    vendor_disposition: str
    closed_at: datetime
    closed_by: str | None = None
    reason: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.disposition != UNLABELED and self.disposition not in CANONICAL_DISPOSITIONS:
            raise ValueError(
                f"{self.disposition!r} is neither canonical nor {UNLABELED!r}. A mapper returned "
                f"a value the taxonomy does not define, which would be scored as if an analyst "
                f"had chosen it."
            )

    @property
    def is_labelled(self) -> bool:
        """Whether this row may contribute to accuracy."""
        return self.disposition != UNLABELED


def _coerce_time(value: Any) -> datetime:
    """Best-effort vendor timestamp to an aware UTC datetime.

    Vendors disagree: Splunk sends epoch seconds as a string, QRadar epoch
    milliseconds as an int, and the Microsoft APIs ISO-8601 with a ``Z``. An
    unparseable value raises rather than defaulting to "now", because a
    silently-wrong close time would put a finding on the wrong side of the
    train/test split and leak the answer into its own evaluation.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, (int, float)):
        # QRadar milliseconds vs Splunk seconds. 10^11 seconds is year 5138,
        # so anything above it is unambiguously milliseconds.
        seconds = float(value) / 1000.0 if float(value) > 1e11 else float(value)
        return datetime.fromtimestamp(seconds, tz=UTC)
    if isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            return _coerce_time(float(text))
        except ValueError:
            pass
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"unparseable close time {value!r}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    raise ValueError(f"unparseable close time {value!r}")


def _norm(label: object) -> str:
    return str(label or "").strip().lower().replace("-", "_").replace(" ", "_")


def _submap(row: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    """Read a nested mapping, or an empty one when it is missing or not a mapping.

    Both Microsoft APIs nest the fields that matter (``properties`` on a
    Sentinel incident, ``_source`` on an Elastic hit), and a vendor that
    returns ``null`` there should yield an empty row rather than an
    ``AttributeError`` three lines later.
    """
    value = row.get(key)
    return value if isinstance(value, Mapping) else {}


def _first_rule_id(value: object) -> str | None:
    """Read the first analytic-rule id off a Sentinel incident.

    Sentinel returns a list because one incident can be raised by several
    rules. The first is recorded so a per-rule breakdown has a key; the full
    list stays in ``raw`` for anyone who needs it.
    """
    if isinstance(value, (list, tuple)) and value:
        return str(value[0])
    return None


def _opt_str(row: Mapping[str, Any], key: str) -> str | None:
    """Read an optional string field, collapsing empty and absent to ``None``.

    ``None`` and ``""`` mean the same thing here: the vendor did not record
    it. Keeping them distinct would put empty strings in the closed-by column
    of a report.
    """
    value = row.get(key)
    return str(value) if value else None


# --------------------------------------------------------------------------
# Splunk Enterprise Security
# --------------------------------------------------------------------------

#: Splunk ES ships six dispositions out of the box, keyed ``disposition:N``.
#: 5 ("Other") and 6 ("Undetermined") are absent on purpose: both are an
#: analyst declining to classify, so both fall through to UNLABELED. Sites may
#: add custom dispositions from 7 upward; those are unmapped by construction.
_SPLUNK_DISPOSITIONS: dict[str, str] = {
    "disposition:1": TRUE_POSITIVE,  # True Positive - Suspicious Activity
    "disposition:2": BENIGN_TRUE_POSITIVE,  # Benign Positive - Suspicious But Expected
    "disposition:3": FALSE_POSITIVE,  # False Positive - Incorrect Analytic Logic
    "disposition:4": FALSE_POSITIVE,  # False Positive - Inaccurate Data
    # Splunk also renders the labels rather than the keys in some exports.
    "true_positive_suspicious_activity": TRUE_POSITIVE,
    "benign_positive_suspicious_but_expected": BENIGN_TRUE_POSITIVE,
    "false_positive_incorrect_analytic_logic": FALSE_POSITIVE,
    "false_positive_inaccurate_data": FALSE_POSITIVE,
}


def map_splunk_disposition(label: object) -> str:
    """Map a Splunk ES notable disposition to the canonical taxonomy."""
    return _SPLUNK_DISPOSITIONS.get(_norm(label), UNLABELED)


def parse_splunk_notable(row: Mapping[str, Any]) -> ClosedFinding:
    """Parse one closed Splunk ES notable from a ``/services/search/jobs`` result row."""
    raw_label = row.get("disposition") or ""
    return ClosedFinding(
        vendor="splunk",
        finding_id=str(row.get("event_id") or row.get("rule_id") or ""),
        title=str(row.get("rule_name") or row.get("search_name") or ""),
        disposition=map_splunk_disposition(raw_label),
        vendor_disposition=str(raw_label),
        closed_at=_coerce_time(row.get("review_time") or row.get("_time")),
        closed_by=_opt_str(row, "reviewer"),
        reason=_opt_str(row, "comment"),
        rule_id=_opt_str(row, "rule_id"),
        severity=(_opt_str(row, "urgency") or "").lower() or None,
        raw=dict(row),
    )


# --------------------------------------------------------------------------
# Microsoft Sentinel
# --------------------------------------------------------------------------

#: Sentinel's ``classification`` on a closed incident. ``Undetermined`` is a
#: first-class choice in the product and is left unmapped on purpose.
_SENTINEL_CLASSIFICATIONS: dict[str, str] = {
    "truepositive": TRUE_POSITIVE,
    "benignpositive": BENIGN_TRUE_POSITIVE,
    "falsepositive": FALSE_POSITIVE,
}


def map_sentinel_disposition(label: object) -> str:
    """Map a Microsoft Sentinel incident classification to the canonical taxonomy."""
    return _SENTINEL_CLASSIFICATIONS.get(_norm(label).replace("_", ""), UNLABELED)


def parse_sentinel_incident(row: Mapping[str, Any]) -> ClosedFinding:
    """Parse one closed Sentinel incident from the ARM incidents API."""
    props = _submap(row, "properties")
    raw_label = props.get("classification") or ""
    closed_by_field = props.get("closedBy")
    closer: Any = closed_by_field
    if isinstance(closed_by_field, Mapping):
        closer = closed_by_field.get("userPrincipalName") or closed_by_field.get("name")
    # `classificationReason` is the structured half; `classificationComment`
    # is the analyst's prose. Both are useful and neither is always present.
    reason_parts = [str(props[k]) for k in ("classificationReason", "classificationComment") if props.get(k)]
    return ClosedFinding(
        vendor="sentinel",
        finding_id=str(row.get("name") or props.get("incidentNumber") or ""),
        title=str(props.get("title") or ""),
        disposition=map_sentinel_disposition(raw_label),
        vendor_disposition=str(raw_label),
        closed_at=_coerce_time(props.get("lastModifiedTimeUtc") or props.get("closedTime")),
        closed_by=(str(closer) if closer else None),
        reason=(": ".join(reason_parts) or None),
        rule_id=_first_rule_id(props.get("relatedAnalyticRuleIds")),
        severity=(_opt_str(props, "severity") or "").lower() or None,
        raw=dict(row),
    )


# --------------------------------------------------------------------------
# Elastic Security
# --------------------------------------------------------------------------

#: Elastic ships no disposition field. A deployment that wants its history
#: graded adopts one of these workflow tags; everything else is UNLABELED.
#: Documented in `apps/docs/docs/evaluation/replay.md` so the convention is
#: something an operator can adopt rather than something this code assumes.
_ELASTIC_WORKFLOW_TAGS: dict[str, str] = {
    "true_positive": TRUE_POSITIVE,
    "benign_positive": BENIGN_TRUE_POSITIVE,
    "benign_true_positive": BENIGN_TRUE_POSITIVE,
    "false_positive": FALSE_POSITIVE,
    "benign": BENIGN,
}


def map_elastic_disposition(tags: object) -> str:
    """Map Elastic ``kibana.alert.workflow_tags`` to the canonical taxonomy.

    Returns :data:`UNLABELED` when no recognised tag is present, which is the
    common case: closing an Elastic signal records no reason, so an untagged
    deployment yields no labels at all. Two conflicting tags also yield
    :data:`UNLABELED`, because picking one would be a guess.
    """
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, (list, tuple)):
        return UNLABELED
    found = {_ELASTIC_WORKFLOW_TAGS[_norm(t)] for t in tags if _norm(t) in _ELASTIC_WORKFLOW_TAGS}
    return found.pop() if len(found) == 1 else UNLABELED


def parse_elastic_signal(row: Mapping[str, Any]) -> ClosedFinding:
    """Parse one closed Elastic Security signal from a ``_search`` hit."""
    nested = _submap(row, "_source")
    src: Mapping[str, Any] = nested or row
    tags = src.get("kibana.alert.workflow_tags") or src.get("tags") or []
    return ClosedFinding(
        vendor="elastic",
        finding_id=str(row.get("_id") or src.get("kibana.alert.uuid") or ""),
        title=str(src.get("kibana.alert.rule.name") or src.get("message") or ""),
        disposition=map_elastic_disposition(tags),
        vendor_disposition=",".join(str(t) for t in tags) if tags else "",
        closed_at=_coerce_time(src.get("kibana.alert.workflow_status_updated_at") or src.get("@timestamp")),
        closed_by=(str(src["kibana.alert.workflow_user"]) if src.get("kibana.alert.workflow_user") else None),
        reason=(str(src["kibana.alert.workflow_reason"]) if src.get("kibana.alert.workflow_reason") else None),
        rule_id=(str(src["kibana.alert.rule.uuid"]) if src.get("kibana.alert.rule.uuid") else None),
        severity=(str(src["kibana.alert.severity"]).lower() if src.get("kibana.alert.severity") else None),
        raw=dict(row),
    )


# --------------------------------------------------------------------------
# IBM QRadar
# --------------------------------------------------------------------------

#: QRadar closing reasons are site-configurable; these three ship by default.
#: "Non-Issue" maps to ``benign`` rather than ``benign_true_positive`` because
#: it makes no claim about whether the rule was right, which is exactly the
#: distinction ``benign`` exists to carry. A custom reason is UNLABELED.
_QRADAR_CLOSING_REASONS: dict[str, str] = {
    "false_positive,_tuned": FALSE_POSITIVE,
    "false_positive_tuned": FALSE_POSITIVE,
    "non_issue": BENIGN,
    "policy_violation": TRUE_POSITIVE,
}


def map_qradar_disposition(label: object) -> str:
    """Map a QRadar offense closing reason to the canonical taxonomy."""
    return _QRADAR_CLOSING_REASONS.get(_norm(label), UNLABELED)


def parse_qradar_offense(row: Mapping[str, Any]) -> ClosedFinding:
    """Parse one closed QRadar offense from ``/api/siem/offenses``.

    ``closing_reason_name`` is resolved by the client from
    ``/api/siem/offense_closing_reasons``; the offense itself only carries the
    numeric ``closing_reason_id``, and a number is not a label anyone can map.
    """
    raw_label = row.get("closing_reason_name") or ""
    return ClosedFinding(
        vendor="qradar",
        finding_id=str(row.get("id") or ""),
        title=str(row.get("description") or "").strip(),
        disposition=map_qradar_disposition(raw_label),
        vendor_disposition=str(raw_label),
        closed_at=_coerce_time(row.get("close_time") or row.get("last_updated_time")),
        closed_by=_opt_str(row, "closing_user"),
        reason=(str(raw_label) or None),
        rule_id=(None if row.get("offense_type") is None else str(row.get("offense_type"))),
        severity=_qradar_severity(row.get("severity")),
        raw=dict(row),
    )


def _qradar_severity(value: Any) -> str | None:
    """QRadar grades 1-10. Fold onto the platform's five-tier ladder."""
    if value is None:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    if n >= 9:
        return "critical"
    if n >= 7:
        return "high"
    if n >= 4:
        return "medium"
    if n >= 2:
        return "low"
    return "info"


# --------------------------------------------------------------------------
# Microsoft Defender XDR
# --------------------------------------------------------------------------

#: Defender XDR's ``classification``. ``Unknown`` is a real choice in the
#: product and is left unmapped.
_DEFENDER_CLASSIFICATIONS: dict[str, str] = {
    "truepositive": TRUE_POSITIVE,
    "informationalexpectedactivity": BENIGN_TRUE_POSITIVE,
    "benignpositive": BENIGN_TRUE_POSITIVE,
    "falsepositive": FALSE_POSITIVE,
}


def map_defender_disposition(label: object) -> str:
    """Map a Microsoft Defender XDR classification to the canonical taxonomy."""
    return _DEFENDER_CLASSIFICATIONS.get(_norm(label).replace("_", ""), UNLABELED)


def parse_defender_alert(row: Mapping[str, Any]) -> ClosedFinding:
    """Parse one resolved Defender XDR alert from the Defender for Endpoint API.

    Field names follow the Defender for Endpoint alert resource, which is what
    :meth:`app.clients.defender_client.DefenderClient.list_resolved_alerts`
    reads. The Graph security API spells three of them differently
    (``displayName``, ``lastUpdateDateTime``, ``resolvedDateTime``), so those
    are accepted as fallbacks rather than making a Graph-sourced row parse to
    an empty title and an unparseable close time.
    """
    raw_label = row.get("classification") or ""
    return ClosedFinding(
        vendor="defender",
        finding_id=str(row.get("id") or row.get("incidentId") or ""),
        title=str(row.get("title") or row.get("displayName") or ""),
        disposition=map_defender_disposition(raw_label),
        vendor_disposition=str(raw_label),
        closed_at=_coerce_time(
            row.get("resolvedTime") or row.get("lastUpdateTime") or row.get("resolvedDateTime") or row.get("lastUpdateDateTime")
        ),
        closed_by=_opt_str(row, "assignedTo"),
        # `determination` is the structured "why" (Malware, SecurityTesting,
        # Phishing, ...) and is a different field from the classification.
        # Conflating the two would score "Phishing" as if it were a verdict.
        reason=_opt_str(row, "determination"),
        rule_id=_opt_str(row, "detectionSource"),
        severity=(_opt_str(row, "severity") or "").lower() or None,
        raw=dict(row),
    )
