"""The finding shape replay grades against, as this service sees it.

Gap-closure Phase 1.2.

Phase 1.1 put the readers on ``services/actions``, because that service owns
the five SIEM credential paths and already holds the writeback going the other
way. It produces ``app.services.alert_history.ClosedFinding``.

This service cannot import that one. So :class:`HistoricalFinding` is the same
row seen from here, and the two are kept in step by
``scripts/check_replay_contract_parity.py``, which parses both dataclasses and
compares the field sets **in both directions**. A one-directional check would
pass while this side quietly lost a field the reader still sends, which is the
failure shape this repository keeps finding in its own gates.

The mapping is deliberately by name and nothing else. There is no positional
construction anywhere, so a field appearing on one side and not the other is a
loud ``TypeError`` at the boundary rather than a value landing in the wrong
column.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

#: An analyst closed the finding without recording a disposition the platform
#: can name. Mirrors ``app.services.alert_history.UNLABELED`` in
#: ``services/actions``; the parity gate pins the two spellings together.
UNLABELED = "unlabeled"

__all__ = ["UNLABELED", "HistoricalFinding"]


@dataclass(frozen=True)
class HistoricalFinding:
    """One finding a human already closed, with the label they chose."""

    vendor: str
    finding_id: str
    title: str
    disposition: str
    vendor_disposition: str
    closed_at: datetime
    closed_by: str | None = None
    reason: str | None = None
    rule_id: str | None = None
    severity: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def is_labelled(self) -> bool:
        """Whether this row may contribute to accuracy."""
        return self.disposition != UNLABELED

    @classmethod
    def from_mapping(cls, row: Mapping[str, Any]) -> HistoricalFinding:
        """Build from a ``ClosedFinding`` serialised across the service boundary.

        ``closed_at`` is required and is not defaulted to "now" when it is
        missing or unparseable. A finding with an invented close time lands on
        whichever side of the train/test split the default happens to fall, so
        a silent default here is a leak with a plausible-looking timestamp on
        it.
        """
        closed_at = _require_time(row.get("closed_at"), finding_id=row.get("finding_id"))
        return cls(
            vendor=str(row.get("vendor") or ""),
            finding_id=str(row.get("finding_id") or ""),
            title=str(row.get("title") or ""),
            disposition=str(row.get("disposition") or UNLABELED),
            vendor_disposition=str(row.get("vendor_disposition") or ""),
            closed_at=closed_at,
            closed_by=_opt(row.get("closed_by")),
            reason=_opt(row.get("reason")),
            rule_id=_opt(row.get("rule_id")),
            severity=_opt(row.get("severity")),
            raw=dict(row.get("raw") or {}),
        )


def _opt(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _require_time(value: Any, *, finding_id: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"finding {finding_id!r} has an unparseable closed_at {value!r}") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    raise ValueError(f"finding {finding_id!r} has no usable closed_at (got {value!r})")
