"""The statuses that mean an alert is finished — generated, do not edit.

Rendered from `services/api/app/services/alert_status.py` by
`scripts/sync_vendored_alert_status.py`. Edit the canonical module and re-run
that script; a CI gate fails when this file and the canonical tuple disagree.

Fusion needs this because `AlertSink` reopens an alert whose detection has
fired again after the alert was closed (GHSA-qp9f-459j-w89c). The reopen is
one conditional UPDATE whose `status = ANY(terminal)` predicate is also the
control that leaves an *open* alert alone, so a list that drifted from the
console's idea of "closed" would either miss a recurrence or churn an alert
an analyst is working.

Only the vocabulary is vendored. The canonical module's `unresolved_filter`
and `resolved_filter` build SQLAlchemy expressions, and fusion writes raw
asyncpg SQL -- vendoring them would put an ORM import on the alert path for
no caller.
"""

from __future__ import annotations

from typing import Final

#: Finished. The canonical module enumerates these by hand on purpose: this is
#: the only list whose membership *removes* work from an analyst's queue.
RESOLVED_STATUSES: Final[tuple[str, ...]] = (
    "resolved",
    "closed",
    "false_positive",
    "fp",
    "dismissed",
)


def is_resolved(status: str | None) -> bool:
    """True only for a status that explicitly means finished.

    The mirror of the canonical module's function of the same name, including
    its treatment of NULL: an alert with no status is not finished.
    """
    if status is None:
        return False
    return status.strip().lower() in RESOLVED_STATUSES


__all__ = ["RESOLVED_STATUSES", "is_resolved"]
