"""One definition of "is this alert still someone's problem".

Why this module exists
----------------------
The dashboard's **Active Alerts** tile counted every alert the tenant had ever
received -- no status filter at all -- while the console labelled the number
*Active* and the severity tile beneath it *Critical — Require immediate
action*. A tenant who had worked their queue to zero saw their entire
historical backlog presented as outstanding work, and the number only ever
went up.

The filter was not missing for want of a definition. Four other places already
had it: `alerts.py`'s critical-queue count, `metrics.py`'s own funnel query,
and `health.py` twice. The tile was the outlier, which is the shape this
module prevents -- five hand-written copies of one rule drift one at a time
and nothing notices, because each site looks locally correct.

`case_status.py` does the same job for cases, and this is deliberately its
sibling rather than an extension of it: alerts and cases have different
vocabularies, and merging them would invite the `open`/`in_progress` confusion
that migration 083 spent an entire release untangling.

Centralising it was not enough, and the second defect is the instructive one
--------------------------------------------------------------------------
`UNRESOLVED_STATUSES` was an **inclusion list** of three states, used in a SQL
`IN`. The auto-triage worker writes `triaged` (`services/agents` →
`investigator/ledger.py`), which was in neither that tuple nor
`RESOLVED_STATUSES` -- so every triaged alert fell out of *both* buckets and
`/metrics/dashboard` answered `{"total": 0, "critical": 0}` for a tenant with
nine open alerts, on the same screen as a funnel reading "Alerts Generated 9".
A live pass watched the critical tile decay 3 → 2 → 1 → 0 as the worker got
through the queue.

The module already shipped the correct rule -- `is_unresolved()` treats an
unknown status as unresolved, for exactly the reason stated in its docstring
-- and the SQL never ran it. So the two are now one definition:
:func:`unresolved_filter` renders `NOT IN (terminal)`, which is the same
predicate `is_unresolved()` applies, and a status nobody adds here still
counts as work.

The vocabulary
--------------
`WRITTEN_STATUSES` is every value a writer in this repository puts in
`alerts.status`, and `scripts/check_alert_status_vocabulary.py` fails the
build when a writer invents one that is not listed. `UNRESOLVED_STATUSES` is
*derived* from it rather than typed out, so the two cannot disagree; only the
terminal set is enumerated by hand, because "finished" is the claim that needs
deliberate sign-off.
"""

from __future__ import annotations

from typing import Any, Final

from sqlalchemy import or_
from sqlalchemy.sql.elements import ColumnElement

#: Finished. Enumerated by hand on purpose: this is the only list whose
#: membership *removes* work from an analyst's queue, so a new terminal
#: state has to be added here deliberately rather than inherited.
#:
#: `resolved` comes from the console and the closure-authorised worker path;
#: `closed` from vendor writeback; `false_positive`/`fp` from the bulk-close
#: endpoint and the feedback path (the schema comment on `models/alert.py`
#: documents both spellings); `dismissed` from `case_depth`'s cascade when a
#: case is dismissed.
RESOLVED_STATUSES: Final[tuple[str, ...]] = (
    "resolved",
    "closed",
    "false_positive",
    "fp",
    "dismissed",
)

#: Every value any writer in this repository puts in `alerts.status`.
#:
#: Maintained as a registry rather than discovered, because a value that is
#: never read is exactly the defect: `triaged` had been written by the
#: auto-triage worker for releases while no reader classified it.
#: `scripts/check_alert_status_vocabulary.py` scans the writers and fails
#: when one of them writes something absent from this tuple.
WRITTEN_STATUSES: Final[tuple[str, ...]] = (
    # Open, in the order an alert ordinarily walks them.
    "new",  # fusion's alert sink, and POST /alerts/submit
    "triaging",  # console claim
    "triaged",  # the auto-triage worker's verdict
    "investigating",  # an investigation launched from a case
    "in_progress",  # console
    "escalated",  # queue hand-off
    "snoozed",  # responder PWA deferral
    # Terminal.
    *RESOLVED_STATUSES,
)

#: An analyst still has to do something about these. Derived rather than
#: typed, so it cannot drift from `WRITTEN_STATUSES` the way the old
#: three-element literal drifted from the worker.
#:
#: Prefer :func:`unresolved_filter` for a database predicate. This tuple is
#: an *enumeration of the known open states* and is correct only for the
#: statuses listed above; the filter additionally catches a status nobody
#: declared, which is the failure this module exists to stop.
UNRESOLVED_STATUSES: Final[tuple[str, ...]] = tuple(s for s in WRITTEN_STATUSES if s not in RESOLVED_STATUSES)

#: Statuses an alert may be bulk-closed *to*. A write vocabulary, not a
#: classification: `new`/`investigating` are excluded because bulk-moving
#: work *into* the queue is not what that endpoint is for. Declared here so
#: the endpoint's `Literal[...]` and the service's `frozenset` cannot name
#: different sets, which they already did.
BULK_CLOSE_STATUSES: Final[tuple[str, ...]] = ("resolved", "false_positive", "closed")

#: Open states from which an agent-investigation launch may forward-advance
#: an alert to `investigating`. Narrower than `UNRESOLVED_STATUSES` on
#: purpose: an alert that is *already* running, escalated or snoozed must not
#: be dragged backwards by a re-run. `cases.py` carried this as its own
#: hand-written tuple -- the second copy of the vocabulary, and the one that
#: happened to be right about `triaged` while the canonical one was wrong.
PRE_INVESTIGATION_STATUSES: Final[tuple[str, ...]] = ("new", "triaging", "triaged")


def is_unresolved(status: str | None) -> bool:
    """True when the alert is still outstanding.

    An unknown status counts as unresolved. An alert whose state nobody
    recognises is work that has not demonstrably finished, and dropping it
    from a queue count would make the backlog look smaller than it is --
    which is the direction of error this module exists to stop.
    """
    if status is None:
        return True
    return status.strip().lower() not in RESOLVED_STATUSES


def is_resolved(status: str | None) -> bool:
    """True only for a status that explicitly means finished."""
    if status is None:
        return False
    return status.strip().lower() in RESOLVED_STATUSES


def unresolved_filter(column: Any) -> ColumnElement[bool]:
    """SQL form of :func:`is_unresolved`, for `WHERE` clauses.

    Written as `NOT IN (terminal)` rather than `IN (open)` so the database
    and Python answer the same question. The inclusion form could not
    express "an unrecognised status is still work", which is how `triaged`
    went uncounted by every tile on the dashboard.

    NULL is handled explicitly because SQL `NOT IN` yields NULL (not TRUE)
    for a NULL left-hand side, and `is_unresolved(None)` is True.
    """
    return or_(column.is_(None), column.notin_(RESOLVED_STATUSES))


def resolved_filter(column: Any) -> ColumnElement[bool]:
    """SQL form of :func:`is_resolved`."""
    return column.in_(RESOLVED_STATUSES)


__all__ = [
    "BULK_CLOSE_STATUSES",
    "PRE_INVESTIGATION_STATUSES",
    "RESOLVED_STATUSES",
    "UNRESOLVED_STATUSES",
    "WRITTEN_STATUSES",
    "is_resolved",
    "is_unresolved",
    "resolved_filter",
    "unresolved_filter",
]
