"""One vocabulary for case status, so two surfaces cannot disagree.

Gap-closure wave 1.

Before the consolidation there were two case tables with two status
vocabularies, and the readers used the wrong one. `metrics.py` counted
`status == "open"` and `status == "in_progress"` — **neither of which is
a state the console can produce**. The console's machine is
``new → triaged → investigating → contained → resolved → closed``, so
those two counters were structurally zero rather than merely empty.

The subtler one is `resolved`. It looks terminal and is not: a case
moves `resolved → closed`, and `closed_at` is written on that last
transition. Counting "closed this week" as `status == 'resolved'`
therefore counts cases that are still open on an analyst's queue, and
misses every case that actually finished. This repository has shipped
that exact defect before.

Everything that asks a question about case status asks it here.
"""

from __future__ import annotations

from typing import Final

__all__ = [
    "ALL_STATUSES",
    "CLOSED",
    "CLOSED_STATUSES",
    "OPEN_STATUSES",
    "RESOLVED",
    "TERMINAL_STATUSES",
    "TRANSITIONS",
    "WORKING_STATUSES",
    "is_open",
    "is_terminal",
]

NEW: Final[str] = "new"
TRIAGED: Final[str] = "triaged"
INVESTIGATING: Final[str] = "investigating"
CONTAINED: Final[str] = "contained"
RESOLVED: Final[str] = "resolved"
CLOSED: Final[str] = "closed"

#: The state machine the console enforces. Mirrors `_TRANSITIONS` in the
#: cases endpoint, which imports from here so there is one copy.
TRANSITIONS: Final[dict[str, set[str]]] = {
    NEW: {TRIAGED},
    TRIAGED: {INVESTIGATING},
    INVESTIGATING: {CONTAINED, RESOLVED},
    CONTAINED: {RESOLVED},
    RESOLVED: {CLOSED},
    CLOSED: set(),
}

ALL_STATUSES: Final[tuple[str, ...]] = tuple(TRANSITIONS)

#: Still on somebody's queue. `resolved` is **in** this set: a resolved
#: case has an outcome but has not been closed out, and treating it as
#: finished is what made "cases closed this week" count the wrong rows.
OPEN_STATUSES: Final[tuple[str, ...]] = (NEW, TRIAGED, INVESTIGATING, CONTAINED, RESOLVED)

#: Somebody is actively working it, as distinct from newly arrived.
WORKING_STATUSES: Final[tuple[str, ...]] = (TRIAGED, INVESTIGATING, CONTAINED)

#: Finished. One member, and that is the point — `closed` is the only
#: state that writes `closed_at`, which every duration metric reads.
CLOSED_STATUSES: Final[tuple[str, ...]] = (CLOSED,)
TERMINAL_STATUSES: Final[tuple[str, ...]] = CLOSED_STATUSES


def is_open(status: str | None) -> bool:
    """Whether this case still needs somebody."""
    return status in OPEN_STATUSES


def is_terminal(status: str | None) -> bool:
    """Whether this case is finished. Only `closed` qualifies."""
    return status in TERMINAL_STATUSES
