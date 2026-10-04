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

The vocabulary
--------------
`models/alert.py` documents `new | triaging | in_progress | resolved`, and
`closed` appears in the wild from vendor writeback. Both terminal states are
listed here, because treating an unrecognised value as resolved would hide
work rather than show it -- the safer default for a *queue* count is to
include what you cannot classify.
"""

from __future__ import annotations

from typing import Final

#: An analyst still has to do something about these.
UNRESOLVED_STATUSES: Final[tuple[str, ...]] = ("new", "triaging", "in_progress")

#: Finished. Separate from the above rather than derived, so a new status
#: added to the model does not silently become "resolved" by omission.
RESOLVED_STATUSES: Final[tuple[str, ...]] = ("resolved", "closed")


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


__all__ = ["RESOLVED_STATUSES", "UNRESOLVED_STATUSES", "is_resolved", "is_unresolved"]
