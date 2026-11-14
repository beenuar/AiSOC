"""What an AiSOC verdict is allowed to do to the finding that produced it.

Closing the loop with the source SIEM is the point of two-way integration: an
analyst should not have to re-read an Elastic signal AiSOC already dismissed,
and a Splunk notable AiSOC confirmed should already be assigned to a human by
the time anyone opens the queue.

The mapping is deliberate, not mechanical, and the three rules below are the
whole safety argument for letting an agent write into the customer's system of
record at all:

**A confirmed true positive is never closed.** It is the case the SOC most
needs a human to see. Closing it because the platform is confident is how an
agent turns a real intrusion into a resolved ticket nobody read. A true
positive escalates: the finding is annotated and moved to in-progress, and it
stays open.

**An unknown verdict is refused, never guessed.** ``needs_review`` and any
string outside the canonical taxonomy resolve to :data:`WritebackAction.REFUSE`
and the source finding is left exactly as it was. This matters more than it
looks: the agents' own :func:`normalize_disposition` defaults an unrecognised
verdict to ``true_positive``, so a mapper that normalised first would silently
convert "I do not know what this string is" into a confident claim. This module
matches the canonical set exactly and refuses everything else.

**Only a benign or false-positive verdict may close a finding.** Those are the
verdicts where being wrong costs a missed detection that the rule will fire
again on, rather than an intrusion closed as handled.

The vocabulary is a deliberate mirror of
``services/agents/app/agents/dispositions.py`` rather than an import, for the
same reason ``live_actions.capabilities`` mirrors the connectors ``Capability``
enum: the two are independently deployable and a hard import would couple them.
``tests/test_disposition_writeback.py`` compares the two sets and fails on
drift.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

TRUE_POSITIVE = "true_positive"
BENIGN_TRUE_POSITIVE = "benign_true_positive"
FALSE_POSITIVE = "false_positive"
BENIGN = "benign"
NEEDS_REVIEW = "needs_review"
ESCALATE = "escalate"

#: Mirror of ``dispositions.CANONICAL_DISPOSITIONS``. Anything outside this set
#: is refused rather than interpreted.
CANONICAL_DISPOSITIONS: frozenset[str] = frozenset(
    {
        TRUE_POSITIVE,
        BENIGN_TRUE_POSITIVE,
        FALSE_POSITIVE,
        BENIGN,
        NEEDS_REVIEW,
        ESCALATE,
    }
)

#: The only verdicts that may close a finding in somebody else's SIEM.
CLOSEABLE_DISPOSITIONS: frozenset[str] = frozenset({FALSE_POSITIVE, BENIGN, BENIGN_TRUE_POSITIVE})

#: Verdicts that annotate and hand the finding to a human without closing it.
ESCALATING_DISPOSITIONS: frozenset[str] = frozenset({TRUE_POSITIVE, ESCALATE})


class WritebackAction(str, Enum):
    """What to do to the source finding."""

    #: Set the finding to a closed/resolved state with AiSOC's reason.
    CLOSE = "close"

    #: Annotate and move to in-progress. The finding stays open.
    ESCALATE = "escalate"

    #: Do nothing at all to the finding. Not a failure — a decision.
    REFUSE = "refuse"


@dataclass(frozen=True)
class WritebackPlan:
    """The decision, and the sentence explaining it.

    ``reason`` is rendered into the vendor comment and into the API response,
    so a Splunk analyst reading the notable sees why AiSOC touched it and an
    AiSOC operator reading the audit trail sees the same words.
    """

    action: WritebackAction
    disposition: str
    reason: str

    @property
    def writes(self) -> bool:
        return self.action is not WritebackAction.REFUSE


def plan_writeback(disposition: object, *, confidence: float | None = None) -> WritebackPlan:
    """Decide what ``disposition`` may do to the finding that produced it.

    ``confidence`` is recorded in the reason but deliberately does not change
    the decision. Confidence is an input to whether an action is *approved*
    (that is the approval matrix's job, and it is the axis it already reasons
    about); it is not licence to close a true positive.
    """
    raw = disposition if isinstance(disposition, str) else ""
    key = raw.strip().lower().replace("-", "_").replace(" ", "_")
    scored = "" if confidence is None else f" (confidence {confidence:.0%})"

    if key not in CANONICAL_DISPOSITIONS:
        shown = raw.strip()[:64] or "<empty>"
        return WritebackPlan(
            action=WritebackAction.REFUSE,
            disposition=key or "unknown",
            reason=(
                f"Refused: {shown!r} is not a recognised AiSOC disposition, and a verdict "
                f"the platform cannot name is not one it may act on. The source finding is unchanged."
            ),
        )

    if key in CLOSEABLE_DISPOSITIONS:
        return WritebackPlan(
            action=WritebackAction.CLOSE,
            disposition=key,
            reason=f"AiSOC triaged this finding as {key}{scored}. Closing it in the source system.",
        )

    if key in ESCALATING_DISPOSITIONS:
        return WritebackPlan(
            action=WritebackAction.ESCALATE,
            disposition=key,
            reason=(
                f"AiSOC triaged this finding as {key}{scored}. Escalated to a human and left OPEN — "
                f"a confirmed true positive is never auto-closed."
            ),
        )

    # needs_review. Reached only for a canonical verdict with no action, which
    # today is exactly this one. Saying nothing is the honest outcome: the
    # finding is already open and already unresolved, so an annotation claiming
    # AiSOC did something would be noise on every alert it could not decide.
    return WritebackPlan(
        action=WritebackAction.REFUSE,
        disposition=key,
        reason=(
            f"Refused: AiSOC reached {key}{scored} rather than a verdict. The source finding is "
            f"left exactly as it was, because 'undecided' is the state it is already in."
        ),
    )
