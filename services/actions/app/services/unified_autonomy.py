"""Unified autonomy policy (Wave 5b).

The agent produces a verdict + confidence; the actions gate keys on blast radius
+ tier. They never shared a contract, so confidence never influenced execution.
This module unifies them into one decision over (confidence, blast radius,
reversibility).

Posture: **aggressive-but-safe** — a REVERSIBLE, low-blast-radius action with
high model confidence may auto-execute by default (it can be rolled back and
its scope is limited), while anything non-reversible, high/critical blast, or
low-confidence still requires a human. This is the "auto-response by default for
reversible low-blast actions, gated by confidence + rollback" behaviour.

Earned autonomy (gap-closure Phase 2.3)
=======================================

Confidence is what the model says about itself. It is not evidence, and an
agent that is confidently wrong is exactly the case this module has to survive.
Phase 2.3 adds the second input: a *grant*, which a tenant earns by running an
alert class in shadow mode and agreeing with their own analysts often enough,
across a large enough sample, with enough of it malicious.

A grant is deliberately a **narrow widening** rather than a new ladder.

* It only ever moves a MEDIUM-blast reversible action from the approval queue
  to AUTO, and only when confidence already clears the LOW-blast floor. A
  track record on triage verdicts is evidence about *judgement*; it is not
  evidence that a HIGH-blast containment was the right call, and the two get
  conflated the moment one number is allowed to unlock everything.
* It never touches CRITICAL blast and never touches a non-reversible action.
  Those refusals come first in :func:`unified_decision` and are unreachable
  from here, which is why they are checked before the grant is consulted
  rather than after.
* It cannot lower a bar. A grant is consulted only on the path that was
  already heading for the approval queue, so the worst a wrong grant can do is
  auto-execute something reversible that a human would have approved.

The grant's *source* travels into the rationale rather than being reduced to a
boolean. "Auto-executed on a measured track record" and "auto-executed because
an operator overruled the gate" describe the same action and read very
differently in an incident review, and the rationale is what ends up quoted
there.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.action import BlastRadius
from app.services.autonomy_safety import REVERSIBLE_ACTIONS, AutonomyMode

# Confidence needed to auto-execute a reversible LOW-blast action.
AUTO_LOW_BLAST_CONFIDENCE = 0.85
# Higher bar to auto-execute a reversible MEDIUM-blast action.
AUTO_MEDIUM_BLAST_CONFIDENCE = 0.95


@dataclass(frozen=True)
class AutonomyDecision:
    mode: AutonomyMode
    rationale: str
    confidence: float
    reversible: bool
    #: ``earned`` or ``operator_override`` when a Phase 2.3 grant is what
    #: allowed this to run unattended, ``None`` otherwise. Recorded separately
    #: from the rationale so a caller can filter on it without parsing prose.
    earned_from: str | None = None


def is_reversible(action_type: str) -> bool:
    return action_type in REVERSIBLE_ACTIONS


def unified_decision(
    *,
    action_type: str,
    blast_radius: BlastRadius,
    confidence: float,
    reversible: bool | None = None,
    low_blast_floor: float = AUTO_LOW_BLAST_CONFIDENCE,
    medium_blast_floor: float = AUTO_MEDIUM_BLAST_CONFIDENCE,
    earned_grant: str | None = None,
) -> AutonomyDecision:
    """Decide how an action may run, unifying model confidence with blast radius.

    ``earned_grant`` is the source of a Phase 2.3 autonomy grant for this verb
    (``earned`` or ``operator_override``), or ``None``. It can only widen the
    MEDIUM-blast branch below, and only above the LOW-blast confidence floor;
    every refusal above that branch is reached first and is unreachable from
    here. See the module docstring for why the widening is that narrow.
    """
    rev = is_reversible(action_type) if reversible is None else reversible
    conf = max(0.0, min(1.0, confidence))

    def d(mode: AutonomyMode, why: str, *, earned: str | None = None) -> AutonomyDecision:
        return AutonomyDecision(mode=mode, rationale=why, confidence=conf, reversible=rev, earned_from=earned)

    # Critical blast is never auto, regardless of confidence.
    if blast_radius == BlastRadius.CRITICAL:
        return d(AutonomyMode.QUEUED_APPROVAL, "CRITICAL blast radius always requires human approval")

    # Without a real rollback path, never auto-execute — a wrong call can't be undone.
    if not rev:
        return d(AutonomyMode.QUEUED_APPROVAL, "non-reversible action requires human approval")

    # High blast, even reversible, needs a human.
    if blast_radius == BlastRadius.HIGH:
        return d(AutonomyMode.QUEUED_APPROVAL, "reversible HIGH-blast action queued for approval")

    if blast_radius == BlastRadius.LOW and conf >= low_blast_floor:
        return d(AutonomyMode.AUTO, f"reversible LOW-blast action, confidence {conf:.2f} >= {low_blast_floor:.2f} — auto-execute")

    if blast_radius == BlastRadius.MEDIUM and conf >= medium_blast_floor:
        return d(AutonomyMode.AUTO, f"reversible MEDIUM-blast action, confidence {conf:.2f} >= {medium_blast_floor:.2f} — auto-execute")

    # The one place a grant changes the answer. Everything above is reached
    # first: CRITICAL blast, a non-reversible action and HIGH blast have all
    # already returned, so no track record can unlock them. The LOW floor is
    # required as well as the grant, because a grant is evidence about the
    # agent's judgement in general and confidence is what it says about this
    # decision, and neither substitutes for the other.
    if earned_grant and blast_radius == BlastRadius.MEDIUM and conf >= low_blast_floor:
        earned_phrase = "an operator override" if earned_grant == "operator_override" else "a measured track record"
        return d(
            AutonomyMode.AUTO,
            f"reversible MEDIUM-blast action, confidence {conf:.2f} >= {low_blast_floor:.2f} and this verb "
            f"is autonomous under {earned_phrase} — auto-execute",
            earned=earned_grant,
        )

    return d(AutonomyMode.QUEUED_APPROVAL, f"confidence {conf:.2f} below auto floor for {blast_radius.value} blast — queued for approval")
