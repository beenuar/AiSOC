"""Approval as a function of confidence *and* impact, not autonomy tier alone.

The L0–L4 ladder answers "how much is this tenant willing to automate". It
does not answer "is this particular action safe at this particular
confidence", and treating one as the other produces both failure modes:
enriching an IOC blocked behind an approval queue because the tier is low,
and isolating a production database server auto-executed because the tier is
high and the model said 94%.

The matrix is the second axis. Every decision needs both:

    enrich an IOC              any confidence    automatic
    search endpoints           any confidence    automatic
    block a known-bad hash     >= 99%            automatic
    kill a process             >= 98%            policy (tier decides)
    disable an account         >= 99%            analyst approval
    isolate a production host  any confidence    mandatory human
    delete a cloud resource    any confidence    prohibited

Two properties are non-negotiable and are asserted in tests:

**The matrix can only raise a requirement, never lower it.** If either the
action's declared contract or the confidence threshold says a human is
needed, a human is needed. An autonomy tier of L4 does not override an
action declared MANDATORY_HUMAN, and high confidence does not override an
IRREVERSIBLE impact.

**Missing confidence is not high confidence.** An action arriving with no
confidence score is treated as the lowest band. The alternative — defaulting
to permissive — means a scoring bug becomes an autonomous action.

Why the rules sit here rather than in ``app.services.approval_matrix``
=====================================================================

They were in that module, which every door still imports them from — it is
now a re-export and the import path has not moved. What moved is the file,
next to ``contract.py`` and ``capability_contracts.py``, so that the three
of them form a self-contained unit importing nothing but each other and the
standard library.

That matters because a second service needs the same answer. The console's
autonomy page has to say whether a verb would actually auto-execute, and it
is served by ``services/api``, which cannot import this one: both package
their code as top-level ``app`` and each image is built with only its own
service directory as context. So ``services/api`` carries a byte-identical
copy at ``app/_vendor/action_contracts/`` and
``scripts/sync_vendored_action_contracts.py --check`` fails the build when
the two drift — the arrangement already used for the LLM input contract, the
deterministic narrative and the autonomy evidence rules.

The console reading its own definition of "auto-executes" is exactly the
defect this move repairs. It read a per-action confidence threshold from a
table no dispatch path consults, concluded that seven high-blast verbs ran
unattended, and announced an autopilot posture on a deployment where the
dispatcher queues every one of them for a human.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

from .contract import (
    NEVER_AUTONOMOUS,
    ActionImpact,
    ApprovalRequirement,
)

logger = logging.getLogger("aisoc.approval_matrix")


class _Contract(Protocol):
    """The two fields a capability contract contributes to a grading.

    Structural rather than an import of ``CapabilityContract``: an executor
    class carries the same two attributes without being one, and every door
    grades both kinds. Naming the dataclass would exclude the executors.
    """

    @property
    def impact(self) -> ActionImpact:
        """What this does to the estate if the finding is wrong."""

    @property
    def approval(self) -> ApprovalRequirement:
        """Baseline requirement, which the matrix may raise and never lower."""


#: Confidence floor per impact tier for a *fully automatic* execution.
#: Below the floor, the action drops to analyst approval.
#:
#: The numbers are deliberately steep. The cost of an unnecessary approval is
#: a few minutes of analyst time; the cost of a wrong autonomous containment
#: is an outage plus the trust needed to ever enable autonomy again.
AUTOMATIC_CONFIDENCE_FLOOR: dict[ActionImpact, float] = {
    ActionImpact.READ_ONLY: 0.0,
    ActionImpact.LOW: 0.90,
    ActionImpact.MODERATE: 0.98,
    ActionImpact.HIGH: 0.99,
    # SEVERE and IRREVERSIBLE are absent on purpose: no floor exists because
    # no confidence makes them automatic. Encoded in NEVER_AUTONOMOUS rather
    # than as an unreachable threshold like 1.01, which invites someone to
    # "just lower it a bit".
}

#: Autonomy tiers, lowest to highest. Mirrors the L0–L4 ladder.
TIER_ORDER = ("L0", "L1", "L2", "L3", "L4")

#: The same ladder as ``MaturityTier`` spells it, and as its ``label``
#: property renders it. Repeated here because this module may not import
#: ``app.services.maturity`` — that module is reached through the dispatcher,
#: and importing it back would close the loop — and because the vendored copy
#: has no ``MaturityTier`` to reach at all.
#:
#: ``services/actions/tests/test_tier_ladder_parity.py`` compares both tuples
#: and the labels against the enum in both directions, so the repetition
#: cannot become a disagreement.
TIER_FULL_NAMES = ("L0_OBSERVE", "L1_NOTIFY", "L2_CONTAIN", "L3_REMEDIATE", "L4_AUTOMATE")

TIER_LABELS: dict[str, str] = {
    "L0": "L0-Observe",
    "L1": "L1-Notify",
    "L2": "L2-Contain",
    "L3": "L3-Remediate",
    "L4": "L4-Automate",
}

#: Deployment-wide tier when ``AISOC_MATURITY_TIER`` is unset. Notify-only:
#: the platform surfaces everything and acts on nothing above a read.
DEFAULT_TIER = "L1"

#: The highest tier an *earned* autonomy grant may lift a verb to. A grant is
#: an inference from agreement on triage verdicts, which is evidence about the
#: agent's judgement and not evidence that a HIGH-blast containment was the
#: right call — so no track record reaches L4. ``dispatcher`` applies it;
#: the console has to apply the same ceiling or it would describe a posture
#: the deployment does not hold.
EARNED_TIER_CEILING_LABEL = "L3"


def tier_from_env_value(raw: str | None) -> tuple[str, bool]:
    """Canonical tier for a raw ``AISOC_MATURITY_TIER`` value.

    Returns ``(tier, recognised)``. ``recognised`` is False only when a
    non-empty value matched nothing, which the caller logs — an unset
    variable is the ordinary case and not a misconfiguration.

    Accepts ``L2``, ``L2_CONTAIN`` and ``2``, which is what the dispatcher
    has always accepted. An unparseable value falls back to
    :data:`DEFAULT_TIER` rather than to the highest tier, because the one
    thing a typo must not do is grant autonomy nobody asked for.
    """
    cleaned = (raw or "").strip().upper()
    if not cleaned:
        return DEFAULT_TIER, True
    for index, tier in enumerate(TIER_ORDER):
        if cleaned in {tier, TIER_FULL_NAMES[index], str(index)}:
            return tier, True
    return DEFAULT_TIER, False


#: The highest impact each tier may execute without an analyst, *given* the
#: confidence floor above is also met.
#:
#: ``None`` means exactly one thing: this tier executes nothing at all. That
#: is true of L0 and of L0 only. ``maturity.py`` defines the ladder as "L0 —
#: Observe: all actions routed to approval queue. L1 — Notify: MINIMAL
#: blast-radius actions are automatic", and ``_AUTO_ALLOWED_AT_TIER`` encodes
#: it as ``set()`` for L0 and ``{MINIMAL}`` for L1. READ_ONLY impact is the
#: same thing as MINIMAL blast radius — ``dispatcher._IMPACT_BLAST`` maps one
#: onto the other — so L1's entry here is READ_ONLY.
#:
#: It read ``None``, which put a pure read into the analyst queue at the
#: default tier. That is the failure mode this module's own docstring opens
#: by naming, and the contract gate calls a read requiring approval
#: "mis-classified or not actually a read". The registry door had grown a
#: local bypass to route around it; this table entry is where the answer
#: belongs, so there is one of it.
#:
#: Only READ_ONLY moves. Every impact above it ranks higher than the L1
#: ceiling and still returns ANALYST, exactly as the ``None`` branch did.
TIER_MAX_AUTOMATIC: dict[str, ActionImpact | None] = {
    "L0": None,  # observe only — not even a read
    "L1": ActionImpact.READ_ONLY,  # notify: reads run, nothing acts
    "L2": ActionImpact.READ_ONLY,
    "L3": ActionImpact.MODERATE,  # reversible actions
    "L4": ActionImpact.HIGH,  # bounded response; never SEVERE or IRREVERSIBLE
}

_IMPACT_ORDER = (
    ActionImpact.READ_ONLY,
    ActionImpact.LOW,
    ActionImpact.MODERATE,
    ActionImpact.HIGH,
    ActionImpact.SEVERE,
    ActionImpact.IRREVERSIBLE,
)


def _impact_rank(impact: ActionImpact) -> int:
    return _IMPACT_ORDER.index(impact)


@dataclass(frozen=True)
class ApprovalDecision:
    """What must happen before this action runs, and why.

    ``reason`` is not decoration. It is shown to the analyst in the approval
    queue and written to the audit trail, and "requires approval" without a
    reason is the kind of prompt people learn to click through.
    """

    requirement: ApprovalRequirement
    reason: str
    impact: ActionImpact
    confidence: float
    tier: str

    @property
    def can_auto_execute(self) -> bool:
        return self.requirement == ApprovalRequirement.AUTOMATIC

    @property
    def is_blocked(self) -> bool:
        return self.requirement == ApprovalRequirement.PROHIBITED


def evaluate(
    *,
    impact: ActionImpact,
    declared_approval: ApprovalRequirement,
    confidence: float | None,
    tier: str,
) -> ApprovalDecision:
    """Combine the action's contract, the finding's confidence and the tenant's tier.

    The result is the *most restrictive* of the three. Each input can raise
    the requirement; none can lower it.
    """
    # Missing confidence is the lowest band, not a free pass. Defaulting
    # permissive would turn a scoring bug into an autonomous action.
    score = 0.0 if confidence is None else max(0.0, min(1.0, float(confidence)))
    tier = tier if tier in TIER_ORDER else "L0"

    if declared_approval == ApprovalRequirement.PROHIBITED:
        return ApprovalDecision(
            requirement=ApprovalRequirement.PROHIBITED,
            reason=(
                "This action is declared prohibited by its own contract. No "
                "autonomy tier or confidence level executes it from the platform."
            ),
            impact=impact,
            confidence=score,
            tier=tier,
        )

    if impact in NEVER_AUTONOMOUS:
        requirement = ApprovalRequirement.PROHIBITED if impact == ActionImpact.IRREVERSIBLE else ApprovalRequirement.MANDATORY_HUMAN
        return ApprovalDecision(
            requirement=requirement,
            reason=(
                f"Impact is {impact.value}: "
                + (
                    "the action cannot be undone, so the platform does not execute it."
                    if impact == ActionImpact.IRREVERSIBLE
                    else f"a human must approve regardless of confidence ({score:.0%}) or autonomy tier ({tier})."
                )
            ),
            impact=impact,
            confidence=score,
            tier=tier,
        )

    if declared_approval == ApprovalRequirement.MANDATORY_HUMAN:
        return ApprovalDecision(
            requirement=ApprovalRequirement.MANDATORY_HUMAN,
            reason=(f"The action's contract requires a human regardless of confidence ({score:.0%}) or autonomy tier ({tier})."),
            impact=impact,
            confidence=score,
            tier=tier,
        )

    ceiling = TIER_MAX_AUTOMATIC.get(tier)
    if ceiling is None:
        return ApprovalDecision(
            requirement=ApprovalRequirement.ANALYST,
            reason=(f"Autonomy tier {tier} does not auto-execute any action; this is a recommendation for an analyst to approve."),
            impact=impact,
            confidence=score,
            tier=tier,
        )

    if _impact_rank(impact) > _impact_rank(ceiling):
        return ApprovalDecision(
            requirement=ApprovalRequirement.ANALYST,
            reason=(f"Autonomy tier {tier} auto-executes up to {ceiling.value} impact; this action is {impact.value}."),
            impact=impact,
            confidence=score,
            tier=tier,
        )

    floor = AUTOMATIC_CONFIDENCE_FLOOR.get(impact)
    if floor is None:
        # Defensive: an impact tier with no floor and not in NEVER_AUTONOMOUS
        # means the two tables disagree. Fail closed rather than guess.
        logger.warning("approval_matrix.no_floor impact=%s", impact.value)
        return ApprovalDecision(
            requirement=ApprovalRequirement.ANALYST,
            reason=f"No confidence floor is defined for {impact.value} impact.",
            impact=impact,
            confidence=score,
            tier=tier,
        )

    if score < floor:
        return ApprovalDecision(
            requirement=ApprovalRequirement.ANALYST,
            reason=(f"Confidence {score:.0%} is below the {floor:.0%} floor for {impact.value}-impact actions."),
            impact=impact,
            confidence=score,
            tier=tier,
        )

    if declared_approval == ApprovalRequirement.ANALYST:
        return ApprovalDecision(
            requirement=ApprovalRequirement.ANALYST,
            reason=(f"The action's contract requires analyst approval even at {score:.0%} confidence."),
            impact=impact,
            confidence=score,
            tier=tier,
        )

    return ApprovalDecision(
        requirement=ApprovalRequirement.AUTOMATIC,
        reason=(
            f"{impact.value} impact at {score:.0%} confidence clears the {floor:.0%} "
            f"floor, and tier {tier} permits automatic execution up to "
            f"{ceiling.value}."
        ),
        impact=impact,
        confidence=score,
        tier=tier,
    )


def evaluate_contract(
    *,
    contract: _Contract,
    confidence: float | None,
    tier: str,
) -> ApprovalDecision:
    """Grade a capability contract. **The one place a door may decide.**

    Every entry point that grades a verb calls this and nothing else:
    ``approval_gate.apply_matrix`` behind ``POST /actions``,
    ``dispatcher._apply_capability_contract`` behind
    ``POST /live-actions/dispatch`` and the playbook bridge, and — through the
    vendored copy — the console's autonomy page, which previously answered the
    question for itself and got it wrong.

    It exists because the two doors were separately responsible for
    unpacking a contract into :func:`evaluate`'s four arguments, and one of
    them grew a local short-circuit the other did not have. ``search_siem``
    is read_only/automatic and returned ``awaiting_approval`` through the
    legacy door while executing through the registry door — the same verb
    graded differently depending on which door it came through, which is the
    precise thing the dispatcher's docstring says its contract block exists
    to stop.

    Keeping the unpacking here is what makes that structural rather than a
    matter of discipline. A third door gets the answer by calling this; it
    cannot get a different one without reimplementing the function, and
    ``services/actions/tests/test_approval_doors_agree.py`` sweeps both live
    doors over every capability, tier and confidence band to catch it if one
    does.
    """
    return evaluate(
        impact=contract.impact,
        declared_approval=contract.approval,
        confidence=confidence,
        tier=tier,
    )
