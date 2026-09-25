"""Approval must be a function of confidence *and* impact, and only ever stricter.

The L0-L4 ladder answers "how much is this tenant willing to automate". It
does not answer "is this action safe at this confidence", and treating one as
the other produces both failure modes: an IOC enrichment stuck in an approval
queue because the tier is low, and a production database server isolated
autonomously because the tier is high and the model said 94%.

The property these tests defend is one-directional: each of the three inputs
— the action's declared contract, the confidence score, the tenant's tier —
can raise the requirement, and none can lower it. Every way of lowering it is
a way of executing something nobody approved.
"""

from __future__ import annotations

import pytest
from app.live_actions.contract import ActionImpact, ApprovalRequirement
from app.services.approval_matrix import (
    AUTOMATIC_CONFIDENCE_FLOOR,
    TIER_MAX_AUTOMATIC,
    evaluate,
)

AUTO = ApprovalRequirement.AUTOMATIC
ANALYST = ApprovalRequirement.ANALYST
HUMAN = ApprovalRequirement.MANDATORY_HUMAN
BLOCKED = ApprovalRequirement.PROHIBITED


class TestNothingLowersARequirement:
    @pytest.mark.parametrize("tier", list(TIER_MAX_AUTOMATIC))
    @pytest.mark.parametrize("impact", [ActionImpact.SEVERE, ActionImpact.IRREVERSIBLE])
    def test_severe_and_irreversible_never_auto_execute(self, tier: str, impact: ActionImpact) -> None:
        """No tier, no confidence. This is the floor autonomy cannot lift."""
        decision = evaluate(impact=impact, declared_approval=AUTO, confidence=1.0, tier=tier)
        assert not decision.can_auto_execute

    def test_irreversible_is_prohibited_not_merely_gated(self) -> None:
        """'Nobody may do this' and 'a human must approve' are different claims."""
        decision = evaluate(impact=ActionImpact.IRREVERSIBLE, declared_approval=AUTO, confidence=1.0, tier="L4")
        assert decision.requirement is BLOCKED
        assert decision.is_blocked

    def test_a_contract_demanding_a_human_survives_any_tier(self) -> None:
        decision = evaluate(impact=ActionImpact.LOW, declared_approval=HUMAN, confidence=1.0, tier="L4")
        assert decision.requirement is HUMAN

    def test_a_prohibited_contract_survives_everything(self) -> None:
        decision = evaluate(impact=ActionImpact.READ_ONLY, declared_approval=BLOCKED, confidence=1.0, tier="L4")
        assert decision.requirement is BLOCKED

    def test_an_analyst_contract_is_not_relaxed_by_high_confidence(self) -> None:
        decision = evaluate(impact=ActionImpact.LOW, declared_approval=ANALYST, confidence=1.0, tier="L4")
        assert decision.requirement is ANALYST


class TestConfidence:
    def test_missing_confidence_is_the_lowest_band_not_the_highest(self) -> None:
        """Defaulting permissive turns a scoring bug into an autonomous action."""
        decision = evaluate(impact=ActionImpact.MODERATE, declared_approval=AUTO, confidence=None, tier="L4")
        assert not decision.can_auto_execute

    def test_below_the_floor_drops_to_analyst(self) -> None:
        floor = AUTOMATIC_CONFIDENCE_FLOOR[ActionImpact.MODERATE]
        decision = evaluate(
            impact=ActionImpact.MODERATE,
            declared_approval=AUTO,
            confidence=floor - 0.01,
            tier="L4",
        )
        assert decision.requirement is ANALYST
        assert f"{floor:.0%}" in decision.reason

    def test_at_the_floor_is_sufficient(self) -> None:
        floor = AUTOMATIC_CONFIDENCE_FLOOR[ActionImpact.MODERATE]
        decision = evaluate(impact=ActionImpact.MODERATE, declared_approval=AUTO, confidence=floor, tier="L4")
        assert decision.can_auto_execute

    @pytest.mark.parametrize("value", [-5.0, -0.1, 1.5, 99.0])
    def test_out_of_range_confidence_is_clamped_not_trusted(self, value: float) -> None:
        decision = evaluate(impact=ActionImpact.READ_ONLY, declared_approval=AUTO, confidence=value, tier="L4")
        assert 0.0 <= decision.confidence <= 1.0

    def test_a_read_needs_no_confidence_at_all(self) -> None:
        """Separating impact from confidence exists precisely for this case."""
        decision = evaluate(impact=ActionImpact.READ_ONLY, declared_approval=AUTO, confidence=0.0, tier="L2")
        assert decision.can_auto_execute

    def test_the_steepness_is_intentional(self) -> None:
        """A wrong autonomous containment costs more than an extra approval."""
        assert AUTOMATIC_CONFIDENCE_FLOOR[ActionImpact.HIGH] >= 0.99
        assert AUTOMATIC_CONFIDENCE_FLOOR[ActionImpact.MODERATE] >= 0.98
        assert AUTOMATIC_CONFIDENCE_FLOOR[ActionImpact.LOW] < AUTOMATIC_CONFIDENCE_FLOOR[ActionImpact.MODERATE]


class TestTiers:
    @pytest.mark.parametrize("impact", list(ActionImpact))
    def test_the_observe_tier_executes_nothing_at_all(self, impact: ActionImpact) -> None:
        """L0 is the one tier whose ceiling is ``None``, and it means it.

        Widened from READ_ONLY alone to every impact: ``None`` now has
        exactly one meaning in ``TIER_MAX_AUTOMATIC`` and this is the
        assertion of it. ``maturity.py`` defines L0 as "all actions routed to
        the approval queue" and ``_AUTO_ALLOWED_AT_TIER`` gives it the empty
        set.
        """
        decision = evaluate(impact=impact, declared_approval=AUTO, confidence=1.0, tier="L0")
        assert not decision.can_auto_execute

    def test_the_notify_tier_reads_and_does_not_act(self) -> None:
        """L1 used to gate a pure read, and that was the defect.

        This test replaces one that asserted the opposite. It was not a
        posture being relaxed — it contradicted the ladder it claimed to
        encode. ``maturity.py``: "L1 — Notify: MINIMAL blast-radius actions
        are automatic", and ``_AUTO_ALLOWED_AT_TIER[L1_NOTIFY]`` is
        ``{MINIMAL}``, which ``dispatcher._IMPACT_BLAST`` equates with
        READ_ONLY impact. The module docstring above opens by naming "an IOC
        enrichment stuck in an approval queue because the tier is low" as a
        failure mode, and the contract gate calls a read that needs approval
        mis-classified. Three statements of the same rule, and the table said
        otherwise at the default tier.

        Both halves are pinned here, where the old test pinned neither
        correctly: a read runs, and nothing above a read does.
        """
        assert evaluate(impact=ActionImpact.READ_ONLY, declared_approval=AUTO, confidence=1.0, tier="L1").can_auto_execute
        for impact in (ActionImpact.LOW, ActionImpact.MODERATE, ActionImpact.HIGH):
            decision = evaluate(impact=impact, declared_approval=AUTO, confidence=1.0, tier="L1")
            assert not decision.can_auto_execute, f"L1 must not auto-execute {impact.value} impact"

    def test_a_read_whose_contract_wants_an_analyst_still_gets_one(self) -> None:
        """The tier ceiling moved; the contract's own floor did not.

        READ_ONLY + ANALYST is a legal declaration — the contract gate only
        forbids READ_ONLY + MANDATORY_HUMAN/PROHIBITED — so the ceiling change
        must not swallow it.
        """
        decision = evaluate(impact=ActionImpact.READ_ONLY, declared_approval=ANALYST, confidence=1.0, tier="L4")
        assert decision.requirement is ANALYST

    def test_l2_reads_but_does_not_act(self) -> None:
        assert evaluate(impact=ActionImpact.READ_ONLY, declared_approval=AUTO, confidence=1.0, tier="L2").can_auto_execute
        assert not evaluate(impact=ActionImpact.LOW, declared_approval=AUTO, confidence=1.0, tier="L2").can_auto_execute

    def test_l3_stops_below_high_impact(self) -> None:
        assert evaluate(impact=ActionImpact.MODERATE, declared_approval=AUTO, confidence=1.0, tier="L3").can_auto_execute
        assert not evaluate(impact=ActionImpact.HIGH, declared_approval=AUTO, confidence=1.0, tier="L3").can_auto_execute

    def test_l4_reaches_high_but_no_further(self) -> None:
        assert evaluate(impact=ActionImpact.HIGH, declared_approval=AUTO, confidence=1.0, tier="L4").can_auto_execute
        assert not evaluate(impact=ActionImpact.SEVERE, declared_approval=AUTO, confidence=1.0, tier="L4").can_auto_execute

    def test_an_unknown_tier_is_the_most_restrictive(self) -> None:
        """A typo in a tenant's policy must not widen what it can do."""
        decision = evaluate(impact=ActionImpact.READ_ONLY, declared_approval=AUTO, confidence=1.0, tier="L9")
        assert not decision.can_auto_execute
        assert decision.tier == "L0"


class TestReasons:
    """'Requires approval' with no reason is a prompt people click through."""

    @pytest.mark.parametrize(
        ("impact", "confidence", "tier"),
        [
            (ActionImpact.IRREVERSIBLE, 1.0, "L4"),
            (ActionImpact.SEVERE, 1.0, "L4"),
            (ActionImpact.HIGH, 0.5, "L4"),
            (ActionImpact.HIGH, 1.0, "L3"),
            (ActionImpact.READ_ONLY, 1.0, "L0"),
            (ActionImpact.LOW, 1.0, "L4"),
        ],
    )
    def test_every_decision_explains_itself(self, impact: ActionImpact, confidence: float, tier: str) -> None:
        decision = evaluate(impact=impact, declared_approval=AUTO, confidence=confidence, tier=tier)
        assert len(decision.reason) > 30
        assert decision.reason.endswith(".")

    def test_the_reason_names_what_blocked_it(self) -> None:
        low_confidence = evaluate(impact=ActionImpact.HIGH, declared_approval=AUTO, confidence=0.5, tier="L4")
        assert "confidence" in low_confidence.reason.lower()

        low_tier = evaluate(impact=ActionImpact.HIGH, declared_approval=AUTO, confidence=1.0, tier="L3")
        assert "tier" in low_tier.reason.lower()


class TestTheWorkedExamples:
    """The table from the plan, asserted rather than described."""

    @pytest.mark.parametrize(
        ("impact", "confidence", "expected"),
        [
            # enrich an IOC — any confidence, automatic
            (ActionImpact.READ_ONLY, 0.0, AUTO),
            # block a known-bad hash — high confidence, automatic
            (ActionImpact.LOW, 0.99, AUTO),
            (ActionImpact.LOW, 0.50, ANALYST),
            # kill a process — very high confidence, tier decides
            (ActionImpact.MODERATE, 0.99, AUTO),
            (ActionImpact.MODERATE, 0.90, ANALYST),
            # disable an account — high impact, analyst even at 99%
            (ActionImpact.HIGH, 0.99, AUTO),
            (ActionImpact.HIGH, 0.98, ANALYST),
            # isolate a production server — mandatory human at any confidence
            (ActionImpact.SEVERE, 1.0, HUMAN),
            # delete a cloud resource — prohibited
            (ActionImpact.IRREVERSIBLE, 1.0, BLOCKED),
        ],
    )
    def test_at_the_highest_tier(self, impact: ActionImpact, confidence: float, expected: ApprovalRequirement) -> None:
        decision = evaluate(impact=impact, declared_approval=AUTO, confidence=confidence, tier="L4")
        assert decision.requirement is expected
