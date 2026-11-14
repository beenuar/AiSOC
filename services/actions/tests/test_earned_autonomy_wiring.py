"""What an earned grant is allowed to change at dispatch, and what it is not.

Gap-closure Phase 2.3.

A grant is a narrow widening, and the tests worth having are about the edges of
that narrowness rather than about the happy path. An autonomy control that only
ever gets tested on the case where it says yes is a control nobody has checked
the shape of.

The reasoning the tests pin, stated once: agreement on triage verdicts is
evidence about the agent's *judgement*. It is not evidence that isolating a
host was the right call. Allowing one number to unlock both is how a
measurement of one thing becomes permission for another.
"""

from __future__ import annotations

from app.live_actions.dispatcher import EARNED_TIER_CEILING
from app.models.action import BlastRadius
from app.services.autonomy_evidence_rules import GrantSource
from app.services.autonomy_safety import AutonomyMode
from app.services.maturity import _AUTO_ALLOWED_AT_TIER, MaturityTier
from app.services.tenant_policy import TenantPolicy
from app.services.unified_autonomy import unified_decision


class TestTheCeilingStopsAtMediumBlast:
    def test_a_grant_cannot_reach_l4(self):
        """`force_auto` goes to L4; a grant stops at L3.

        The difference is what each one is. `force_auto` is a human writing
        down a decision about one verb. A grant is an inference from agreement
        on triage verdicts, and an inference must not buy as much as a
        decision.
        """
        assert EARNED_TIER_CEILING is MaturityTier.L3_REMEDIATE
        assert EARNED_TIER_CEILING < MaturityTier.L4_AUTOMATE

    def test_the_ceiling_permits_medium_and_nothing_above_it(self):
        permitted = _AUTO_ALLOWED_AT_TIER[EARNED_TIER_CEILING]
        assert BlastRadius.MEDIUM in permitted
        assert BlastRadius.HIGH not in permitted
        assert BlastRadius.CRITICAL not in permitted


class TestThePolicyCarriesTheGrantButNeverIssuesOne:
    def test_a_tenant_with_no_grants_has_no_earned_autonomy(self):
        assert TenantPolicy(tier=MaturityTier.L2_CONTAIN).earned_autonomy_for("block_ip") is None

    def test_the_source_comes_back_rather_than_a_boolean(self):
        """A caller has to be able to say *which* kind of autonomy this was.

        "Auto-executed on a measured track record" and "auto-executed because
        somebody overruled the gate" are the same action and very different
        sentences in an incident review, and the rationale is what gets quoted
        there.
        """
        policy = TenantPolicy(
            tier=MaturityTier.L2_CONTAIN,
            earned_verbs={"block_ip": GrantSource.OPERATOR_OVERRIDE.value},
        )
        assert policy.earned_autonomy_for("block_ip") == "operator_override"

    def test_a_grant_for_one_verb_does_not_cover_another(self):
        policy = TenantPolicy(tier=MaturityTier.L2_CONTAIN, earned_verbs={"block_ip": "earned"})
        assert policy.earned_autonomy_for("isolate_host") is None


class TestAGrantOnlyWidensOneBranch:
    def test_it_does_not_reach_a_critical_blast_action(self):
        """Checked before the grant is consulted, so no evidence can reach it."""
        decision = unified_decision(
            action_type="block_ip",
            blast_radius=BlastRadius.CRITICAL,
            confidence=0.99,
            reversible=True,
            earned_grant="earned",
        )
        assert decision.mode is AutonomyMode.QUEUED_APPROVAL
        assert decision.earned_from is None

    def test_it_does_not_reach_a_non_reversible_action(self):
        """Without a rollback path a wrong call cannot be undone, whatever the record."""
        decision = unified_decision(
            action_type="isolate_host",
            blast_radius=BlastRadius.LOW,
            confidence=0.99,
            reversible=False,
            earned_grant="earned",
        )
        assert decision.mode is AutonomyMode.QUEUED_APPROVAL

    def test_it_does_not_reach_a_high_blast_action(self):
        decision = unified_decision(
            action_type="block_ip",
            blast_radius=BlastRadius.HIGH,
            confidence=0.99,
            reversible=True,
            earned_grant="earned",
        )
        assert decision.mode is AutonomyMode.QUEUED_APPROVAL

    def test_it_widens_a_medium_blast_action_above_the_low_floor(self):
        """The one place a grant changes the answer.

        Without the grant a reversible MEDIUM-blast action at 0.90 confidence
        queues, because the MEDIUM floor is 0.95.
        """
        without = unified_decision(action_type="block_ip", blast_radius=BlastRadius.MEDIUM, confidence=0.90, reversible=True)
        assert without.mode is AutonomyMode.QUEUED_APPROVAL

        with_grant = unified_decision(
            action_type="block_ip",
            blast_radius=BlastRadius.MEDIUM,
            confidence=0.90,
            reversible=True,
            earned_grant="earned",
        )
        assert with_grant.mode is AutonomyMode.AUTO
        assert with_grant.earned_from == "earned"

    def test_confidence_is_still_required(self):
        """A grant is evidence about the agent in general.

        Confidence is what it says about this decision. Neither substitutes
        for the other, so a low-confidence call still queues even with a
        perfect track record behind the verb.
        """
        decision = unified_decision(
            action_type="block_ip",
            blast_radius=BlastRadius.MEDIUM,
            confidence=0.40,
            reversible=True,
            earned_grant="earned",
        )
        assert decision.mode is AutonomyMode.QUEUED_APPROVAL

    def test_a_grant_never_lowers_a_bar(self):
        """It is consulted only on the path already heading for the queue.

        So the worst a wrong grant can do is auto-execute something reversible
        that a human would have approved. Everything that was AUTO without it
        stays AUTO, and everything that was BLOCKED or queued for a structural
        reason stays there.
        """
        for blast in (BlastRadius.LOW, BlastRadius.MEDIUM, BlastRadius.HIGH, BlastRadius.CRITICAL):
            for confidence in (0.10, 0.50, 0.86, 0.96, 1.0):
                for reversible in (True, False):
                    plain = unified_decision(
                        action_type="block_ip",
                        blast_radius=blast,
                        confidence=confidence,
                        reversible=reversible,
                    )
                    granted = unified_decision(
                        action_type="block_ip",
                        blast_radius=blast,
                        confidence=confidence,
                        reversible=reversible,
                        earned_grant="earned",
                    )
                    if plain.mode is AutonomyMode.AUTO:
                        assert granted.mode is AutonomyMode.AUTO, (blast, confidence, reversible)
                    else:
                        # The only permitted movement is queued -> auto, and
                        # only on the reversible MEDIUM branch.
                        assert granted.mode in {plain.mode, AutonomyMode.AUTO}
                        if granted.mode is not plain.mode:
                            assert blast is BlastRadius.MEDIUM and reversible


class TestTheRationaleSaysWhichKind:
    def test_an_earned_grant_reads_as_a_track_record(self):
        decision = unified_decision(
            action_type="block_ip",
            blast_radius=BlastRadius.MEDIUM,
            confidence=0.90,
            reversible=True,
            earned_grant="earned",
        )
        assert "measured track record" in decision.rationale

    def test_an_override_reads_as_an_override(self):
        decision = unified_decision(
            action_type="block_ip",
            blast_radius=BlastRadius.MEDIUM,
            confidence=0.90,
            reversible=True,
            earned_grant="operator_override",
        )
        assert "operator override" in decision.rationale
        assert decision.earned_from == "operator_override"
