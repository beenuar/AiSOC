"""The promotion gate, tested on the cases where it has to say no.

Gap-closure Phase 2.3.

A gate is worth only its refusals. Four of them are interesting enough that
getting any one wrong would let a tenant act unattended on a track record that
does not support it, and each fails in a way that looks reasonable from the
outside:

* too few decisions, which is the easy one
* enough decisions but too few malicious ones, which a queue produces by
  itself because a real queue is mostly false positives
* agreement that is high only because the agent abstains, which looks like
  caution from every angle
* drift that arrives gradually, which a window average absorbs

The fifth case, and the one the audit log exists for, is an operator
overruling a refusal. That has to stay possible and has to stay visibly
distinct from autonomy anybody earned.
"""

from __future__ import annotations

import pytest
from app.services.autonomy_evidence_rules import (
    DEFAULT_THRESHOLDS,
    AgreementWindow,
    GrantSource,
    PromotionThresholds,
    Refusal,
    evaluate_demotion,
    evaluate_promotion,
)


def window(
    *,
    labelled: int,
    agreed: int,
    malicious_support: int,
    malicious_caught: int,
    abstained: int = 0,
    unlabeled: int = 0,
) -> AgreementWindow:
    """A window with the counts named, and answered derived so they add up."""
    return AgreementWindow(
        resolved=labelled + unlabeled,
        labelled=labelled,
        abstained=abstained,
        answered=labelled - abstained,
        agreed=agreed,
        malicious_support=malicious_support,
        malicious_caught=malicious_caught,
    )


def qualifying() -> AgreementWindow:
    """A track record that earns the capability, used as the control.

    Every refusal test below starts from this and breaks one thing, so a test
    that fails tells you which property it was rather than that something is
    wrong somewhere.
    """
    return window(labelled=120, agreed=112, malicious_support=35, malicious_caught=34, abstained=6)


def healthy_recent() -> AgreementWindow:
    return window(labelled=50, agreed=49, malicious_support=14, malicious_caught=14, abstained=1)


class TestTheControlIsActuallyQualifying:
    def test_a_good_track_record_earns_it(self):
        verdict = evaluate_promotion(window=qualifying(), recent=healthy_recent())
        assert verdict.allowed is True
        assert verdict.refusals == ()


class TestRefusalOneTooFewDecisions:
    def test_twenty_decisions_is_not_a_track_record(self):
        verdict = evaluate_promotion(
            window=window(labelled=20, agreed=20, malicious_support=8, malicious_caught=8),
            recent=window(labelled=20, agreed=20, malicious_support=8, malicious_caught=8),
        )
        assert verdict.allowed is False
        assert Refusal.INSUFFICIENT_SAMPLE in verdict.refusals

    def test_perfect_agreement_does_not_substitute_for_a_sample(self):
        """20 for 20 is 100%, and it is still 20."""
        verdict = evaluate_promotion(
            window=window(labelled=20, agreed=20, malicious_support=20, malicious_caught=20),
            recent=AgreementWindow(),
        )
        assert verdict.allowed is False

    def test_the_floor_is_configurable(self):
        small = window(labelled=20, agreed=20, malicious_support=8, malicious_caught=8)
        relaxed = PromotionThresholds(min_decisions=10, min_malicious=5, drift_min_answered=100)
        assert evaluate_promotion(window=small, recent=small, thresholds=relaxed).allowed is True


class TestRefusalTwoTooFewMaliciousCases:
    def test_a_large_sample_of_a_quiet_queue_is_refused(self):
        """A real queue reaches 100 decisions with two true positives in it.

        Agreement over that sample says the agent can recognise noise. That is
        not the question, and it is the shape almost every evaluation corpus
        naturally takes.
        """
        verdict = evaluate_promotion(
            window=window(labelled=400, agreed=398, malicious_support=2, malicious_caught=2),
            recent=window(labelled=50, agreed=50, malicious_support=0, malicious_caught=0),
        )
        assert verdict.allowed is False
        assert Refusal.INSUFFICIENT_MALICIOUS in verdict.refusals
        # And not for want of a sample: the sample is four times the floor.
        assert Refusal.INSUFFICIENT_SAMPLE not in verdict.refusals

    def test_the_floor_matches_the_one_replay_uses(self):
        """Phase 1 withholds a headline accuracy below 30 malicious cases.

        Two different floors for the same statistical problem would mean a
        replay report that refuses to print a number and a promotion gate that
        acts on it.
        """
        assert DEFAULT_THRESHOLDS.min_malicious == 30

    def test_zero_malicious_cases_refuses_on_recall_too(self):
        """An unmeasured recall is a refusal, not a pass.

        "Not measured" must never be read here as "met the threshold", which
        is the direction a `None` silently takes if it is compared with `<`.
        """
        verdict = evaluate_promotion(
            window=window(labelled=400, agreed=400, malicious_support=0, malicious_caught=0),
            recent=AgreementWindow(),
        )
        assert Refusal.MALICIOUS_RECALL_BELOW_THRESHOLD in verdict.refusals


class TestRefusalThreeAgreementBoughtByAbstaining:
    def test_an_agent_that_declines_most_of_its_queue_is_refused(self):
        """Perfect on everything it answered, and it answered a fifth of them.

        This is the refusal a naive gate misses, because every number it looks
        at is excellent.
        """
        verdict = evaluate_promotion(
            window=window(labelled=200, abstained=160, agreed=40, malicious_support=40, malicious_caught=12),
            recent=window(labelled=50, abstained=40, agreed=10, malicious_support=10, malicious_caught=3),
        )
        assert verdict.allowed is False
        assert Refusal.EXCESSIVE_ABSTENTION in verdict.refusals

    def test_abstaining_did_not_lift_the_agreement_rate_that_was_checked(self):
        """The guard that does not depend on a threshold at all.

        Even with the abstention cap removed, the agent is refused, because
        every malicious case it declined counted against recall. Two
        independent guards, and this test removes the first to prove the
        second is load-bearing rather than redundant.
        """
        evasive = window(labelled=200, abstained=160, agreed=40, malicious_support=40, malicious_caught=12)
        assert evasive.agreement_rate == 1.0

        no_abstention_cap = PromotionThresholds(max_abstention_rate=1.0)
        verdict = evaluate_promotion(window=evasive, recent=AgreementWindow(), thresholds=no_abstention_cap)

        assert verdict.allowed is False
        assert Refusal.EXCESSIVE_ABSTENTION not in verdict.refusals
        assert Refusal.MALICIOUS_RECALL_BELOW_THRESHOLD in verdict.refusals

    def test_answering_nothing_at_all_is_refused_rather_than_unmeasured(self):
        verdict = evaluate_promotion(
            window=window(labelled=200, abstained=200, agreed=0, malicious_support=40, malicious_caught=0),
            recent=AgreementWindow(),
        )
        assert verdict.allowed is False
        assert Refusal.AGREEMENT_BELOW_THRESHOLD in verdict.refusals


class TestRefusalFourGradualDrift:
    def test_a_window_that_still_passes_is_refused_when_the_recent_slice_has_slipped(self):
        """The case a window average is built to hide.

        Three weeks at 99% and one week at 70% still averages about 95%. The
        window is genuinely qualifying here; the trailing slice is not, and
        that is the whole finding.
        """
        recent_decline = window(labelled=50, agreed=35, malicious_support=12, malicious_caught=11, abstained=2)
        assert (recent_decline.agreement_rate or 0) < DEFAULT_THRESHOLDS.demotion_agreement

        verdict = evaluate_promotion(window=qualifying(), recent=recent_decline)

        assert verdict.allowed is False
        assert verdict.refusals == (Refusal.RECENT_DRIFT,)

    def test_an_existing_grant_is_demoted_on_the_same_slice(self):
        """Promotion and demotion read the same trailing slice.

        A grant issued into a decline it would be revoked for the next moment
        would produce a promote/demote pair in the audit log seconds apart,
        which reads as a malfunction rather than as a gate working.
        """
        recent_decline = window(labelled=50, agreed=35, malicious_support=12, malicious_caught=11, abstained=2)
        assert evaluate_demotion(window=qualifying(), recent=recent_decline).allowed is False

    def test_a_slice_too_small_to_judge_does_not_demote(self):
        """A quiet tenant must not lose a grant over three decisions.

        `False` from the drift check means "the recent slice cannot say", not
        "the recent slice is fine"; the window checks still apply, and this
        test pins the distinction so a later tightening does not make quiet
        weeks dangerous.
        """
        tiny_and_bad = window(labelled=4, agreed=1, malicious_support=2, malicious_caught=0)
        assert evaluate_demotion(window=qualifying(), recent=tiny_and_bad).allowed is True

    def test_a_recent_slice_with_no_malicious_cases_does_not_demote_on_recall(self):
        """No true positives arrived. That is not evidence the agent got worse."""
        quiet = window(labelled=50, agreed=49, malicious_support=0, malicious_caught=0, abstained=1)
        assert evaluate_demotion(window=qualifying(), recent=quiet).allowed is True


class TestDemotionIsNotTheMirrorOfPromotion:
    def test_the_floors_sit_below_the_promotion_thresholds(self):
        """Deliberate hysteresis: a rate at the line must not flip the grant."""
        borderline = window(labelled=120, agreed=112, malicious_support=35, malicious_caught=30, abstained=0)
        rate = borderline.agreement_rate or 0.0
        assert rate < DEFAULT_THRESHOLDS.min_agreement
        assert rate >= DEFAULT_THRESHOLDS.demotion_agreement

        # Not good enough to earn, good enough to keep. That gap is the point.
        assert evaluate_promotion(window=borderline, recent=healthy_recent()).allowed is False
        assert evaluate_demotion(window=borderline, recent=healthy_recent()).allowed is True

    def test_an_unmeasured_rate_refuses_a_promotion_and_does_not_demote_a_grant(self):
        """The asymmetry stated as a test, because it looks like an inconsistency.

        Promotion: nothing has been shown, so no. Demotion: nothing has been
        shown, so there is no evidence the agent got worse, and revoking over
        an empty denominator would punish a quiet week.
        """
        nothing_yet = AgreementWindow()
        assert evaluate_promotion(window=nothing_yet, recent=nothing_yet).allowed is False
        assert evaluate_demotion(window=nothing_yet, recent=nothing_yet).allowed is True


class TestItSaysEverythingThatIsWrongAtOnce:
    def test_refusals_are_not_short_circuited(self):
        """An operator told one thing at a time overrides out of frustration.

        Three separate problems here, and all three come back together.
        """
        verdict = evaluate_promotion(
            window=window(labelled=30, abstained=20, agreed=6, malicious_support=4, malicious_caught=1),
            recent=AgreementWindow(),
        )
        assert Refusal.INSUFFICIENT_SAMPLE in verdict.refusals
        assert Refusal.INSUFFICIENT_MALICIOUS in verdict.refusals
        assert Refusal.EXCESSIVE_ABSTENTION in verdict.refusals
        assert len(verdict.refusals) >= 3

    def test_never_measured_is_its_own_refusal(self):
        """A tenant who never started must not be told to try again later."""
        verdict = evaluate_promotion(window=qualifying(), recent=healthy_recent(), shadow_enabled=False)
        assert verdict.allowed is False
        assert verdict.refusals == (Refusal.SHADOW_MODE_NOT_ENABLED,)


class TestAnOverrideIsADifferentWord:
    def test_the_two_sources_are_distinct_values(self):
        assert GrantSource.EARNED.value != GrantSource.OPERATOR_OVERRIDE.value

    def test_the_gate_verdict_is_identical_whether_or_not_an_override_follows(self):
        """`evaluate_promotion` takes no override argument, and that is the design.

        The source is decided from this verdict by the caller, so there is no
        argument a caller could pass that would make a refused promotion
        evaluate as allowed and be recorded as earned.
        """
        import inspect

        parameters = set(inspect.signature(evaluate_promotion).parameters)
        assert "override" not in parameters
        assert parameters == {"window", "recent", "thresholds", "shadow_enabled"}


class TestThresholdsTravelByValue:
    def test_a_snapshot_records_numbers_not_a_reference(self):
        """Retuning a threshold next quarter must not rewrite past justifications."""
        strict = PromotionThresholds(min_agreement=0.99)
        payload = strict.as_dict()
        assert payload["min_agreement"] == pytest.approx(0.99)
        assert payload["min_decisions"] == DEFAULT_THRESHOLDS.min_decisions
