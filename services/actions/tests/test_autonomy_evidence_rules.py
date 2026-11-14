"""The arithmetic that decides whether an agent has earned anything.

Gap-closure Phase 2.2.

Most of these are about one property, stated three ways, because it is the
property a plausible implementation gets wrong: **an agent must not be able to
improve its agreement rate by declining to answer.** That is not a hypothetical
failure. Routing the hard cases to a human is the single easiest thing for a
triage agent to do, it looks like caution from every angle, and under a naive
metric it produces a perfect record on the alerts nobody was worried about.
"""

from __future__ import annotations

import pytest
from app.services.autonomy_evidence_rules import (
    ABSTENTION_VERDICTS,
    AGREEMENT_COUNTS_SQL,
    DEFAULT_THRESHOLDS,
    GRADED_DISPOSITIONS,
    MALICIOUS,
    RECENT_COUNTS_SQL,
    UNLABELED,
    AgreementWindow,
    PromotionThresholds,
    scoped_sql,
    to_named_params,
    window_from_counts,
)


class TestAbstainingCannotBuyAgreement:
    def test_declining_the_hard_cases_does_not_move_the_rate(self):
        """Ten right out of ten answered is 100% whether or not 90 were declined."""
        answered_everything = AgreementWindow(
            resolved=10,
            labelled=10,
            answered=10,
            abstained=0,
            agreed=10,
            malicious_support=4,
            malicious_caught=4,
        )
        declined_most = AgreementWindow(
            resolved=100,
            labelled=100,
            answered=10,
            abstained=90,
            agreed=10,
            malicious_support=4,
            malicious_caught=4,
        )
        assert answered_everything.agreement_rate == 1.0
        assert declined_most.agreement_rate == 1.0

    def test_what_declining_does_move_is_the_abstention_rate(self):
        """The cost of abstaining is visible, and it is visible in its own column."""
        declined_most = AgreementWindow(
            resolved=100,
            labelled=100,
            answered=10,
            abstained=90,
            agreed=10,
            malicious_support=4,
            malicious_caught=4,
        )
        assert declined_most.abstention_rate == 0.9
        assert declined_most.abstention_rate > DEFAULT_THRESHOLDS.max_abstention_rate

    def test_an_abstention_on_a_malicious_case_counts_as_a_miss(self):
        """Recall's denominator is every malicious case, answered or not.

        An alert routed to a human was not caught by the agent, and this is
        the metric that says so. Phase 1 makes the same call in
        ``aisoc_benchmark.replay``, and the two have to agree or the replay
        report and the live scorecard describe different agents.
        """
        window = AgreementWindow(
            resolved=40,
            labelled=40,
            answered=10,
            abstained=30,
            agreed=10,
            malicious_support=30,
            malicious_caught=8,
        )
        # Agreement is perfect over what it answered.
        assert window.agreement_rate == 1.0
        # Recall is not, because 22 malicious cases went to a human.
        assert window.malicious_recall == pytest.approx(8 / 30)


class TestAbsentIsNotZero:
    def test_a_rate_with_no_denominator_is_none(self):
        empty = AgreementWindow()
        assert empty.agreement_rate is None
        assert empty.malicious_recall is None
        assert empty.abstention_rate is None

    def test_no_malicious_cases_is_not_zero_recall(self):
        """A tenant whose queue held no true positives has an unmeasured recall.

        Zero would say the agent missed every one of them. There were none to
        miss, and the two call for opposite responses: one is a reason to
        refuse autonomy, the other is a reason to keep measuring.
        """
        window = AgreementWindow(
            resolved=50,
            labelled=50,
            answered=50,
            abstained=0,
            agreed=50,
            malicious_support=0,
            malicious_caught=0,
        )
        assert window.malicious_recall is None
        assert window.agreement_rate == 1.0


class TestUnlabelledIsResolvedButNotGraded:
    def test_an_analyst_who_declined_to_classify_is_counted_and_excluded(self):
        window = AgreementWindow(
            resolved=100,
            labelled=40,
            answered=40,
            abstained=0,
            agreed=38,
            malicious_support=12,
            malicious_caught=11,
        )
        assert window.unlabeled == 60
        # The rate is over the 40 that carried a label, not the 100 closed.
        assert window.agreement_rate == pytest.approx(38 / 40)

    def test_unlabeled_is_not_a_gradeable_disposition(self):
        """Anything treating it as a verdict must fail a membership check."""
        assert UNLABELED not in GRADED_DISPOSITIONS


class TestTheCountsHaveToAddUp:
    """A window whose parts disagree is a bug in the aggregate query.

    It would surface as a plausible-looking rate rather than as an error, and
    a plausible-looking rate is what a promotion gets granted on.
    """

    def test_answered_plus_abstained_must_equal_labelled(self):
        with pytest.raises(ValueError, match="must equal"):
            AgreementWindow(resolved=10, labelled=10, answered=5, abstained=2, agreed=5)

    def test_agreed_cannot_exceed_answered(self):
        with pytest.raises(ValueError, match="agreed"):
            AgreementWindow(resolved=10, labelled=10, answered=5, abstained=5, agreed=6)

    def test_caught_cannot_exceed_support(self):
        with pytest.raises(ValueError, match="malicious_caught"):
            AgreementWindow(
                resolved=10,
                labelled=10,
                answered=10,
                abstained=0,
                agreed=10,
                malicious_support=2,
                malicious_caught=3,
            )

    def test_labelled_cannot_exceed_resolved(self):
        with pytest.raises(ValueError, match="labelled"):
            AgreementWindow(resolved=5, labelled=10, answered=10, abstained=0, agreed=0)


class TestWindowFromCounts:
    def test_it_reads_a_driver_row(self):
        window = window_from_counts(
            {
                "resolved": 120,
                "labelled": 100,
                "abstained": 10,
                "answered": 90,
                "agreed": 87,
                "malicious_support": 31,
                "malicious_caught": 29,
            }
        )
        assert window.unlabeled == 20
        assert window.agreement_rate == pytest.approx(87 / 90)
        assert window.malicious_recall == pytest.approx(29 / 31)

    def test_missing_keys_read_as_zero_not_as_a_crash(self):
        """An aggregate that returned no row at all is an empty window.

        ``fetchrow`` on a tenant with no decisions returns ``None``, and the
        callers pass ``dict(row or {})``. That has to produce a window whose
        rates are all "not measured", not a ``KeyError`` three frames up.
        """
        assert window_from_counts({}) == AgreementWindow()


class TestTheSqlIsSplicedNotConcatenated:
    def test_both_statements_carry_the_scope_marker(self):
        """Neither statement may be scoped by appending to the end.

        The window aggregate ends in a ``WHERE`` chain and the trailing-slice
        one ends in ``ORDER BY … LIMIT`` inside a CTE. A caller appending to
        either would produce valid SQL for one and a syntax error for the
        other, which is how a scope silently stops being applied on the half
        that still parses.
        """
        for statement in (AGREEMENT_COUNTS_SQL, RECENT_COUNTS_SQL):
            assert "/*scope*/" in statement

    def test_an_empty_predicate_scores_the_whole_tenant(self):
        spliced = scoped_sql(AGREEMENT_COUNTS_SQL, "")
        assert "/*scope*/" not in spliced
        assert "d.tenant_id = $1" in spliced

    def test_the_tenant_predicate_survives_every_scope(self):
        spliced = scoped_sql(RECENT_COUNTS_SQL, "AND d.alert_class = :scope_key")
        assert "d.tenant_id = $1" in spliced
        assert "AND d.alert_class = :scope_key" in spliced

    def test_named_params_rewrites_every_placeholder(self):
        names = ["tenant_id", "graded", "abstentions", "malicious", "window_start", "window_end", "recent_limit"]
        rewritten = to_named_params(AGREEMENT_COUNTS_SQL, names)
        assert ":tenant_id" in rewritten
        assert ":recent_limit" not in rewritten  # only the recent statement binds $7
        for index in range(1, len(names) + 1):
            assert f"${index}" not in rewritten

    def test_double_digit_placeholders_are_rewritten_before_single_digit_ones(self):
        """``$1`` must not match inside ``$10``.

        Neither statement binds ten parameters today, so this is about the
        helper rather than about them: the next caller that does would
        otherwise get ``:tenant_id0`` and a runtime error far from here.
        """
        names = [f"p{n}" for n in range(1, 12)]
        rewritten = to_named_params("SELECT $1, $10, $11", names)
        assert rewritten == "SELECT :p1, :p10, :p11"


class TestTheDefaultsArePlansDefaults:
    def test_the_plan_numbers_are_the_defaults(self):
        assert DEFAULT_THRESHOLDS.min_decisions == 100
        assert DEFAULT_THRESHOLDS.min_malicious == 30

    def test_demotion_floors_sit_below_promotion_thresholds(self):
        """Deliberate hysteresis.

        Equal values would flip a grant on every decision that moved the rate
        across the line, and the audit log would fill with churn nobody could
        read, which is how a real demotion gets missed.
        """
        limits = PromotionThresholds()
        assert limits.demotion_agreement < limits.min_agreement
        assert limits.demotion_malicious_recall < limits.min_malicious_recall

    def test_thresholds_serialise_by_value(self):
        """The snapshot records numbers, not the name of a constant.

        A threshold retuned next quarter must not rewrite the justification
        for every promotion granted under the old one.
        """
        payload = PromotionThresholds(min_decisions=7).as_dict()
        assert payload["min_decisions"] == 7
        assert payload["window_days"] == DEFAULT_THRESHOLDS.window_days


class TestTheTaxonomyMatchesPhaseOne:
    def test_malicious_is_the_writeback_spelling(self):
        assert MALICIOUS == "true_positive"
        assert GRADED_DISPOSITIONS[0] == MALICIOUS

    def test_an_empty_verdict_is_an_abstention(self):
        """A null verdict reaches the aggregate as ``''`` through COALESCE.

        If that were not an abstention it would be scored as a wrong answer,
        and a run that crashed before producing a verdict would count against
        agreement as though the agent had decided something.
        """
        assert "" in ABSTENTION_VERDICTS
        assert "needs_review" in ABSTENTION_VERDICTS
        assert "escalate" in ABSTENTION_VERDICTS
