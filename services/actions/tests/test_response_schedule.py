"""Time gates: a tenant's schedule may raise an approval, never lower one.

Wave-2 Phase 6.3. "Automatic" has always been a statement about the action's
impact and the finding's confidence, and never about whether anybody is
awake. These tests fix the direction of the new control: every condition can
only move AUTOMATIC to ANALYST, and a decision that already requires a human
comes back untouched.

The second property is the one worth the file. ``on_call_now = None`` means
this platform could not read the rota, and it is treated as nobody on call —
because the alternative is that a failed lookup silently re-enables
automatic containment at three in the morning, which is the direction
nobody checks.
"""

from __future__ import annotations

from datetime import UTC, datetime, time

import pytest
from app.live_actions.approval_rules import (
    ApprovalDecision,
    BusinessWindow,
    ResponseSchedule,
    apply_schedule,
    evaluate,
)
from app.live_actions.contract import ActionImpact, ApprovalRequirement

#: Monday 09:00–17:00 UTC, which is inside business hours for
#: ``MONDAY_MIDDAY`` and outside it for ``SUNDAY_NIGHT``.
WEEKDAYS = tuple(BusinessWindow(weekday=day, start=time(9, 0), end=time(17, 0)) for day in range(5))

MONDAY_MIDDAY = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)
SUNDAY_NIGHT = datetime(2026, 11, 1, 3, 0, tzinfo=UTC)


def _automatic() -> ApprovalDecision:
    decision = evaluate(
        impact=ActionImpact.MODERATE,
        declared_approval=ApprovalRequirement.AUTOMATIC,
        confidence=0.99,
        tier="L3",
    )
    assert decision.requirement is ApprovalRequirement.AUTOMATIC, "the fixture must start automatic or it proves nothing"
    return decision


class TestTheGateOnlyRaises:
    def test_no_schedule_changes_nothing(self) -> None:
        """Every tenant until one configures a schedule."""
        decision = _automatic()
        assert apply_schedule(decision, None, now=SUNDAY_NIGHT) is decision

    def test_outside_business_hours_raises_to_analyst(self) -> None:
        schedule = ResponseSchedule(windows=WEEKDAYS, require_human_outside_business_hours=True)
        raised = apply_schedule(_automatic(), schedule, now=SUNDAY_NIGHT)
        assert raised.requirement is ApprovalRequirement.ANALYST
        assert "outside the tenant's declared response hours" in raised.reason

    def test_inside_business_hours_leaves_it_automatic(self) -> None:
        """The positive control.

        A gate stuck closed looks like working caution, so the test that a
        healthy tenant keeps its automatic verb is the one that catches it.
        """
        schedule = ResponseSchedule(windows=WEEKDAYS, require_human_outside_business_hours=True)
        unchanged = apply_schedule(_automatic(), schedule, now=MONDAY_MIDDAY)
        assert unchanged.requirement is ApprovalRequirement.AUTOMATIC

    def test_a_decision_already_needing_a_human_is_untouched(self) -> None:
        """There is nothing a clock can add to 'a human must approve this'."""
        decision = evaluate(
            impact=ActionImpact.HIGH,
            declared_approval=ApprovalRequirement.MANDATORY_HUMAN,
            confidence=0.99,
            tier="L4",
        )
        schedule = ResponseSchedule(windows=WEEKDAYS, require_human_outside_business_hours=True, freeze_active=True)
        assert apply_schedule(decision, schedule, now=SUNDAY_NIGHT) is decision

    def test_it_never_produces_an_automatic_decision(self) -> None:
        """The direction, asserted over every requirement the matrix emits."""
        schedule = ResponseSchedule(
            windows=WEEKDAYS,
            require_human_outside_business_hours=True,
            require_human_without_on_call=True,
            freeze_active=True,
        )
        for impact in ActionImpact:
            for declared in ApprovalRequirement:
                before = evaluate(impact=impact, declared_approval=declared, confidence=1.0, tier="L4")
                after = apply_schedule(before, schedule, now=SUNDAY_NIGHT)
                if before.requirement is not ApprovalRequirement.AUTOMATIC:
                    assert after.requirement is before.requirement
                else:
                    assert after.requirement in (ApprovalRequirement.AUTOMATIC, ApprovalRequirement.ANALYST)


class TestUnknownIsNotCover:
    def test_an_unreadable_on_call_state_counts_as_nobody_on_call(self) -> None:
        schedule = ResponseSchedule(on_call_now=None, require_human_without_on_call=True)
        raised = apply_schedule(_automatic(), schedule, now=MONDAY_MIDDAY)
        assert raised.requirement is ApprovalRequirement.ANALYST
        assert "could not be read" in raised.reason

    def test_nobody_on_call_says_so_rather_than_saying_unknown(self) -> None:
        schedule = ResponseSchedule(on_call_now=False, require_human_without_on_call=True)
        raised = apply_schedule(_automatic(), schedule, now=MONDAY_MIDDAY)
        assert "nobody is on call" in raised.reason

    def test_somebody_on_call_leaves_it_automatic(self) -> None:
        schedule = ResponseSchedule(on_call_now=True, require_human_without_on_call=True)
        assert apply_schedule(_automatic(), schedule, now=MONDAY_MIDDAY).requirement is ApprovalRequirement.AUTOMATIC

    def test_a_schedule_with_no_windows_is_not_business_hours(self) -> None:
        """A tenant who switched the condition on and declared no windows
        meant 'never unattended'. Reading an empty list as 'always business
        hours' would turn the control off at the moment it was switched on."""
        schedule = ResponseSchedule(windows=(), require_human_outside_business_hours=True)
        assert schedule.is_business_hours(MONDAY_MIDDAY) is False
        assert apply_schedule(_automatic(), schedule, now=MONDAY_MIDDAY).requirement is ApprovalRequirement.ANALYST


class TestTheImpactFloor:
    def test_conditions_do_not_apply_below_the_declared_floor(self) -> None:
        """Otherwise a tenant who wanted to stop midnight containments would
        also be approving every enrichment at midnight, and would switch the
        whole thing off."""
        schedule = ResponseSchedule(
            windows=WEEKDAYS,
            require_human_outside_business_hours=True,
            applies_from_impact=ActionImpact.HIGH,
        )
        low = evaluate(
            impact=ActionImpact.LOW,
            declared_approval=ApprovalRequirement.AUTOMATIC,
            confidence=0.999,
            tier="L3",
        )
        if low.requirement is ApprovalRequirement.AUTOMATIC:
            assert apply_schedule(low, schedule, now=SUNDAY_NIGHT).requirement is ApprovalRequirement.AUTOMATIC

    def test_conditions_apply_at_and_above_the_floor(self) -> None:
        schedule = ResponseSchedule(
            windows=WEEKDAYS,
            require_human_outside_business_hours=True,
            applies_from_impact=ActionImpact.MODERATE,
        )
        assert schedule.conditions_apply_to(ActionImpact.MODERATE) is True
        assert schedule.conditions_apply_to(ActionImpact.HIGH) is True
        assert schedule.conditions_apply_to(ActionImpact.LOW) is False


class TestWindows:
    @pytest.mark.parametrize(
        ("moment", "expected"),
        [
            (datetime(2026, 11, 2, 8, 59, tzinfo=UTC), False),
            (datetime(2026, 11, 2, 9, 0, tzinfo=UTC), True),
            (datetime(2026, 11, 2, 16, 59, tzinfo=UTC), True),
            (datetime(2026, 11, 2, 17, 0, tzinfo=UTC), False),
            (datetime(2026, 11, 7, 12, 0, tzinfo=UTC), False),
        ],
    )
    def test_boundaries_are_half_open(self, moment: datetime, expected: bool) -> None:
        assert ResponseSchedule(windows=WEEKDAYS).is_business_hours(moment) is expected

    def test_a_window_may_wrap_midnight(self) -> None:
        """A night shift is exactly the case this feature is about."""
        night = (BusinessWindow(weekday=2, start=time(22, 0), end=time(2, 0)),)
        schedule = ResponseSchedule(windows=night)
        assert schedule.is_business_hours(datetime(2026, 11, 4, 23, 30, tzinfo=UTC)) is True
        assert schedule.is_business_hours(datetime(2026, 11, 4, 1, 0, tzinfo=UTC)) is True
        assert schedule.is_business_hours(datetime(2026, 11, 4, 12, 0, tzinfo=UTC)) is False


class TestFreeze:
    def test_a_freeze_raises_regardless_of_the_clock(self) -> None:
        schedule = ResponseSchedule(windows=WEEKDAYS, freeze_active=True)
        raised = apply_schedule(_automatic(), schedule, now=MONDAY_MIDDAY)
        assert raised.requirement is ApprovalRequirement.ANALYST
        assert "change freeze" in raised.reason

    def test_several_conditions_are_all_named_in_the_reason(self) -> None:
        """'Requires approval' with no reason is the kind of prompt people
        learn to click through."""
        schedule = ResponseSchedule(
            windows=WEEKDAYS,
            on_call_now=False,
            require_human_outside_business_hours=True,
            require_human_without_on_call=True,
            freeze_active=True,
        )
        reason = apply_schedule(_automatic(), schedule, now=SUNDAY_NIGHT).reason
        assert "change freeze" in reason
        assert "outside the tenant's declared response hours" in reason
        assert "nobody is on call" in reason


class TestGradedVerbsForTimeoutContainment:
    """The partition a wave-2 6.3 timeout containment is allowed to name.

    ``services/agents`` owns the sweeper that fires a declared deadline and
    cannot import these contracts — different service, different image — so
    its own test for this skips. The predicate is asserted here, where the
    vocabulary actually lives, rather than left to a skip that proves
    nothing.
    """

    def test_read_only_verbs_are_excluded(self) -> None:
        from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS

        graded = {name for name, contract in CAPABILITY_CONTRACTS.items() if contract.impact is not ActionImpact.READ_ONLY}

        # A timeout that runs a search has not contained anything.
        assert "search_siem" not in graded
        assert "get_cloud_identity" not in graded
        # And the verbs a deadline would plausibly reach are in.
        assert "isolate_host" in graded
        assert "disable_user" in graded

    def test_every_graded_verb_still_carries_its_own_approval_requirement(self) -> None:
        """A timeout is not a tier promotion.

        Dispatching through the governed path means the verb is graded by
        its own contract, so a MANDATORY_HUMAN verb named as a timeout
        containment queues rather than runs. Asserted on the contract set
        because that is what the dispatch consults.
        """
        from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS

        for name, contract in CAPABILITY_CONTRACTS.items():
            if contract.impact is ActionImpact.READ_ONLY:
                continue
            decision = evaluate(
                impact=contract.impact,
                declared_approval=contract.approval,
                confidence=1.0,
                tier="L4",
            )
            if contract.approval in (ApprovalRequirement.MANDATORY_HUMAN, ApprovalRequirement.PROHIBITED):
                assert decision.requirement is not ApprovalRequirement.AUTOMATIC, (
                    f"{name} would auto-execute at a deadline despite its contract"
                )
