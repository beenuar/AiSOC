"""Replay and shadow mode record what happened, not a placeholder.

Fix pass items 3.4, 3.6 and 3.12. See `plans/aisoc_fix_pass_plan.plan.md`.

Three figures that were structurally unable to be right
-------------------------------------------------------
**3.4 Model attribution.** `fused_alert_consumer` stamps a shadow decision
with `model=_opt_text(getattr(state, "model_used", None))`. `InvestigationState`
has 33 fields and none of them is `model_used`, so that `getattr` default is
the only branch that ever runs: **every shadow decision records a null model**,
and per-model agreement -- the whole point of recording it -- is empty on every
deployment.

**3.6 Tool calls.** The replay runner sets `decision.tool_calls = 0` under a
comment saying it is "recorded so a future change that gives triage a tool
shows up here as a number moving off zero". A literal zero can never move off
zero. The intent in the comment and the code contradict each other.

**3.12 Pivot counting.** `_classify_pivots` treats a result as a pivot unless
its preview contains `available: false`. A tool that raised returns
`{"error": "..."}` from the registry wrapper, which has no `available` key, so
**a failed call counts as a pivot** and an investigation can reach its depth
floor on four tools that all threw.

What this file asserts
----------------------
The real functions, with the real shapes they are handed in production. No
mock stands between the assertion and the thing being measured, because in all
three cases the thing being measured is a single arithmetic or attribute step
and a mock of it would be the test asserting its own input.
"""

from __future__ import annotations

import pytest


class TestPivotsCountOnlySuccessfulCalls:
    """3.12 -- a failed call is not a pivot."""

    def test_a_tool_that_raised_is_not_counted_as_a_pivot(self) -> None:
        """The registry wrapper's shape, verbatim.

        `app/tools/registry.py` returns `{"error": f"{type(exc).__name__}: {exc}"}`
        when a tool raises. It has no `available` key, so the pre-fix
        classifier put it in `pivots`.
        """
        from app.investigator.deep_investigation import _classify_pivots

        trace = [
            {"tool": "lake_process_activity", "result_preview": "{'error': 'TimeoutError: '}"},
            {"tool": "lake_network", "result_preview": '{"error": "ConnectError: refused"}'},
        ]

        pivots, unavailable = _classify_pivots(trace)

        assert pivots == [], f"a failed call was counted as a pivot: {pivots}"
        assert sorted(unavailable) == ["lake_network", "lake_process_activity"]

    def test_an_unavailable_tool_is_still_not_a_pivot(self) -> None:
        """The case that already worked, so the fix cannot regress it."""
        from app.investigator.deep_investigation import _classify_pivots

        pivots, unavailable = _classify_pivots([{"tool": "siem_search", "result_preview": "{'available': False, 'reason': 'no backend'}"}])

        assert pivots == []
        assert unavailable == ["siem_search"]

    def test_a_successful_call_is_a_pivot(self) -> None:
        """The negative control. A classifier that called everything a failure
        would satisfy both assertions above."""
        from app.investigator.deep_investigation import _classify_pivots

        pivots, unavailable = _classify_pivots(
            [{"tool": "lake_process_activity", "result_preview": "{'available': True, 'rows': [{'host': 'WS-42'}]}"}]
        )

        assert pivots == ["lake_process_activity"]
        assert unavailable == []

    def test_depth_cannot_be_reached_on_failures_alone(self) -> None:
        """Why this matters, stated as the property rather than the mechanism.

        Four tools that all threw must not look like four pivots, or an
        investigation reports the depth it was required to reach while having
        learned nothing.
        """
        from app.investigator.deep_investigation import _classify_pivots

        trace = [{"tool": f"tool_{n}", "result_preview": "{'error': 'RuntimeError: boom'}"} for n in range(4)]

        pivots, _ = _classify_pivots(trace)

        assert len(set(pivots)) == 0, f"four failed calls produced {len(set(pivots))} distinct pivots"


def _state(**extra):
    """A minimally valid state. Only `incident_id` is required."""
    import uuid

    from app.models.state import InvestigationState

    return InvestigationState(incident_id=uuid.uuid4(), tenant_id=uuid.uuid4(), **extra)


class TestTheStateCarriesTheModelThatAnswered:
    """3.4 -- a shadow decision must name the model it came from."""

    def test_investigation_state_has_a_field_for_the_model_used(self) -> None:
        """`getattr(state, "model_used", None)` is read by the shadow writer.

        Pre-fix the field does not exist, so the default is the only branch
        that runs and every shadow decision records a null model.
        """
        from app.models.state import InvestigationState

        assert "model_used" in InvestigationState.model_fields, (
            "InvestigationState has no `model_used`, so the shadow writer's `getattr(state, 'model_used', None)` can only ever be None"
        )

    def test_a_state_round_trips_the_model_it_was_given(self) -> None:

        state = _state(model_used="aisoc-triage")

        assert state.model_used == "aisoc-triage"

    def test_a_state_with_no_model_records_none_rather_than_a_guess(self) -> None:
        """The negative control. A default of `"unknown"` would make the
        column non-null and useless; absence has to stay legible."""

        assert _state().model_used is None


class TestToolCallsAreCountedRatherThanAsserted:
    """3.6 -- the number has to be able to move."""

    def test_the_runner_does_not_assign_a_literal_zero(self) -> None:
        """Read as source deliberately, and this is the one place that is right.

        The defect is not a wrong value -- zero is the correct answer today,
        because shadow mode declines escalation and escalation is the only
        stage that calls tools. The defect is that the comment above it says
        the figure is "recorded so a future change that gives triage a tool
        shows up here as a number moving off zero", and a literal can never
        move. There is no runtime behaviour to assert against, because the
        current correct answer and the hardcoded answer are the same number;
        what can be asserted is that the figure is derived.
        """
        import inspect

        from app.replay import runner

        source = inspect.getsource(runner)

        assert "decision.tool_calls = 0" not in source, (
            "tool_calls is assigned a literal, so the comment's promise that it "
            "will move off zero when triage gains a tool cannot come true"
        )

    def test_the_count_comes_from_the_ledger(self) -> None:
        from app.replay import runner

        assert hasattr(runner, "_tool_calls_recorded"), "no helper derives the tool-call count, so nothing reads what actually happened"

    @pytest.mark.parametrize(
        ("rows", "expected"),
        [([], 0), ([{"kind": "tool_call"}], 1), ([{"kind": "tool_call"}, {"kind": "llm_response"}], 1)],
    )
    def test_only_tool_call_rows_are_counted(self, rows: list[dict], expected: int) -> None:
        """Counting every ledger row would report the LLM calls as tool calls."""
        from app.replay.runner import _tool_calls_recorded

        assert _tool_calls_recorded(rows) == expected


class TestAReplayHasNoSideEffects:
    """3.2 -- two of the four leaks the plan names.

    The other two were already closed: `ShadowTriageWriter.persists_cost` is
    `False` so the cost ledger is not written, and every write method returns
    the "nothing happened" value its live counterpart returns on a no-op.

    These two were not, because neither reaches the worker through the writer:
    `alert_trigger.run_for_alert` was called unconditionally, and the cost
    governor's `DEDUPLICATED` branch answered from a live cache. Both now ask
    the writer, which is the same mechanism the other two already used.
    """

    def test_the_replay_writer_declines_both(self) -> None:
        from app.replay.shadow import ShadowTriageWriter

        writer = ShadowTriageWriter()

        assert writer.fires_playbooks is False, "a replay of last month's alerts would fire this month's playbooks"
        assert writer.uses_dedup_cache is False, "a replay graded on a cached production verdict measures the cache, not the agent"

    def test_the_live_writer_still_does_both(self) -> None:
        """The negative control. A fix that declined these everywhere would
        turn playbooks and deduplication off in production."""
        from app.workers.triage_persistence import LiveTriageWriter

        writer = LiveTriageWriter()

        assert writer.fires_playbooks is True
        assert writer.uses_dedup_cache is True

    def test_shadow_mode_withholds_playbooks_but_keeps_deduplication(self) -> None:
        """Shadow mode is measuring, not replaying, so the two differ.

        A playbook that ran would be the agent acting on a verdict nobody has
        accepted, which is what the mode exists to withhold. Deduplication is
        production behaviour, and turning it off would make the scorecard
        describe a different workload from the one it predicts.
        """
        from app.workers.shadow_mode import ShadowModeTriageWriter

        writer = ShadowModeTriageWriter.__new__(ShadowModeTriageWriter)

        assert writer.fires_playbooks is False
        assert writer.uses_dedup_cache is True

    def test_the_protocol_declares_both(self) -> None:
        """The protocol, not three separate classes.

        A writer added later that forgets one fails  against the
        protocol, which is how the three existing writers were found when
        these two members were added.
        """
        from app.workers.triage_persistence import TriageWriter

        for name in ("fires_playbooks", "uses_dedup_cache"):
            assert hasattr(TriageWriter, name), f"the writer protocol does not declare {name}"
