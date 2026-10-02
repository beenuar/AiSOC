"""A budget breach stops the loop, and the run routes to a human.

Parity plan 2.6: "Enforce per-alert token caps and runner tool-call budgets
inside the loop, not after it" and "an over-budget investigation ends in a
labelled budget-exhausted state that routes to a human, never in a verdict".

What was wrong
--------------
`InvestigationBudget` declared `max_tokens` and `max_tool_calls` and only
`max_seconds` had a reader. The runner's module docstring said the token
budget was "enforced upstream by the CostGovernor", which charges a rolling
window across runs rather than bounding this one, so a single investigation
could spend any number of tokens inside its two minutes.

The distinction this file tests is mid-loop versus after. A check that runs
when the graph finishes can only report the overspend; a check inside the
loop prevents it, and that is the difference between a cap and a receipt.
"""

from __future__ import annotations

import contextvars
import uuid

import pytest
from app.core.cost_telemetry import CallRecord, CostTracker
from app.graph.runner import InvestigationBudget, _budget_exhausted, default_budget


def _tracker_with(*, calls: int, tokens_each: int) -> CostTracker:
    tracker = CostTracker(run_id=str(uuid.uuid4()), tenant_id=str(uuid.uuid4()), persist=False)
    for _ in range(calls):
        tracker._records.append(
            CallRecord(
                model="aisoc-triage",
                prompt_tokens=tokens_each,
                completion_tokens=0,
                latency_ms=1.0,
            )
        )
    return tracker


class TestTheAccumulators:
    def test_tokens_count_prompt_and_completion(self) -> None:
        tracker = CostTracker(run_id="r", tenant_id="t", persist=False)
        tracker._records.append(CallRecord(model="m", prompt_tokens=100, completion_tokens=40, latency_ms=1.0))
        assert tracker.tokens_used == 140, "counting only prompt tokens would let a verbose model spend past the cap"

    def test_calls_counts_every_call(self) -> None:
        assert _tracker_with(calls=3, tokens_each=1).calls_made == 3


class TestTheBudgetCheck:
    def test_a_run_under_budget_continues(self) -> None:
        budget = InvestigationBudget(max_seconds=120, max_tokens=1000, max_tool_calls=8)
        tracker = _tracker_with(calls=2, tokens_each=100)
        with _bound(tracker):
            assert _budget_exhausted(budget) is None

    def test_the_token_cap_stops_it(self) -> None:
        budget = InvestigationBudget(max_seconds=120, max_tokens=500, max_tool_calls=99)
        tracker = _tracker_with(calls=3, tokens_each=200)  # 600
        with _bound(tracker):
            reason = _budget_exhausted(budget)
        assert reason is not None
        assert "token budget" in reason
        assert "600" in reason and "500" in reason, (
            f"the reason must carry the numbers, or an operator cannot tell a tight budget from a runaway run: {reason!r}"
        )

    def test_the_call_cap_stops_it(self) -> None:
        budget = InvestigationBudget(max_seconds=120, max_tokens=10**9, max_tool_calls=3)
        tracker = _tracker_with(calls=3, tokens_each=1)
        with _bound(tracker):
            reason = _budget_exhausted(budget)
        assert reason is not None
        assert "model-call budget" in reason

    def test_an_unmeasured_run_is_allowed_to_continue(self) -> None:
        """No tracker bound means no measurement.

        Refusing on the absence of telemetry would stop every run in a
        deployment that has not configured it, which is a far worse failure
        than an unbounded one.
        """
        assert _budget_exhausted(default_budget()) is None

    def test_a_zero_budget_is_treated_as_unset_not_as_zero(self) -> None:
        """`max_tokens=0` reads as "no cap", because a cap of zero would
        stop every run before its first call and look like a hang."""
        budget = InvestigationBudget(max_seconds=120, max_tokens=0, max_tool_calls=0)
        with _bound(_tracker_with(calls=5, tokens_each=10_000)):
            assert _budget_exhausted(budget) is None


@pytest.mark.asyncio
class TestTheLoopActuallyStops:
    """The property the plan asks for: the loop stops mid-run.

    Driven through `_run`, the function the production path calls, with a
    graph that would stream far more steps than the budget allows.
    """

    async def test_it_breaks_before_the_graph_is_exhausted(self) -> None:
        from app.graph import runner as runner_module
        from app.models.state import InvestigationState

        streamed: list[str] = []

        class _Graph:
            async def astream(self, _state):  # noqa: ANN001, ANN202
                for i in range(20):
                    streamed.append(f"node{i}")
                    # Each node spends, so the budget is reached partway.
                    tracker = runner_module.current_cost_tracker()
                    if tracker is not None:
                        tracker._records.append(
                            CallRecord(
                                model="aisoc-triage",
                                prompt_tokens=100,
                                completion_tokens=0,
                                latency_ms=1.0,
                            )
                        )
                    yield {f"node{i}": {}}

        state = InvestigationState(incident_id=uuid.uuid4(), tenant_id=uuid.uuid4())
        tracker = CostTracker(run_id=str(state.run_id), tenant_id=str(state.tenant_id), persist=False)
        budget = InvestigationBudget(max_seconds=30, max_tokens=500, max_tool_calls=99)

        with _bound(tracker):
            result = await runner_module._run(_Graph(), state, budget=budget, persist=False, seq_start=0)

        assert len(streamed) < 20, (
            f"the graph streamed all {len(streamed)} nodes, so the budget did not stop the loop and is a receipt rather than a cap"
        )
        assert result.budget_exhausted is True
        assert result.budget_exhausted_reason
        assert "token budget" in result.budget_exhausted_reason

    async def test_it_escalates_rather_than_returning_a_verdict(self) -> None:
        """A truncated run has not reached a conclusion.

        Reporting whatever the model last said is how a stopped
        investigation becomes a confident wrong disposition.
        """
        from app.agents.dispositions import NEEDS_REVIEW
        from app.graph import runner as runner_module
        from app.models.state import InvestigationState

        class _Graph:
            async def astream(self, _state):  # noqa: ANN001, ANN202
                tracker = runner_module.current_cost_tracker()
                for i in range(5):
                    if tracker is not None:
                        tracker._records.append(CallRecord(model="m", prompt_tokens=1000, completion_tokens=0, latency_ms=1.0))
                    # The graph keeps asserting a confident verdict.
                    yield {f"n{i}": {"verdict": "benign", "confidence": 0.99}}

        state = InvestigationState(incident_id=uuid.uuid4(), tenant_id=uuid.uuid4())
        tracker = CostTracker(run_id=str(state.run_id), tenant_id=str(state.tenant_id), persist=False)
        budget = InvestigationBudget(max_seconds=30, max_tokens=1500, max_tool_calls=99)

        with _bound(tracker):
            result = await runner_module._run(_Graph(), state, budget=budget, persist=False, seq_start=0)

        assert result.verdict == NEEDS_REVIEW, (
            f"a budget-exhausted run returned {result.verdict!r} rather than escalating; the "
            "graph's last confident verdict was presented as the answer"
        )
        assert any("escalating" in f.lower() for f in result.findings), (
            "the findings do not say the run stopped early, so an analyst reading the case "
            "cannot tell a completed investigation from a truncated one"
        )


class _bound:
    """Bind a tracker into the context the runner reads."""

    def __init__(self, tracker: CostTracker) -> None:
        self._tracker = tracker
        # Annotated, because inferring `None` from the initial value makes
        # the `set()` below an incompatible assignment.
        self._token: contextvars.Token[CostTracker | None] | None = None

    def __enter__(self) -> CostTracker:
        from app.core import cost_telemetry

        self._token = cost_telemetry._current_tracker.set(self._tracker)
        return self._tracker

    def __exit__(self, *_: object) -> None:
        from app.core import cost_telemetry

        if self._token is not None:
            cost_telemetry._current_tracker.reset(self._token)
