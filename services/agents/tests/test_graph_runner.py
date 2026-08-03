"""#569 — the shared, durable investigation-graph runner.

Proves the runner records one ledger event per graph node (under the run's
deterministic id, with a seq offset so it follows the worker's triage_verdict
event) and that a wall-clock budget bounds the run and fails safe to
needs_review on timeout. A tiny fake graph stands in for the compiled
LangGraph so the runner logic is tested in isolation (no external calls).
"""

from __future__ import annotations

import asyncio
import uuid
from uuid import uuid4

import pytest
from app.graph import runner as runner_mod
from app.graph.runner import InvestigationBudget, _run
from app.models.state import InvestigationState

pytestmark = pytest.mark.asyncio


class _FakeGraph:
    def __init__(self, steps: list[dict], *, delay: float = 0.0) -> None:
        self._steps = steps
        self._delay = delay

    async def astream(self, _state_dict):  # noqa: ANN001
        for step in self._steps:
            if self._delay:
                await asyncio.sleep(self._delay)
            yield step


def _state() -> InvestigationState:
    return InvestigationState(incident_id=uuid4(), tenant_id=uuid4(), alert_summary="cred dump")


async def test_runner_records_one_ledger_event_per_node(monkeypatch):
    events: list[dict] = []

    async def _rec(**kwargs):  # noqa: ANN003
        events.append(kwargs)
        return uuid4()

    async def _resolve(_ref):  # noqa: ANN001
        return uuid4()

    async def _noop(**kwargs):  # noqa: ANN003
        return None

    monkeypatch.setattr(runner_mod.ledger_module, "record_event", _rec)
    monkeypatch.setattr(runner_mod.ledger_module, "resolve_tenant", _resolve)
    monkeypatch.setattr(runner_mod.ledger_module, "start_run", _noop)
    monkeypatch.setattr(runner_mod.ledger_module, "complete_run", _noop)

    state = _state()
    graph = _FakeGraph(
        [
            {"triage": {"verdict": "true_positive"}},
            {"enrichment": {"findings": ["enriched"]}},
            {"attack_path": {"status": "completed"}},
        ]
    )
    await _run(graph, state, budget=InvestigationBudget(max_seconds=5), persist=True, seq_start=1)

    assert [e["agent"] for e in events] == ["triage", "enrichment", "attack_path"]
    # seq follows the worker's triage_verdict event (seq 1) without colliding.
    assert [e["seq"] for e in events] == [2, 3, 4]
    assert all(e["kind"] == "graph_step" for e in events)


async def test_runner_budget_timeout_fails_safe_to_needs_review():
    state = _state()
    # Each step sleeps 0.2s; a 0.05s budget times out before completion.
    graph = _FakeGraph([{"triage": {}}, {"enrichment": {}}], delay=0.2)
    result = await _run(graph, state, budget=InvestigationBudget(max_seconds=0.05), persist=False, seq_start=0)
    assert result.verdict == "needs_review"
    assert any("budget" in f.lower() for f in result.findings)


async def test_runner_merges_node_outputs_into_final_state(monkeypatch):
    async def _resolve(_ref):  # noqa: ANN001
        return None  # persist path disabled (no tenant) — pure merge test

    monkeypatch.setattr(runner_mod.ledger_module, "resolve_tenant", _resolve)

    state = _state()
    graph = _FakeGraph(
        [
            {"triage": {"verdict": "true_positive", "confidence": 0.7}},
            {"enrichment": {"findings": ["ioc malicious"]}},
        ]
    )
    result = await _run(graph, state, budget=InvestigationBudget(max_seconds=5), persist=False, seq_start=0)
    assert result.verdict == "true_positive"
    assert result.confidence == 0.7
    assert "ioc malicious" in result.findings
    assert isinstance(result.run_id, uuid.UUID)
