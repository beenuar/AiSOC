"""An auto-escalated alert must be investigated as deeply as a manual one.

Three gaps in investigation depth, all the same shape: a capability was built,
and the path that needed it did not use it.

1. The manual investigator orchestrator has built a `ContextBundle` — graph
   neighbourhood, blast radius, historical verdicts for the same entities,
   UEBA baselines — since T2.1. The escalation path the auto-triage worker
   uses never did, so the high-volume automatic route investigated with
   strictly less context than a human clicking "investigate" on the identical
   alert.

2. `run_with_tools` is described in its own module docstring as "the primitive
   that lets specialist agents use tools instead of reasoning over a single
   pre-serialised blob", and called `bound.ainvoke` directly — bypassing the
   LLM input contract on the one place in the system where untrusted content
   is fed back into a prompt.

3. QRadar's AQL translator was written, exported and tested, and the connector
   type was missing from the API's federated-capable set.
"""

from __future__ import annotations

import uuid

import pytest
from app.agents import tool_loop
from app.agents.investigation_agent import _bundle_findings
from app.models.state import AgentStatus, InvestigationState
from app.workers import fused_alert_consumer as consumer
from app.workers.fused_alert_consumer import FusedAlertTriageWorker


def _state() -> InvestigationState:
    return InvestigationState(
        run_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        alert_summary="Lateral movement from WIN-DC01",
        raw_alert={"hostname": "WIN-DC01", "username": "svc_backup"},
        verdict="true_positive",
        status=AgentStatus.RUNNING,
    )


# ── context on the escalation path ────────────────────────────────────────


@pytest.mark.asyncio
async def test_escalation_prefetches_the_context_bundle(monkeypatch: pytest.MonkeyPatch):
    """The regression: the automatic path got no pre-fetched context at all."""
    seen: dict[str, object] = {}

    async def _prefetch(*, case_id, tenant_id, alert_summary, raw_alert):  # noqa: ANN001
        seen.update(case_id=case_id, tenant_id=tenant_id, alert_summary=alert_summary)
        return {"entities": [], "blast_radius": {}}

    async def _run_escalation(state, **kwargs):  # noqa: ANN001, ANN003
        seen["bundle_at_run"] = state.context_bundle
        return state

    monkeypatch.setattr(consumer, "prefetch_context_bundle_dict", _prefetch)
    monkeypatch.setattr(consumer, "run_escalation", _run_escalation)
    monkeypatch.setenv("AISOC_AGENT_ESCALATION", "1")

    state = _state()
    await FusedAlertTriageWorker(bootstrap_servers="localhost:9092")._maybe_escalate(state)

    assert seen["case_id"] == str(state.incident_id)
    assert seen["tenant_id"] == str(state.tenant_id)
    # Built *before* the subgraph runs, or the nodes cannot use it.
    assert seen["bundle_at_run"] is not None


@pytest.mark.asyncio
async def test_a_context_failure_never_blocks_the_escalation(
    monkeypatch: pytest.MonkeyPatch,
):
    """Context is additive. Losing it must not lose the investigation."""
    ran = False

    async def _prefetch(**kwargs):  # noqa: ANN003
        return {}  # prefetch_context_bundle_dict never raises; it returns {}

    async def _run_escalation(state, **kwargs):  # noqa: ANN001, ANN003
        nonlocal ran
        ran = True
        return state

    monkeypatch.setattr(consumer, "prefetch_context_bundle_dict", _prefetch)
    monkeypatch.setattr(consumer, "run_escalation", _run_escalation)
    monkeypatch.setenv("AISOC_AGENT_ESCALATION", "1")

    await FusedAlertTriageWorker(bootstrap_servers="localhost:9092")._maybe_escalate(_state())
    assert ran


# ── the bundle reaches the investigation ──────────────────────────────────


def _bundle(**overrides) -> dict:
    """A ContextBundle as `model_dump(mode="json")` produces it."""
    payload = {"incident_id": str(uuid.uuid4()), "tenant_id": "t", "entities": []}
    payload.update(overrides)
    return payload


def test_historical_verdicts_become_findings():
    """How identical alerts previously resolved is the highest-value context."""
    findings = _bundle_findings(
        _bundle(
            historical_similar_cases=[
                {"key": "sig-a", "verdict": "false_positive", "similarity_score": 0.94},
            ]
        )
    )
    assert any("false_positive" in f for f in findings)
    assert any("similar historical" in f.lower() for f in findings)


def test_blast_radius_becomes_a_finding():
    findings = _bundle_findings(
        _bundle(
            entity_neighborhoods={
                "host:WIN-DC01": {
                    "entity": {"type": "host", "key": "host:WIN-DC01", "value": "WIN-DC01"},
                    "blast_radius_score": 0.82,
                }
            }
        )
    )
    assert any("blast radius" in f.lower() for f in findings)


def test_no_bundle_produces_no_findings():
    assert _bundle_findings(None) == []
    assert _bundle_findings({}) == []


def test_an_unreadable_bundle_is_ignored_not_fatal():
    """A shape change in the bundle must not break every investigation."""
    assert _bundle_findings({"entities": "not-a-list"}) == []
    assert _bundle_findings({"no": "incident_id"}) == []


def test_raw_payloads_are_never_surfaced():
    """Only the bundle's declared-safe summary fields reach the findings."""
    findings = _bundle_findings(
        _bundle(
            entity_neighborhoods={
                "host:h": {
                    "entity": {"type": "host", "key": "host:h", "value": "h"},
                    "blast_radius_score": 0.5,
                    "nodes": [{"vaulted": "do-not-leak"}],
                }
            }
        )
    )
    assert not any("do-not-leak" in f for f in findings)


# ── the tool loop honours the LLM contract ────────────────────────────────


@pytest.mark.asyncio
async def test_the_tool_loop_routes_through_the_llm_contract(
    monkeypatch: pytest.MonkeyPatch,
):
    """Tool output is untrusted: a log row can read as an instruction.

    Calling `bound.ainvoke` directly skipped injection validation on precisely
    the highest-risk content in the system, and lost token/cost telemetry for
    every tool-calling turn.
    """
    from app.tools.registry import ToolRegistry

    called = False

    async def _safe(llm, messages, **kwargs):  # noqa: ANN001, ANN003
        nonlocal called
        called = True

        class _Resp:
            content = "done"
            tool_calls: list = []

        return _Resp()

    monkeypatch.setattr(tool_loop, "safe_ainvoke", _safe)

    class _LLM:
        def bind_tools(self, schemas):  # noqa: ANN001
            return self

    out = await tool_loop.run_with_tools(_LLM(), system="s", user="u", registry=ToolRegistry())
    assert called, "the loop bypassed safe_ainvoke"
    assert out["content"] == "done"
