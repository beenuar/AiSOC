"""Shared, durable investigation-graph runner (issue #569).

Both the Kafka auto-triage worker and the manual investigations API run the
*same* orchestration through here, so escalated alerts flow through one
implementation instead of two divergent ones:

* the manual API runs the FULL graph (auto-triage → triage → enrichment →
  investigation → attack-path) via :func:`run_full_investigation`;
* the auto-triage worker, having already produced a governed verdict, runs the
  post-triage escalation subgraph via :func:`run_escalation`.

Every node transition is recorded to the Investigation Ledger (append-only,
``ON CONFLICT (run_id, seq) DO NOTHING``), so a restart mid-investigation
re-runs idempotently — it never loses or duplicates the run. A wall-clock
budget bounds the run; a token budget is enforced upstream by the
``CostGovernor`` and a tool-call budget by the ReAct loop's ``max_iters``.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass

import structlog

from app.agents.dispositions import NEEDS_REVIEW
from app.investigator import ledger as ledger_module
from app.models.state import AgentStatus, InvestigationState

logger = structlog.get_logger()


@dataclass(frozen=True)
class InvestigationBudget:
    """Resource envelope for one investigation (issue #569)."""

    max_seconds: float = 120.0
    max_tokens: int = 20_000
    max_tool_calls: int = 8


def default_budget() -> InvestigationBudget:
    return InvestigationBudget(
        max_seconds=float(os.getenv("AISOC_INVESTIGATION_MAX_SECONDS", "120")),
        max_tokens=int(os.getenv("AISOC_MAX_TOKENS_PER_ALERT", "20000")),
        max_tool_calls=int(os.getenv("AISOC_INVESTIGATION_MAX_TOOL_CALLS", "8")),
    )


async def _run(
    graph,  # noqa: ANN001 — a compiled LangGraph
    state: InvestigationState,
    *,
    budget: InvestigationBudget | None,
    persist: bool,
    seq_start: int,
) -> InvestigationState:
    budget = budget or default_budget()
    tenant_ref = str(state.tenant_id)
    state_dict = state.to_dict()
    merged: dict = dict(state_dict)

    tenant_uuid = await ledger_module.resolve_tenant(tenant_ref) if persist else None
    if persist:
        # Idempotent — start_run ON CONFLICT DO NOTHING (the worker may have
        # already opened this run when it persisted the triage verdict).
        await ledger_module.start_run(
            run_id=state.run_id,
            case_id=str(state.incident_id),
            tenant_ref=tenant_ref,
            alert_summary=state.alert_summary or "",
            raw_alert=state.raw_alert or {},
            model_used="graph:investigation",
        )

    seq = seq_start
    timed_out = False
    try:
        async with asyncio.timeout(budget.max_seconds):
            async for step in graph.astream(state_dict):
                if not isinstance(step, dict):
                    continue
                for node, out in step.items():
                    seq += 1
                    if isinstance(out, dict):
                        merged.update(out)
                    if tenant_uuid is not None:
                        await ledger_module.record_event(
                            run_id=state.run_id,
                            tenant_id=tenant_uuid,
                            seq=seq,
                            kind="graph_step",
                            agent=str(node),
                            summary=f"graph node '{node}' completed",
                            payload={"node": str(node)},
                        )
    except TimeoutError:
        timed_out = True
        logger.warning("investigation.budget_timeout", run_id=str(state.run_id), max_seconds=budget.max_seconds)

    try:
        result = InvestigationState.model_validate(merged)
    except Exception as exc:  # noqa: BLE001 — never let a mapping error lose the run
        logger.warning("investigation.state_rebuild_failed", run_id=str(state.run_id), error=str(exc))
        result = state

    if timed_out:
        result.add_finding(f"Investigation budget ({budget.max_seconds}s) exceeded — partial results, escalating.")
        if not result.verdict:
            result.verdict = NEEDS_REVIEW
        if result.status is AgentStatus.COMPLETED:
            result.status = AgentStatus.RUNNING

    if persist:
        await ledger_module.complete_run(
            run_id=result.run_id,
            tenant_id=tenant_uuid or result.tenant_id,
            status="completed",
            error=result.error,
            iterations=result.iteration_count,
        )
    return result


async def run_full_investigation(
    state: InvestigationState,
    *,
    budget: InvestigationBudget | None = None,
    persist: bool = True,
) -> InvestigationState:
    """Run the FULL graph (auto-triage → … → attack-path). Manual API entry."""
    from app.graph.workflow import investigation_graph  # noqa: PLC0415 — avoid import cycle

    return await _run(investigation_graph, state, budget=budget, persist=persist, seq_start=0)


async def run_escalation(
    state: InvestigationState,
    *,
    budget: InvestigationBudget | None = None,
    persist: bool = True,
    seq_start: int = 1,
) -> InvestigationState:
    """Run the post-triage escalation subgraph (triage → … → attack-path).

    Used by the auto-triage worker after it has produced (and persisted) a
    governed verdict. ``seq_start`` defaults to 1 so the recorded graph steps
    follow the worker's ``triage_verdict`` event (seq 1) without colliding.
    """
    from app.graph.workflow import escalation_graph  # noqa: PLC0415 — avoid import cycle

    return await _run(escalation_graph, state, budget=budget, persist=persist, seq_start=seq_start)
