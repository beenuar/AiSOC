"""
InvestigatorOrchestrator — LangGraph state-machine wiring all Pillar-1 agents.

Graph topology:
  START → recon → forensic → responder → report_writer → END

The state dict is threaded through every node unchanged apart from the
node's own additions. An error in any node marks the state as "failed"
and short-circuits to END.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, AsyncIterator

import structlog
from langgraph.graph import END, START, StateGraph

from .forensic_agent import run_forensic
from .recon_agent import run_recon
from .report_writer_agent import run_report_writer
from .responder_agent import run_responder
from .state import InvestigatorState, StepKind

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# Error-wrapper: catches exceptions in any node and marks state as failed
# ---------------------------------------------------------------------------

def _safe_node(fn):
    """Wrap an async node so exceptions are captured in state instead of crashing the graph."""
    import functools

    @functools.wraps(fn)
    async def wrapper(state_dict: dict[str, Any]) -> dict[str, Any]:
        try:
            return await fn(state_dict)
        except Exception as exc:  # noqa: BLE001
            state = InvestigatorState.from_dict(state_dict)
            state.status = "failed"
            state.error = str(exc)
            state.completed_at = datetime.utcnow()
            state.log(StepKind.ERROR, fn.__name__, f"Node failed: {exc}")
            logger.error(f"{fn.__name__} failed", case_id=state.case_id, error=str(exc))
            return state.to_dict()

    return wrapper


# ---------------------------------------------------------------------------
# Guard: skip remaining nodes if state is already failed/completed
# ---------------------------------------------------------------------------

async def _guard(state_dict: dict[str, Any]) -> str:
    """Conditional edge: 'continue' or 'end'."""
    status = state_dict.get("status", "")
    if status in ("failed", "completed"):
        return "end"
    return "continue"


# ---------------------------------------------------------------------------
# Build the compiled graph (cached on first call)
# ---------------------------------------------------------------------------

_GRAPH: Any = None


def _build_graph():
    global _GRAPH
    if _GRAPH is not None:
        return _GRAPH

    builder = StateGraph(dict)

    builder.add_node("recon", _safe_node(run_recon))
    builder.add_node("forensic", _safe_node(run_forensic))
    builder.add_node("responder", _safe_node(run_responder))
    builder.add_node("report_writer", _safe_node(run_report_writer))

    builder.add_edge(START, "recon")

    for src, dst in [("recon", "forensic"), ("forensic", "responder"), ("responder", "report_writer")]:
        builder.add_conditional_edges(
            src,
            _guard,
            {"continue": dst, "end": END},
        )

    builder.add_edge("report_writer", END)

    _GRAPH = builder.compile()
    return _GRAPH


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class InvestigatorOrchestrator:
    """High-level wrapper around the compiled LangGraph."""

    def __init__(self) -> None:
        self._graph = _build_graph()

    async def run(
        self,
        case_id: str,
        alert_summary: str,
        raw_alert: dict[str, Any] | None = None,
        tenant_id: str = "default",
    ) -> InvestigatorState:
        """Execute the full investigation pipeline and return the final state."""
        initial = InvestigatorState(
            case_id=case_id,
            alert_summary=alert_summary,
            raw_alert=raw_alert or {},
            tenant_id=tenant_id,
        )
        logger.info("investigation.start", case_id=case_id)
        result = await self._graph.ainvoke(initial.to_dict())
        final = InvestigatorState.from_dict(result)
        logger.info(
            "investigation.end",
            case_id=case_id,
            status=final.status,
            iterations=final.iteration,
        )
        return final

    async def stream(
        self,
        case_id: str,
        alert_summary: str,
        raw_alert: dict[str, Any] | None = None,
        tenant_id: str = "default",
    ) -> AsyncIterator[dict[str, Any]]:
        """
        Stream per-step state updates as typed events:
          {"type": "step",  "kind": <str>, "agent": <str>, "summary": <str>, ...}
          {"type": "done",  "state": {report_md, recon, forensic, responder, ...}}
          {"type": "error", "error": <str>}
        """
        initial = InvestigatorState(
            case_id=case_id,
            alert_summary=alert_summary,
            raw_alert=raw_alert or {},
            tenant_id=tenant_id,
        )
        logger.info("investigation.stream.start", case_id=case_id)
        last_state: InvestigatorState | None = None
        try:
            async for event in self._graph.astream(initial.to_dict()):
                # event is {node_name: state_dict}
                for node_name, state_dict in event.items():
                    state = InvestigatorState.from_dict(state_dict)
                    last_state = state
                    # Emit all new audit-log entries since the last node
                    for entry in state.audit_log:
                        yield {
                            "type": "step",
                            "kind": entry.kind,
                            "agent": entry.agent,
                            "summary": entry.summary,
                            "node": node_name,
                            "case_id": case_id,
                            "ts": entry.ts.isoformat() if hasattr(entry.ts, "isoformat") else str(entry.ts),
                        }

            # Emit the final "done" event with the complete state payload
            if last_state is not None:
                yield {
                    "type": "done",
                    "case_id": case_id,
                    "state": {
                        "status": last_state.status,
                        "report_md": last_state.report_md,
                        "report_html": last_state.report_html,
                        "recon": last_state.recon.model_dump(mode="json"),
                        "forensic": last_state.forensic.model_dump(mode="json"),
                        "responder": last_state.responder.model_dump(mode="json"),
                        "started_at": last_state.started_at.isoformat(),
                        "completed_at": last_state.completed_at.isoformat() if last_state.completed_at else None,
                        "error": last_state.error,
                    },
                }
        except Exception as exc:  # noqa: BLE001
            logger.error("investigation.stream.error", case_id=case_id, error=str(exc))
            yield {"type": "error", "error": str(exc), "case_id": case_id}


async def run_investigation(
    case_id: str,
    alert_summary: str,
    raw_alert: dict[str, Any] | None = None,
    tenant_id: str = "default",
) -> InvestigatorState:
    """Convenience function — creates a one-shot orchestrator and runs it."""
    return await InvestigatorOrchestrator().run(
        case_id=case_id,
        alert_summary=alert_summary,
        raw_alert=raw_alert,
        tenant_id=tenant_id,
    )
