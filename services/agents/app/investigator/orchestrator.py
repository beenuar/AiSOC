"""
InvestigatorOrchestrator — LangGraph state-machine wiring all Pillar-1 agents.

Graph topology:
  START → recon → forensic → responder → report_writer → END

The state dict is threaded through every node unchanged apart from the
node's own additions. An error in any node marks the state as "failed"
and short-circuits to END.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import datetime
from typing import Any

import structlog
from langgraph.graph import END, START, StateGraph
from opentelemetry import trace

from app.core.cost_telemetry import CostTracker

from . import ledger
from .forensic_agent import run_forensic
from .recon_agent import run_recon
from .report_writer_agent import run_report_writer
from .responder_agent import run_responder
from .state import InvestigatorState, StepKind

logger = structlog.get_logger()

try:
    from app.core.telemetry import get_tracer as _get_tracer

    _tracer = _get_tracer("aisoc.investigator")
except Exception:
    _tracer = trace.get_tracer("aisoc.investigator")


# ---------------------------------------------------------------------------
# Error-wrapper: catches exceptions in any node and marks state as failed
# ---------------------------------------------------------------------------


def _safe_node(fn):
    """Wrap an async node so exceptions are captured in state instead of crashing the graph.
    Also emits an OpenTelemetry span per node execution."""
    import functools

    @functools.wraps(fn)
    async def wrapper(state_dict: dict[str, Any]) -> dict[str, Any]:
        span_name = f"investigator.{fn.__name__}"
        with _tracer.start_as_current_span(span_name) as span:
            case_id = state_dict.get("case_id", "unknown")
            span.set_attribute("case.id", case_id)
            span.set_attribute("agent.name", fn.__name__)
            try:
                result = await fn(state_dict)
                span.set_attribute("agent.status", result.get("status", "unknown"))
                return result
            except Exception as exc:  # noqa: BLE001
                span.record_exception(exc)
                span.set_status(trace.StatusCode.ERROR, str(exc))
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
        run_id: uuid.UUID | None = None,
    ) -> InvestigatorState:
        """Execute the full investigation pipeline and return the final state.

        Persists the run + every audit-log entry to the ledger if a database
        is configured. ``run_id`` may be passed in by the caller (e.g. the
        WebSocket emitter that already has the id), otherwise a new one is
        generated here.
        """
        with _tracer.start_as_current_span("investigator.run") as span:
            span.set_attribute("case.id", case_id)
            span.set_attribute("tenant.id", tenant_id)
            initial = InvestigatorState(
                case_id=case_id,
                alert_summary=alert_summary,
                raw_alert=raw_alert or {},
                tenant_id=tenant_id,
            )

            run_uuid = run_id or uuid.uuid4()
            tenant_uuid = await ledger.start_run(
                run_id=run_uuid,
                case_id=case_id,
                tenant_ref=tenant_id,
                alert_summary=alert_summary,
                raw_alert=raw_alert,
            )

            logger.info("investigation.start", case_id=case_id, run_id=str(run_uuid))
            async with CostTracker(run_id=str(run_uuid), tenant_id=tenant_id) as tracker:
                result = await self._graph.ainvoke(initial.to_dict())
                final = InvestigatorState.from_dict(result)
                # Stash cost summary so the API/UI can surface it.
                final.cost_summary = tracker.summary()

            # Persist the full audit log post-hoc (one shot, no streaming)
            if tenant_uuid is not None:
                for seq, entry in enumerate(final.audit_log):
                    await ledger.record_event(
                        run_id=run_uuid,
                        tenant_id=tenant_uuid,
                        seq=seq,
                        kind=entry.kind.value if hasattr(entry.kind, "value") else str(entry.kind),
                        agent=entry.agent,
                        summary=entry.summary,
                        payload=entry.metadata,
                        input_hash=entry.input_hash,
                        output_hash=entry.output_hash,
                        duration_ms=int(entry.duration_ms),
                        timestamp=entry.timestamp,
                    )

                # Stash the final report as an artifact for replay/audit
                if final.report_md:
                    await ledger.record_artifact(
                        run_id=run_uuid,
                        tenant_id=tenant_uuid,
                        kind="report_md",
                        content=final.report_md,
                    )

                await ledger.complete_run(
                    run_id=run_uuid,
                    tenant_id=tenant_uuid,
                    status=final.status,
                    error=final.error,
                    iterations=final.iteration,
                )

            span.set_attribute("investigation.status", final.status)
            span.set_attribute("investigation.iterations", final.iteration)
            span.set_attribute("investigation.run_id", str(run_uuid))
            if final.cost_summary:
                span.set_attribute("investigation.cost_usd", final.cost_summary.get("cost_usd", 0.0))
                span.set_attribute("investigation.tokens_total", final.cost_summary.get("tokens_total", 0))
            logger.info(
                "investigation.end",
                case_id=case_id,
                run_id=str(run_uuid),
                status=final.status,
                iterations=final.iteration,
                cost_usd=final.cost_summary.get("cost_usd") if final.cost_summary else None,
            )
            return final

    async def stream(
        self,
        case_id: str,
        alert_summary: str,
        raw_alert: dict[str, Any] | None = None,
        tenant_id: str = "default",
        run_id: uuid.UUID | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """Stream per-step state updates as typed events.

        Event types yielded:
          ``step``  - one per agent audit-log entry, in order, exactly once
          ``done``  - terminal event with the full final state
          ``error`` - terminal event if the graph raises

        Each event includes ``run_id`` so consumers can correlate the live
        WebSocket stream with the persisted ledger row.

        Implementation note
        -------------------
        LangGraph's ``astream`` yields the entire mutated state at every
        node transition, so naively iterating ``state.audit_log`` re-emits
        previously yielded entries. We track the last emitted seq per run
        and only forward new entries. This same monotonic seq becomes the
        primary sort key in the persisted ledger.
        """
        initial = InvestigatorState(
            case_id=case_id,
            alert_summary=alert_summary,
            raw_alert=raw_alert or {},
            tenant_id=tenant_id,
        )

        run_uuid = run_id or uuid.uuid4()
        tenant_uuid = await ledger.start_run(
            run_id=run_uuid,
            case_id=case_id,
            tenant_ref=tenant_id,
            alert_summary=alert_summary,
            raw_alert=raw_alert,
        )

        logger.info("investigation.stream.start", case_id=case_id, run_id=str(run_uuid))
        last_state: InvestigatorState | None = None
        emitted_count = 0  # how many audit_log entries already streamed
        tracker = CostTracker(run_id=str(run_uuid), tenant_id=tenant_id)
        try:
            await tracker.__aenter__()
            async for event in self._graph.astream(initial.to_dict()):
                # event is {node_name: state_dict}
                for node_name, state_dict in event.items():
                    state = InvestigatorState.from_dict(state_dict)
                    last_state = state
                    # Only emit audit-log entries we haven't seen yet
                    new_entries = state.audit_log[emitted_count:]
                    for offset, entry in enumerate(new_entries):
                        seq = emitted_count + offset
                        kind_val = entry.kind.value if hasattr(entry.kind, "value") else str(entry.kind)
                        ts_str = entry.timestamp.isoformat() if hasattr(entry.timestamp, "isoformat") else str(entry.timestamp)
                        # Persist before emitting so subscribers can deep-link
                        if tenant_uuid is not None:
                            await ledger.record_event(
                                run_id=run_uuid,
                                tenant_id=tenant_uuid,
                                seq=seq,
                                kind=kind_val,
                                agent=entry.agent,
                                summary=entry.summary,
                                payload=entry.metadata,
                                input_hash=entry.input_hash,
                                output_hash=entry.output_hash,
                                duration_ms=int(entry.duration_ms),
                                timestamp=entry.timestamp,
                            )
                        yield {
                            "type": "step",
                            "kind": kind_val,
                            "agent": entry.agent,
                            "summary": entry.summary,
                            "node": node_name,
                            "case_id": case_id,
                            "run_id": str(run_uuid),
                            "seq": seq,
                            "ts": ts_str,
                        }
                    emitted_count = len(state.audit_log)

            # Capture cost summary before emitting done so the UI sees it.
            cost_summary = tracker.summary()
            if last_state is not None:
                last_state.cost_summary = cost_summary

            # Emit the final "done" event with the complete state payload
            if last_state is not None:
                if tenant_uuid is not None and last_state.report_md:
                    await ledger.record_artifact(
                        run_id=run_uuid,
                        tenant_id=tenant_uuid,
                        kind="report_md",
                        content=last_state.report_md,
                    )
                if tenant_uuid is not None:
                    await ledger.complete_run(
                        run_id=run_uuid,
                        tenant_id=tenant_uuid,
                        status=last_state.status,
                        error=last_state.error,
                        iterations=last_state.iteration,
                    )
                yield {
                    "type": "done",
                    "case_id": case_id,
                    "run_id": str(run_uuid),
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
                        "cost_summary": cost_summary,
                    },
                }
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "investigation.stream.error",
                case_id=case_id,
                run_id=str(run_uuid),
                error=str(exc),
            )
            if tenant_uuid is not None:
                await ledger.complete_run(
                    run_id=run_uuid,
                    tenant_id=tenant_uuid,
                    status="failed",
                    error=str(exc),
                )
            yield {
                "type": "error",
                "error": str(exc),
                "case_id": case_id,
                "run_id": str(run_uuid),
            }
        finally:
            # Always flush + reset the tracker so the contextvar is cleared.
            try:
                await tracker.__aexit__(None, None, None)
            except Exception:  # noqa: BLE001
                logger.warning("cost_tracker.flush_failed", run_id=str(run_uuid))


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
