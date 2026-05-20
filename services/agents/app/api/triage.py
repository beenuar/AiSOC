"""
Router triage API — T2.2 (v8.0)
==============================

Exposes the parallel router topology (``RouterOrchestrator``) as a
first-class HTTP surface so the web console, ChatOps bot, and eval
harness can dispatch alerts through the four-agent fan-out without
rewriting the legacy ``/investigate`` pipeline.

Endpoints
---------

* ``POST /api/v1/cases/{case_id}/triage`` — launch async router run.
* ``GET  /api/v1/triage/{run_id}``        — poll status + summary.

The topology selection is read on every router invocation via the
``AISOC_AGENT_PARALLEL_TOPOLOGY`` env flag (canonical default: on).
Callers may force a topology with the ``topology`` request field
(``"parallel"`` | ``"sequential"``); when unset the env flag wins.

This surface deliberately runs alongside ``investigate.py`` rather than
replacing it: the legacy ``InvestigatorOrchestrator`` streams per-step
NDJSON events for the existing console workbench, while the router is
a single-shot fan-out designed for the v8.0 auto-triage funnel. Wiring
them through separate routes keeps the blast radius minimal — a console
that still calls ``/cases/{id}/investigate`` keeps working unchanged.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

import httpx
import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from app.models.state import AgentStatus, InvestigationState
from app.orchestrator import PARALLEL_TOPOLOGY_FLAG, RouterOrchestrator

logger = structlog.get_logger()
router = APIRouter(prefix="/api/v1", tags=["triage"])

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_REALTIME_URL = os.environ.get("REALTIME_URL", "http://realtime:8086")
_INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "")

# Stable namespace for deriving deterministic tenant/incident UUIDs from
# string inputs (e.g. ``tenant_id="acme"``). Using a frozen project-scoped
# namespace so the same string always maps to the same UUID across pods.
_AISOC_NS = uuid.UUID("3b18b8a7-7c2c-4f15-bf3f-4c4b7a4f8d6e")

# ---------------------------------------------------------------------------
# Simple in-memory run store (separate from investigate.py to avoid
# accidental key collisions between the two surfaces).
# ---------------------------------------------------------------------------

_triage_runs: dict[str, dict[str, Any]] = {}
_router_orch = RouterOrchestrator()


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class TriageRequest(BaseModel):
    """Request body for ``POST /api/v1/cases/{case_id}/triage``.

    ``tenant_id`` and ``incident_id`` may be supplied as raw UUID strings
    or as arbitrary identifiers (e.g. ``"acme"``); non-UUID values are
    coerced via UUID5 against the project namespace so callers don't
    have to mint UUIDs upstream.
    """

    alert_summary: str = ""
    raw_alert: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = "default"
    incident_id: str | None = None
    # Optional override — when set, bypasses the env flag for this run.
    # One of ``"parallel"`` | ``"sequential"``. Anything else → 400.
    topology: str | None = None


class TriageResponse(BaseModel):
    run_id: str
    case_id: str
    status: str
    message: str
    topology: str  # "parallel" | "sequential" — the mode that *will* run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _coerce_uuid(raw: str | None, *, fallback: str) -> UUID:
    """Turn a caller-supplied identifier into a UUID.

    * ``None`` / empty → UUID5(fallback)
    * Valid UUID string → that UUID
    * Anything else → UUID5(value) so the same input always maps to the
      same UUID without making the caller manage UUIDs.
    """
    if not raw:
        return uuid.uuid5(_AISOC_NS, fallback)
    try:
        return UUID(raw)
    except (ValueError, TypeError):
        return uuid.uuid5(_AISOC_NS, raw)


def _resolve_topology(req_topology: str | None) -> str:
    """Resolve which topology this request will run under.

    Precedence:

    1. Explicit per-request override (``req_topology``).
    2. ``AISOC_AGENT_PARALLEL_TOPOLOGY`` env flag — default parallel.
    """
    if req_topology is not None:
        if req_topology not in {"parallel", "sequential"}:
            raise HTTPException(
                status_code=400,
                detail=f"invalid topology {req_topology!r}; expected 'parallel' or 'sequential'",
            )
        return req_topology
    raw = os.getenv(PARALLEL_TOPOLOGY_FLAG)
    if raw is None:
        return "parallel"
    return "sequential" if raw.strip().lower() in {"0", "false", "no", "off", "disabled"} else "parallel"


async def _emit_event(run_id: str, tenant_id: str, event: dict[str, Any]) -> None:
    """Forward a router event to the realtime service (best-effort)."""
    url = f"{_REALTIME_URL}/internal/agent-event"
    headers: dict[str, str] = {}
    if _INTERNAL_TOKEN:
        headers["x-internal-token"] = _INTERNAL_TOKEN
    payload = {
        "run_id": run_id,
        "tenant_id": tenant_id,
        "kind": event.get("kind", "step"),
        "agent": event.get("agent", "router"),
        "summary": event.get("summary", ""),
        "data": event.get("data"),
    }
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            await client.post(url, json=payload, headers=headers)
    except Exception as exc:  # noqa: BLE001
        logger.debug("realtime_emit_skipped", reason=str(exc))


# ---------------------------------------------------------------------------
# Background task — runs the router and stores the result
# ---------------------------------------------------------------------------


async def _run_router_and_store(
    run_id: str,
    case_id: str,
    seeded_state: InvestigationState,
    topology: str,
    tenant_id_str: str,
) -> None:
    """Execute the router topology against ``seeded_state`` and persist."""
    await _emit_event(
        run_id,
        tenant_id_str,
        {
            "kind": "started",
            "agent": "router",
            "summary": f"Router triage started (topology={topology})",
            "data": {"topology": topology, "case_id": case_id},
        },
    )
    try:
        final_state, info = await _router_orch.run(seeded_state, topology=topology)
        _triage_runs[run_id].update(
            {
                "status": "completed",
                "completed_at": datetime.utcnow().isoformat(),
                "topology": info.get("topology", topology),
                "signals": info.get("signals", []),
                "auto_closed": info.get("auto_closed", False),
                "wall_clock_ms": info.get("wall_clock_ms"),
                "router_run_id": info.get("run_id"),
                "verdict": final_state.verdict,
                "confidence": final_state.confidence,
                "confidence_basis": list(final_state.confidence_basis),
                "findings": list(final_state.findings),
                "mitre_mappings": list(final_state.mitre_mappings),
                "proposed_actions": [a.model_dump() if hasattr(a, "model_dump") else a for a in final_state.proposed_actions],
                "iteration_count": final_state.iteration_count,
                "state_status": final_state.status.value if hasattr(final_state.status, "value") else str(final_state.status),
                "error": None,
            }
        )
        await _emit_event(
            run_id,
            tenant_id_str,
            {
                "kind": "completed",
                "agent": "router",
                "summary": (
                    f"Router triage completed: verdict={final_state.verdict} "
                    f"confidence={final_state.confidence:.2f} signals={info.get('signals', [])}"
                ),
                "data": {
                    "topology": info.get("topology", topology),
                    "wall_clock_ms": info.get("wall_clock_ms"),
                    "signals": info.get("signals", []),
                    "auto_closed": info.get("auto_closed", False),
                },
            },
        )
        logger.info(
            "triage.completed",
            run_id=run_id,
            case_id=case_id,
            topology=info.get("topology", topology),
            signals=info.get("signals", []),
            wall_clock_ms=info.get("wall_clock_ms"),
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("triage.failed", run_id=run_id, case_id=case_id, error=str(exc))
        _triage_runs[run_id].update(
            {
                "status": "failed",
                "completed_at": datetime.utcnow().isoformat(),
                "error": str(exc),
            }
        )
        await _emit_event(
            run_id,
            tenant_id_str,
            {
                "kind": "error",
                "agent": "router",
                "summary": f"Router triage failed: {exc}",
                "data": {"status": "failed"},
            },
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("/cases/{case_id}/triage", response_model=TriageResponse)
async def launch_triage(
    case_id: str,
    body: TriageRequest,
    background_tasks: BackgroundTasks,
) -> TriageResponse:
    """Launch a router-topology triage run for ``case_id``.

    Returns immediately with the run identifier; poll
    ``GET /api/v1/triage/{run_id}`` for the final verdict / findings.
    """
    topology = _resolve_topology(body.topology)

    run_id = str(uuid4())
    tenant_uuid = _coerce_uuid(body.tenant_id, fallback=body.tenant_id or "default")
    incident_uuid = _coerce_uuid(body.incident_id, fallback=case_id)

    state = InvestigationState(
        incident_id=incident_uuid,
        tenant_id=tenant_uuid,
        alert_summary=body.alert_summary,
        raw_alert=dict(body.raw_alert or {}),
        status=AgentStatus.PENDING,
    )

    _triage_runs[run_id] = {
        "run_id": run_id,
        "case_id": case_id,
        "status": "running",
        "started_at": datetime.utcnow().isoformat(),
        "topology": topology,
        "tenant_id": body.tenant_id,
        "incident_id": str(incident_uuid),
    }

    background_tasks.add_task(
        _run_router_and_store,
        run_id,
        case_id,
        state,
        topology,
        body.tenant_id,
    )
    logger.info(
        "triage.launched",
        run_id=run_id,
        case_id=case_id,
        topology=topology,
    )
    return TriageResponse(
        run_id=run_id,
        case_id=case_id,
        status="running",
        message=f"Triage started. Poll GET /api/v1/triage/{run_id}",
        topology=topology,
    )


@router.get("/triage/{run_id}")
async def get_triage(
    run_id: str,
    tenant_id: str = "default",
) -> dict[str, Any]:
    """Return the current state of a router triage run.

    Tenant isolation is enforced at the query layer (project convention,
    see PRs #116–#128): the caller MUST pass the same ``tenant_id`` the
    run was launched with. Mismatched (or absent) tenant returns 404
    rather than 403 to avoid leaking the existence of run IDs across
    tenant boundaries.
    """
    run = _triage_runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Triage run not found")
    if str(run.get("tenant_id")) != tenant_id:
        # Same response shape as the not-found branch so a probing
        # caller can't distinguish "wrong tenant" from "no such run".
        raise HTTPException(status_code=404, detail="Triage run not found")
    return run
