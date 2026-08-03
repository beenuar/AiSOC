"""
Agent service REST API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel

from app.graph.runner import run_full_investigation
from app.models.state import AgentTask, InvestigationState

router = APIRouter()

# In-memory run store for status polling. The durable record of every step is
# the Postgres Investigation Ledger (written by the shared graph runner) — this
# dict is only the fast local status cache for GET /investigations/{run_id}.
_runs: dict[str, dict] = {}


class InvestigationRequest(BaseModel):
    incident_id: UUID
    tenant_id: UUID
    alert_summary: str
    raw_alert: dict[str, Any] = {}
    task: AgentTask = AgentTask.INVESTIGATION


class InvestigationResponse(BaseModel):
    run_id: UUID
    status: str
    message: str


async def _run_investigation(run_id: str, state: InvestigationState) -> None:
    """Run investigation in background and store results.

    Uses the SAME durable graph runner as the Kafka auto-triage worker
    (issue #569), so manual and automated investigations share one
    orchestration implementation and both persist every step to the ledger.
    """
    try:
        result = await run_full_investigation(state)
        _runs[run_id] = {
            "status": "completed",
            "result": result.to_dict(),
            "completed_at": datetime.utcnow().isoformat(),
        }
    except Exception as exc:  # noqa: BLE001 — surface failure via the status cache
        _runs[run_id] = {"status": "failed", "error": str(exc)}


@router.post("/investigations", response_model=InvestigationResponse)
async def start_investigation(
    request: InvestigationRequest,
    background_tasks: BackgroundTasks,
):
    """Start a new automated investigation for an incident."""
    run_id = str(uuid4())
    state = InvestigationState(
        run_id=UUID(run_id),
        incident_id=request.incident_id,
        tenant_id=request.tenant_id,
        task=request.task,
        alert_summary=request.alert_summary,
        raw_alert=request.raw_alert,
    )
    _runs[run_id] = {"status": "running", "started_at": datetime.utcnow().isoformat()}
    background_tasks.add_task(_run_investigation, run_id, state)

    return InvestigationResponse(
        run_id=UUID(run_id),
        status="running",
        message="Investigation started",
    )


@router.get("/investigations/{run_id}")
async def get_investigation(run_id: str):
    """Get the status and results of an investigation run."""
    run = _runs.get(run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Investigation run not found")
    return run


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-agents"}
