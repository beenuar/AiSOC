"""
Action Execution Service REST API.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, HTTPException

from app.models.action import ActionRequest, ActionResult, ActionStatus, ActionType
from app.services.blast_radius import BlastRadiusGate
from app.services.executor_registry import EXECUTOR_REGISTRY

logger = structlog.get_logger()
router = APIRouter()
gate = BlastRadiusGate()

# In-memory action store (replace with DB in production)
_actions: dict[str, dict[str, Any]] = {}


@router.post("/actions", response_model=dict)
async def submit_action(request: ActionRequest):
    """Submit an action for execution (may require approval)."""
    status, blast_radius, reason = gate.evaluate(request)

    record = {
        "id": str(request.id),
        "action_type": request.action_type,
        "target": request.target,
        "status": status,
        "blast_radius": blast_radius,
        "gate_reason": reason,
        "incident_id": str(request.incident_id),
        "tenant_id": str(request.tenant_id),
        "rationale": request.rationale,
    }
    _actions[str(request.id)] = record

    # Auto-execute if approved
    if status == ActionStatus.APPROVED:
        executor = EXECUTOR_REGISTRY.get(request.action_type)
        if executor:
            try:
                result = await executor.execute(request)
                record["status"] = result.status
                record["output"] = result.output
                record["rollback_data"] = result.rollback_data
                if result.error:
                    record["error"] = result.error
            except Exception as exc:
                logger.error("Action execution failed", error=str(exc))
                record["status"] = ActionStatus.FAILED
                record["error"] = str(exc)
        else:
            record["status"] = ActionStatus.FAILED
            record["error"] = f"No executor found for action type: {request.action_type}"

    logger.info(
        "Action submitted",
        action_id=str(request.id),
        action_type=request.action_type,
        status=record["status"],
        blast_radius=blast_radius,
    )
    return record


@router.post("/actions/{action_id}/approve")
async def approve_action(action_id: str):
    """Approve a pending action (human-in-the-loop gate)."""
    record = _actions.get(action_id)
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    if record["status"] != ActionStatus.AWAITING_APPROVAL:
        raise HTTPException(status_code=400, detail=f"Action is not awaiting approval (current: {record['status']})")

    # Reconstruct request and execute
    request = ActionRequest(
        id=UUID(action_id),
        incident_id=UUID(record["incident_id"]),
        tenant_id=UUID(record["tenant_id"]),
        action_type=ActionType(record["action_type"]),
        target=record["target"],
        rationale=record["rationale"],
    )

    executor = EXECUTOR_REGISTRY.get(request.action_type)
    if executor:
        result = await executor.execute(request)
        record["status"] = result.status
        record["output"] = result.output
    else:
        record["status"] = ActionStatus.FAILED
        record["error"] = "No executor available"

    logger.info("Action approved and executed", action_id=action_id, status=record["status"])
    return record


@router.post("/actions/{action_id}/reject")
async def reject_action(action_id: str):
    """Reject a pending action."""
    record = _actions.get(action_id)
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    record["status"] = ActionStatus.REJECTED
    logger.info("Action rejected", action_id=action_id)
    return record


@router.get("/actions/{action_id}")
async def get_action(action_id: str):
    """Get action status and result."""
    record = _actions.get(action_id)
    if not record:
        raise HTTPException(status_code=404, detail="Action not found")
    return record


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-actions"}
