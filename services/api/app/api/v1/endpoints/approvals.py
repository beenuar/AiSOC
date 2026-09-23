"""Agent approval endpoints for the mobile responder PWA.

Whenever an agent wants to take a high-risk action (isolate host,
disable user, run a destructive playbook step), it stops and emits an
approval request that lands here. The PWA polls and subscribes to push
notifications so the on-call analyst can approve or deny in one tap,
even from a phone.

That was the design, and for both of its halves it was only the design.
Nothing in the repository called ``POST /approvals``, so the queue had no
producer and the responder app's approvals screen was structurally empty; and
``decide`` flipped a row and notified the realtime service without ever
reaching ``services/actions``, so the queue had no executor either. Tapping
Approve recorded a decision and ran nothing, which is worse than a missing
feature: the operator is told the host was contained.

Both halves are closed in v9.0. ``services/agents`` posts here when triage
proposes an action that needs sign-off, and ``decide`` carries the decision
through to the actions service and records on the row whether it executed.

Endpoints
---------
* ``GET    /approvals``           List pending/decided approvals.
* ``GET    /approvals/{id}``      Approval detail (with action payload).
* ``POST   /approvals``           Create one (called by the agent service).
* ``POST   /approvals/{id}/decide`` Approve or deny.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select

from app.api.v1.deps import AuthUser, require_permission
from app.core.config import settings
from app.db.rls import TenantDBSession
from app.models.responder import AgentApproval
from app.services.actions_client import ActionsServiceError, decide_action, submit_action

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/approvals", tags=["responder", "approvals"])

_HTTP_TIMEOUT = 5.0
_VALID_STATUSES = {"pending", "approved", "denied", "expired"}


class ApprovalResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    run_id: uuid.UUID | None
    case_id: str | None
    alert_id: uuid.UUID | None
    requested_by: str
    required_user_id: uuid.UUID | None
    required_topic: str | None
    title: str
    summary: str
    risk_level: str
    action: dict
    status: str
    decided_by_id: uuid.UUID | None
    decided_at: datetime | None
    decision_comment: str | None
    expires_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ApprovalListResponse(BaseModel):
    items: list[ApprovalResponse]
    total: int
    page: int
    page_size: int
    pages: int


class ApprovalCreateRequest(BaseModel):
    run_id: uuid.UUID | None = None
    case_id: str | None = Field(default=None, max_length=200)
    alert_id: uuid.UUID | None = None
    requested_by: str = Field(default="agent", max_length=120)
    required_user_id: uuid.UUID | None = None
    required_topic: str | None = Field(default=None, max_length=80)
    title: str = Field(min_length=1, max_length=200)
    summary: str = Field(min_length=1)
    risk_level: Literal["low", "medium", "high", "critical"] = "medium"
    action: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["approve", "deny"]
    comment: str | None = Field(default=None, max_length=2000)


@router.get("", response_model=ApprovalListResponse)
async def list_approvals(
    user: AuthUser,
    db: TenantDBSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    status_filter: str | None = Query(default="pending", alias="status"),
    mine: bool = Query(default=False),
    risk_level: str | None = Query(default=None),
) -> ApprovalListResponse:
    """List approvals for the current tenant.

    Defaults to ``status=pending`` so the PWA inbox view is fast.
    Set ``mine=true`` to only show approvals routed specifically to the
    current user.
    """
    filters = [AgentApproval.tenant_id == user.tenant_id]
    if status_filter:
        if status_filter not in _VALID_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of {_VALID_STATUSES}",
            )
        filters.append(AgentApproval.status == status_filter)
    if mine:
        filters.append(AgentApproval.required_user_id == user.user_id)
    if risk_level:
        filters.append(AgentApproval.risk_level == risk_level)

    count_stmt = select(func.count()).select_from(AgentApproval).where(and_(*filters))
    total = (await db.execute(count_stmt)).scalar_one()

    stmt = (
        select(AgentApproval)
        .where(and_(*filters))
        .order_by(AgentApproval.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(stmt)).scalars().all()

    return ApprovalListResponse(
        items=[ApprovalResponse.model_validate(row) for row in rows],
        total=int(total),
        page=page,
        page_size=page_size,
        pages=max(1, (int(total) + page_size - 1) // page_size),
    )


@router.get("/{approval_id}", response_model=ApprovalResponse)
async def get_approval(
    approval_id: uuid.UUID,
    user: AuthUser,
    db: TenantDBSession,
) -> ApprovalResponse:
    row = (
        await db.execute(
            select(AgentApproval).where(
                AgentApproval.id == approval_id,
                AgentApproval.tenant_id == user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")
    return ApprovalResponse.model_validate(row)


@router.post("", response_model=ApprovalResponse, status_code=status.HTTP_201_CREATED)
async def create_approval(
    body: ApprovalCreateRequest,
    user: Annotated[AuthUser, Depends(require_permission("cases:write"))],
    db: TenantDBSession,
) -> ApprovalResponse:
    """Create a new approval request.

    The agents service calls this when it hits a high-risk step that
    requires human sign-off. We persist it, then fan-out a Web Push
    notification via the realtime service so the PWA buzzes the right
    on-call analyst.
    """
    row = AgentApproval(
        tenant_id=user.tenant_id,
        run_id=body.run_id,
        case_id=body.case_id,
        alert_id=body.alert_id,
        requested_by=body.requested_by,
        required_user_id=body.required_user_id,
        required_topic=body.required_topic,
        title=body.title,
        summary=body.summary,
        risk_level=body.risk_level,
        action=body.action,
        expires_at=body.expires_at,
        status="pending",
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    # Best-effort push notification — failure must not block the agent run.
    await _notify_realtime(row, event="approval_request")

    return ApprovalResponse.model_validate(row)


@router.post("/{approval_id}/decide", response_model=ApprovalResponse)
async def decide_approval(
    approval_id: uuid.UUID,
    body: ApprovalDecisionRequest,
    user: Annotated[AuthUser, Depends(require_permission("cases:write"))],
    db: TenantDBSession,
) -> ApprovalResponse:
    """Approve or deny a pending approval.

    Idempotent only on the same decision: re-approving an already
    approved request returns the row unchanged; trying to flip an
    approved row to denied (or vice versa) is a 409.
    """
    row = (
        await db.execute(
            select(AgentApproval).where(
                AgentApproval.id == approval_id,
                AgentApproval.tenant_id == user.tenant_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approval not found")

    new_status = "approved" if body.decision == "approve" else "denied"

    if row.status == new_status:
        return ApprovalResponse.model_validate(row)
    if row.status not in {"pending", "expired"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Approval already {row.status}; cannot change to {new_status}",
        )

    row.status = new_status
    row.decided_by_id = user.user_id
    row.decided_at = datetime.now(UTC)
    row.decision_comment = body.comment

    # Dispatch before committing the decision, so an approval that the actions
    # service refuses does not leave a row reading "approved" against an
    # action that never ran. This endpoint used to flip the row and stop:
    # every tap of Approve in the responder app recorded a decision and
    # executed nothing, which is the most dangerous shape a security control
    # can have — it reports that the host was contained.
    dispatch = await _dispatch_decision(row, user, approve=body.decision == "approve")
    row.action = {**(row.action or {}), "dispatch": dispatch}

    await db.commit()
    await db.refresh(row)

    # Notify the agents service (and any other listener) so the run can
    # resume — fire-and-forget pattern matches the rest of the surface.
    await _notify_realtime(row, event="approval_decided")

    if dispatch.get("state") == "failed":
        # The decision is durable and the operator is told the truth: their
        # choice was recorded, the execution behind it was not accepted.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"Decision recorded, but the action service refused it: {dispatch.get('detail')}. "
                "The approval row reflects your decision; the action did not run."
            ),
        )

    return ApprovalResponse.model_validate(row)


async def _dispatch_decision(
    row: AgentApproval,
    user: AuthUser,
    *,
    approve: bool,
) -> dict[str, Any]:
    """Carry a decision through to ``services/actions``.

    Returns a provenance record that is stored on the approval, so "was this
    actually executed" is answerable from the row rather than by correlating
    two services' logs. The four states are deliberately distinct:

    ``not_executable``  the approval names no action type, so there is
                        nothing to run. Common and fine: an approval can
                        gate a human step.
    ``declined``        the decision was to deny; the action was rejected
                        upstream so it cannot later be approved by replay.
    ``executed``        the actions service accepted and ran it.
    ``failed``          the actions service refused or was unreachable.
    """
    action = row.action or {}
    action_type = action.get("action_type") or action.get("type")
    target = action.get("target")
    if not isinstance(action_type, str) or not action_type.strip():
        return {"state": "not_executable", "reason": "approval carries no action_type"}
    if not isinstance(target, str) or not target.strip():
        return {"state": "not_executable", "reason": "approval carries no target"}

    # The approval id is reused as the action id so the two systems share one
    # identifier. Without that, "which action did this approval authorise"
    # requires a join nobody wrote.
    action_id = str(row.id)
    principal = {
        "user_id": str(user.user_id),
        "email": getattr(user, "email", None),
        "roles": list(getattr(user, "roles", []) or []),
        "permissions": list(getattr(user, "permissions", []) or []),
    }

    try:
        await submit_action(
            action_id=action_id,
            action_type=action_type.strip(),
            target=target.strip(),
            tenant_id=str(row.tenant_id),
            incident_id=str(row.run_id or row.id),
            rationale=row.summary or row.title,
            parameters=action.get("parameters") or {},
            # The requester is the agent, not the approver. Sending the
            # approver here would make them both, and separation of duties
            # would pass by accident.
            requested_by=row.requested_by or "agent",
        )
    except ActionsServiceError as exc:
        logger.warning(
            "Approval dispatch: submit refused",
            extra={"approval_id": action_id, "status": exc.status_code, "detail": str(exc)},
        )
        return {"state": "failed", "stage": "submit", "detail": str(exc)}

    try:
        result = await decide_action(action_id=action_id, approve=approve, approver=principal)
    except ActionsServiceError as exc:
        logger.warning(
            "Approval dispatch: decision refused",
            extra={"approval_id": action_id, "status": exc.status_code, "detail": str(exc)},
        )
        return {"state": "failed", "stage": "decide", "detail": str(exc)}

    return {
        "state": "executed" if approve else "declined",
        "action_id": action_id,
        "action_status": result.get("status"),
        "blast_radius": result.get("blast_radius"),
    }


async def _notify_realtime(row: AgentApproval, *, event: str) -> None:
    """Fan out an agent event to the realtime service.

    Both the websocket layer (for desktop) and the Web Push layer (for
    mobile) listen on this internal endpoint. We translate the SQL row
    into the existing ``agent.event`` shape so we don't have to teach
    the realtime service a new contract.
    """
    base = settings.REALTIME_BASE_URL.rstrip("/") if settings.REALTIME_BASE_URL else None
    if not base:
        return

    headers: dict[str, str] = {"Accept": "application/json"}
    if settings.REALTIME_INTERNAL_TOKEN:
        # Match the lower-cased header the realtime service checks.
        headers["x-internal-token"] = settings.REALTIME_INTERNAL_TOKEN

    payload: dict[str, Any] = {
        "tenant_id": str(row.tenant_id),
        "run_id": str(row.run_id) if row.run_id else str(row.id),
        "kind": "APPROVAL_REQUEST" if event == "approval_request" else "APPROVAL_DECISION",
        "agent": row.requested_by or "agent",
        "summary": row.title,
        "data": {
            "approval_id": str(row.id),
            "case_id": row.case_id,
            "alert_id": str(row.alert_id) if row.alert_id else None,
            "risk_level": row.risk_level,
            "status": row.status,
            "decision_comment": row.decision_comment,
            "notify_user_ids": ([str(row.required_user_id)] if row.required_user_id else None),
        },
    }

    url = f"{base}/internal/agent-event"
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            await client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        # The approval has already been persisted; failing to notify is
        # a degraded experience, not a data loss event.
        logger.warning(
            "Failed to fan-out approval event to realtime: %s",
            exc,
            extra={"approval_id": str(row.id), "event": event},
        )
