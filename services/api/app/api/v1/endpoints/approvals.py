"""Agent approval endpoints for the mobile responder PWA.

Whenever an agent wants to take a high-risk action (isolate host,
disable user, run a destructive playbook step), it stops and emits an
approval request that lands here. The PWA polls and subscribes to push
notifications so the on-call analyst can approve or deny in one tap,
even from a phone.

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

    await db.commit()
    await db.refresh(row)

    # Notify the agents service (and any other listener) so the run can
    # resume — fire-and-forget pattern matches the rest of the surface.
    await _notify_realtime(row, event="approval_decided")

    return ApprovalResponse.model_validate(row)


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
