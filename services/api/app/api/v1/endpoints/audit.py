"""Audit log API endpoints.

GET /api/v1/audit        — paginated, filterable audit trail
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.audit import AuditLog

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEventOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    actor_id: uuid.UUID | None
    actor_email: str | None
    actor_ip: str | None
    action: str
    resource: str | None
    resource_id: str | None
    changes: dict | None
    created_at: str

    model_config = {"from_attributes": True}


class AuditListResponse(BaseModel):
    items: list[AuditEventOut]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("", response_model=AuditListResponse)
async def list_audit_events(
    current_user: Annotated[AuthUser, Depends(require_permission("audit_log:read"))],
    db: TenantDBSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    action: str | None = Query(default=None, description="Filter by action prefix, e.g. 'cases:'"),
    resource: str | None = Query(default=None),
    actor_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, description="Search actor_email or action"),
) -> AuditListResponse:
    """Return a paginated, tenant-scoped audit trail."""
    q = select(AuditLog).where(AuditLog.tenant_id == current_user.tenant_id)

    if action:
        q = q.where(AuditLog.action.like(f"{action}%"))
    if resource:
        q = q.where(AuditLog.resource == resource)
    if actor_id:
        q = q.where(AuditLog.actor_id == actor_id)
    if search:
        term = f"%{search}%"
        q = q.where(
            AuditLog.action.ilike(term) | AuditLog.actor_email.ilike(term)
        )

    count_q = select(func.count()).select_from(q.subquery())
    total_result = await db.execute(count_q)
    total: int = total_result.scalar_one()

    q = q.order_by(AuditLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(q)
    items = result.scalars().all()

    return AuditListResponse(
        items=[
            AuditEventOut(
                id=e.id,
                tenant_id=e.tenant_id,
                actor_id=e.actor_id,
                actor_email=e.actor_email,
                actor_ip=str(e.actor_ip) if e.actor_ip else None,
                action=e.action,
                resource=e.resource,
                resource_id=e.resource_id,
                changes=e.changes,
                created_at=e.created_at.isoformat(),
            )
            for e in items
        ],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=max(1, -(-total // page_size)),
    )
