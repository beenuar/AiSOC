"""Audit log API endpoints.

GET /api/v1/audit               — paginated, filterable audit trail
GET /api/v1/audit/export        — full export of the (filtered) trail as CSV or HTML
"""

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.audit import AuditLog
from app.services.audit_export import (
    AuditRow,
    ExportContext,
    render_audit_csv,
    render_audit_html,
)

router = APIRouter(prefix="/audit", tags=["audit"])

# Hard cap on a single export request — keeps memory + browser-side
# rendering predictable and forces operators to narrow filters for very
# long-running tenants. The real audit trail is never truncated server-side.
_EXPORT_MAX_ROWS = 10_000


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


def _filtered_audit_query(
    *,
    tenant_id: uuid.UUID,
    action: str | None,
    resource: str | None,
    actor_id: uuid.UUID | None,
    search: str | None,
):
    """Build the base SQLAlchemy query for audit reads.

    Pulled out so the list and export endpoints share identical filtering
    semantics — the exported CSV/HTML is always exactly what the analyst
    sees in the UI.
    """
    q = select(AuditLog).where(AuditLog.tenant_id == tenant_id)
    if action:
        q = q.where(AuditLog.action.like(f"{action}%"))
    if resource:
        q = q.where(AuditLog.resource == resource)
    if actor_id:
        q = q.where(AuditLog.actor_id == actor_id)
    if search:
        term = f"%{search}%"
        q = q.where(AuditLog.action.ilike(term) | AuditLog.actor_email.ilike(term))
    return q


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
    q = _filtered_audit_query(
        tenant_id=current_user.tenant_id,
        action=action,
        resource=resource,
        actor_id=actor_id,
        search=search,
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


@router.get(
    "/export",
    summary="Export the (filtered) audit trail as CSV or print-ready HTML",
    response_model=None,
)
async def export_audit_events(
    current_user: Annotated[AuthUser, Depends(require_permission("audit_log:read"))],
    db: TenantDBSession,
    fmt: str = Query(default="csv", alias="format", pattern="^(csv|html)$"),
    action: str | None = Query(default=None, description="Filter by action prefix, e.g. 'cases:'"),
    resource: str | None = Query(default=None),
    actor_id: uuid.UUID | None = Query(default=None),
    search: str | None = Query(default=None, description="Search actor_email or action"),
    limit: int = Query(default=_EXPORT_MAX_ROWS, ge=1, le=_EXPORT_MAX_ROWS),
) -> PlainTextResponse | HTMLResponse:
    """Return the filtered audit trail as a downloadable artefact.

    * ``format=csv`` (default) — RFC 4180 CSV, suitable for SIEM ingest
      and compliance binders.
    * ``format=html`` — self-contained HTML the browser can save to PDF.

    The same filters as ``GET /audit`` apply, so the exported bundle
    matches what the analyst is looking at in the UI. A hard ``limit``
    of 10 000 rows keeps a single export bounded — narrow the filters
    for very long-running tenants.
    """
    q = _filtered_audit_query(
        tenant_id=current_user.tenant_id,
        action=action,
        resource=resource,
        actor_id=actor_id,
        search=search,
    )
    q = q.order_by(AuditLog.created_at.desc()).limit(limit)

    result = await db.execute(q)
    events = result.scalars().all()

    rows = [
        AuditRow(
            id=str(e.id),
            tenant_id=str(e.tenant_id),
            actor_id=str(e.actor_id) if e.actor_id else None,
            actor_email=e.actor_email,
            actor_ip=str(e.actor_ip) if e.actor_ip else None,
            action=e.action,
            resource=e.resource,
            resource_id=e.resource_id,
            changes=e.changes,
            created_at=e.created_at,
        )
        for e in events
    ]

    generated_at = datetime.now(UTC)
    timestamp_slug = generated_at.strftime("%Y%m%dT%H%M%SZ")

    if fmt == "csv":
        body = render_audit_csv(rows)
        return PlainTextResponse(
            content=body,
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": (f'attachment; filename="aisoc-audit-{timestamp_slug}.csv"'),
                "X-Total-Rows": str(len(rows)),
            },
        )

    context = ExportContext(
        tenant_id=str(current_user.tenant_id),
        generated_at=generated_at,
        generated_by_email=current_user.email,
        filters={
            "action": action,
            "resource": resource,
            "actor_id": str(actor_id) if actor_id else None,
            "search": search,
        },
        total_rows=len(rows),
    )
    html_body = render_audit_html(rows, context)
    return HTMLResponse(
        content=html_body,
        headers={
            "Content-Disposition": (f'inline; filename="aisoc-audit-{timestamp_slug}.html"'),
            "X-Total-Rows": str(len(rows)),
        },
    )
