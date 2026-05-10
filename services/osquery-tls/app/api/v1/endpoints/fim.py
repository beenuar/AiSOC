"""FIM (File Integrity Monitoring) API endpoints.

GET /api/v1/osquery/fim/events   – paginated FIM event log
GET /api/v1/osquery/fim/summary  – aggregate counts by action, path, tenant

Query params for /events:
  - tenant_id   (required) – scope to a specific tenant
  - action      (optional) – filter by action (CREATED/DELETED/UPDATED/ATTRIBUTES_MODIFIED)
  - path_prefix (optional) – filter by target_path prefix (SQL LIKE)
  - hostname    (optional) – filter by hostname
  - limit       (default 100, max 1000)
  - offset      (default 0)
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.models.fim_event import FimEvent

router = APIRouter(prefix="/fim", tags=["fim"])


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class FimEventOut(BaseModel):
    id: int
    tenant_id: str
    node_key: str
    hostname: str | None
    target_path: str
    action: str
    md5: str | None
    sha256: str | None
    pid: int | None
    ppid: int | None
    process_name: str | None
    username: str | None
    event_time: datetime
    ingested_at: datetime

    model_config = {"from_attributes": True}


class FimEventPage(BaseModel):
    total: int
    offset: int
    limit: int
    items: list[FimEventOut]


class FimActionCount(BaseModel):
    action: str
    count: int


class FimPathCount(BaseModel):
    target_path: str
    count: int


class FimSummary(BaseModel):
    tenant_id: str
    total_events: int
    by_action: list[FimActionCount]
    top_paths: list[FimPathCount]  # top 10 most-changed paths


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/events", response_model=FimEventPage)
async def list_fim_events(
    tenant_id: Annotated[str, Query(description="Tenant to scope results to")],
    action: Annotated[str | None, Query()] = None,
    path_prefix: Annotated[str | None, Query(description="Filter by path prefix")] = None,
    hostname: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: AsyncSession = Depends(get_db),
) -> FimEventPage:
    """Return a paginated list of FIM events for a tenant."""
    base_query = select(FimEvent).where(FimEvent.tenant_id == tenant_id)

    if action:
        base_query = base_query.where(FimEvent.action == action.upper())
    if path_prefix:
        base_query = base_query.where(FimEvent.target_path.like(f"{path_prefix}%"))
    if hostname:
        base_query = base_query.where(FimEvent.hostname == hostname)

    # Count
    count_q = select(func.count()).select_from(base_query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    # Page
    rows_q = base_query.order_by(FimEvent.event_time.desc()).offset(offset).limit(limit)
    rows = (await db.execute(rows_q)).scalars().all()

    return FimEventPage(
        total=total,
        offset=offset,
        limit=limit,
        items=[FimEventOut.model_validate(r) for r in rows],
    )


@router.get("/summary", response_model=FimSummary)
async def fim_summary(
    tenant_id: Annotated[str, Query(description="Tenant to summarise")],
    db: AsyncSession = Depends(get_db),
) -> FimSummary:
    """Return aggregate FIM statistics for a tenant."""
    # Total event count
    total = (await db.execute(select(func.count()).where(FimEvent.tenant_id == tenant_id))).scalar_one()

    # By-action breakdown
    action_rows = (
        await db.execute(
            select(FimEvent.action, func.count().label("cnt"))
            .where(FimEvent.tenant_id == tenant_id)
            .group_by(FimEvent.action)
            .order_by(func.count().desc())
        )
    ).all()
    by_action = [FimActionCount(action=r.action, count=r.cnt) for r in action_rows]

    # Top 10 most changed paths
    path_rows = (
        await db.execute(
            select(FimEvent.target_path, func.count().label("cnt"))
            .where(FimEvent.tenant_id == tenant_id)
            .group_by(FimEvent.target_path)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()
    top_paths = [FimPathCount(target_path=r.target_path, count=r.cnt) for r in path_rows]

    return FimSummary(
        tenant_id=tenant_id,
        total_events=total,
        by_action=by_action,
        top_paths=top_paths,
    )
