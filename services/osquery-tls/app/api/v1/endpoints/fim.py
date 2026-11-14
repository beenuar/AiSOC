"""FIM (File Integrity Monitoring) API endpoints.

GET /api/v1/osquery/fim/events   – paginated FIM event log
GET /api/v1/osquery/fim/summary  – aggregate counts by action, path, tenant

Query params for /events:
  - tenant_id   (optional) – filter, intersected with the caller's scope
  - action      (optional) – filter by action (CREATED/DELETED/UPDATED/ATTRIBUTES_MODIFIED)
  - path_prefix (optional) – filter by target_path prefix (SQL LIKE)
  - hostname    (optional) – filter by hostname
  - since       (optional) – only events at or after this timestamp
  - limit       (default 100, max 1000)
  - offset      (default 0)

The tenant is resolved from the caller's credential by
``app/security/tenant_scope.py`` and a ``tenant_id`` parameter only ever
narrows within it. ``/summary`` used to resolve the scope correctly for its
total and then filter its two breakdowns on the raw, unresolved query
parameter — so the console, which sends the placeholder string ``"default"``,
got a correct total beside a by-action list and a top-paths list filtered on a
literal that matches only nodes enrolled with no tenant header. Not a leak
(``scoped_tenant_or_403`` had already refused anything out of scope) but two
numbers on the same card computed against two different tenants.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql import Select

from app.db.session import get_db
from app.models.fim_event import FimEvent
from app.security.tenant_scope import (
    TenantPrincipal,
    require_console_or_service_auth,
    scoped_tenant_or_403,
)

router = APIRouter(prefix="/fim", tags=["fim"])

#: The console reaches this service directly through a Next rewrite, so the
#: FIM and pack surfaces are internet-reachable. The tenant comes from the
#: caller's credential; a `tenant_id` on the request is a filter intersected
#: with it, never a selector.
ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]


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
    #: Distinct nodes that have reported a FIM event in the window. The console
    #: has always rendered this as an "Active Nodes" card and the response has
    #: never carried it, so the card called `.toLocaleString()` on `undefined`.
    active_nodes: int
    by_action: list[FimActionCount]
    top_paths: list[FimPathCount]  # top 10 most-changed paths


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


def _apply_since(query: Select, since: datetime | None) -> Select:
    """Narrow to events at or after ``since``.

    The console has always sent a `since` derived from its "Time window"
    selector and neither endpoint declared the parameter, so FastAPI dropped it
    and every window from "Last 1 hour" to "All time" returned the same rows.
    """
    return query.where(FimEvent.event_time >= since) if since is not None else query


@router.get("/events", response_model=FimEventPage)
async def list_fim_events(
    principal: ScopedPrincipal,
    tenant_id: Annotated[str | None, Query(description="Optional filter; intersected with the caller's scope")] = None,
    action: Annotated[str | None, Query()] = None,
    path_prefix: Annotated[str | None, Query(description="Filter by path prefix")] = None,
    hostname: Annotated[str | None, Query()] = None,
    since: Annotated[datetime | None, Query(description="Only events at or after this timestamp")] = None,
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: AsyncSession = Depends(get_db),
) -> FimEventPage:
    """Return a paginated list of FIM events for a tenant."""
    scoped = str(scoped_tenant_or_403(principal, tenant_id))
    base_query = select(FimEvent).where(FimEvent.tenant_id == scoped)

    if action:
        base_query = base_query.where(FimEvent.action == action.upper())
    if path_prefix:
        base_query = base_query.where(FimEvent.target_path.like(f"{path_prefix}%"))
    if hostname:
        base_query = base_query.where(FimEvent.hostname == hostname)
    base_query = _apply_since(base_query, since)

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
    principal: ScopedPrincipal,
    tenant_id: Annotated[str | None, Query(description="Optional filter; intersected with the caller's scope")] = None,
    since: Annotated[datetime | None, Query(description="Only events at or after this timestamp")] = None,
    db: AsyncSession = Depends(get_db),
) -> FimSummary:
    """Return aggregate FIM statistics for a tenant.

    Every query below filters on ``scoped`` — the tenant the credential
    resolved to — and never on the raw ``tenant_id`` parameter. Two of the
    three used to do the latter.
    """
    scoped = str(scoped_tenant_or_403(principal, tenant_id))

    # Total event count
    total = (await db.execute(_apply_since(select(func.count()).where(FimEvent.tenant_id == scoped), since))).scalar_one()

    # Nodes that have actually reported a FIM event in the window.
    active_nodes = (
        await db.execute(
            _apply_since(
                select(func.count(func.distinct(FimEvent.node_key))).where(FimEvent.tenant_id == scoped),
                since,
            )
        )
    ).scalar_one()

    # By-action breakdown
    action_rows = (
        await db.execute(
            _apply_since(
                select(FimEvent.action, func.count().label("cnt")).where(FimEvent.tenant_id == scoped),
                since,
            )
            .group_by(FimEvent.action)
            .order_by(func.count().desc())
        )
    ).all()
    by_action = [FimActionCount(action=r.action, count=r.cnt) for r in action_rows]

    # Top 10 most changed paths
    path_rows = (
        await db.execute(
            _apply_since(
                select(FimEvent.target_path, func.count().label("cnt")).where(FimEvent.tenant_id == scoped),
                since,
            )
            .group_by(FimEvent.target_path)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()
    top_paths = [FimPathCount(target_path=r.target_path, count=r.cnt) for r in path_rows]

    return FimSummary(
        tenant_id=scoped,
        total_events=total,
        active_nodes=active_nodes,
        by_action=by_action,
        top_paths=top_paths,
    )
