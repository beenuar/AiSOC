"""Alert management endpoints."""
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.db.rls import TenantDBSession
from app.models.alert import Alert

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    description: str | None
    severity: str
    status: str
    priority: int
    category: str | None
    mitre_tactics: list
    mitre_techniques: list
    connector_type: str | None
    ai_score: float | None
    ai_summary: str | None
    ai_recommendations: list
    affected_ips: list
    affected_hosts: list
    affected_users: list
    case_id: uuid.UUID | None
    tags: list
    event_time: datetime
    first_seen: datetime
    last_seen: datetime
    snoozed_until: datetime | None = None
    snoozed_by_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertSnoozeRequest(BaseModel):
    """Snooze an alert from the mobile responder PWA."""

    duration_minutes: int | None = None
    until: datetime | None = None
    reason: str | None = None


class AlertListResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    page: int
    page_size: int
    pages: int


class AlertUpdateRequest(BaseModel):
    status: str | None = None
    priority: int | None = None
    tags: list[str] | None = None
    assigned_to_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None


class AlertStatsResponse(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    new_last_24h: int
    critical_open: int


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    category: str | None = Query(default=None),
    assigned_to_me: bool = Query(default=False),
    search: str | None = Query(default=None),
) -> AlertListResponse:
    """List alerts for the current tenant with filtering and pagination."""
    filters = [Alert.tenant_id == current_user.tenant_id]

    if severity:
        filters.append(Alert.severity == severity)
    if status:
        filters.append(Alert.status == status)
    if category:
        filters.append(Alert.category == category)
    if assigned_to_me:
        filters.append(Alert.assigned_to_id == current_user.user_id)

    # Count
    count_result = await db.execute(
        select(func.count()).select_from(Alert).where(and_(*filters))
    )
    total = count_result.scalar_one()

    # Fetch
    offset = (page - 1) * page_size
    result = await db.execute(
        select(Alert)
        .where(and_(*filters))
        .order_by(Alert.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    alerts = result.scalars().all()

    return AlertListResponse(
        items=[AlertResponse.model_validate(a) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/stats", response_model=AlertStatsResponse)
async def get_alert_stats(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> AlertStatsResponse:
    """Get alert statistics for the dashboard."""
    from datetime import timedelta

    from sqlalchemy import case as sa_case

    tenant_filter = Alert.tenant_id == current_user.tenant_id

    # Total count
    total_result = await db.execute(select(func.count()).select_from(Alert).where(tenant_filter))
    total = total_result.scalar_one()

    # By severity
    sev_result = await db.execute(
        select(Alert.severity, func.count()).where(tenant_filter).group_by(Alert.severity)
    )
    by_severity = {row[0]: row[1] for row in sev_result.all()}

    # By status
    status_result = await db.execute(
        select(Alert.status, func.count()).where(tenant_filter).group_by(Alert.status)
    )
    by_status = {row[0]: row[1] for row in status_result.all()}

    # New last 24h
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    new_24h_result = await db.execute(
        select(func.count()).select_from(Alert).where(
            and_(tenant_filter, Alert.created_at >= cutoff)
        )
    )
    new_last_24h = new_24h_result.scalar_one()

    # Critical open
    crit_result = await db.execute(
        select(func.count()).select_from(Alert).where(
            and_(tenant_filter, Alert.severity == "critical", Alert.status.in_(["new", "triaging", "in_progress"]))
        )
    )
    critical_open = crit_result.scalar_one()

    return AlertStatsResponse(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        new_last_24h=new_last_24h,
        critical_open=critical_open,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> AlertResponse:
    """Get a single alert by ID."""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id)
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return AlertResponse.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: uuid.UUID,
    request: AlertUpdateRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: DBSession,
) -> AlertResponse:
    """Update alert status, priority, tags, assignment, or case link."""
    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id)
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    updates: dict = {}
    if request.status is not None:
        updates["status"] = request.status
        if request.status in ("resolved", "false_positive", "closed"):
            updates["resolved_at"] = datetime.now(UTC)
    if request.priority is not None:
        updates["priority"] = request.priority
    if request.tags is not None:
        updates["tags"] = request.tags
    if request.assigned_to_id is not None:
        updates["assigned_to_id"] = request.assigned_to_id
        updates["assigned_at"] = datetime.now(UTC)
    if request.case_id is not None:
        updates["case_id"] = request.case_id

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        await db.execute(update(Alert).where(Alert.id == alert_id).values(**updates))
        await db.commit()
        await db.refresh(alert)

    return AlertResponse.model_validate(alert)


@router.post("/{alert_id}/escalate", response_model=AlertResponse)
async def escalate_alert(
    alert_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: DBSession,
) -> AlertResponse:
    """Escalate an alert (raises severity by one level)."""
    severity_ladder = ["info", "low", "medium", "high", "critical"]

    result = await db.execute(
        select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id)
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    current_idx = severity_ladder.index(alert.severity) if alert.severity in severity_ladder else 2
    new_severity = severity_ladder[min(current_idx + 1, len(severity_ladder) - 1)]

    await db.execute(
        update(Alert).where(Alert.id == alert_id).values(
            severity=new_severity, updated_at=datetime.now(UTC)
        )
    )
    await db.commit()
    await db.refresh(alert)

    return AlertResponse.model_validate(alert)


@router.post("/{alert_id}/snooze", response_model=AlertResponse)
async def snooze_alert(
    alert_id: uuid.UUID,
    body: AlertSnoozeRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: TenantDBSession,
) -> AlertResponse:
    """Defer an alert for a fixed window from the mobile responder PWA.

    Either ``duration_minutes`` or ``until`` must be supplied. The alert
    re-surfaces in the queue once ``snoozed_until`` is in the past.
    """
    from datetime import timedelta

    if body.duration_minutes is None and body.until is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either duration_minutes or until must be provided",
        )

    if body.until is not None:
        snoozed_until = body.until.astimezone(UTC) if body.until.tzinfo else body.until.replace(tzinfo=UTC)
    else:
        if (body.duration_minutes or 0) <= 0 or (body.duration_minutes or 0) > 60 * 24 * 30:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="duration_minutes must be between 1 and 43200 (30 days)",
            )
        snoozed_until = datetime.now(UTC) + timedelta(minutes=body.duration_minutes or 0)

    result = await db.execute(
        select(Alert).where(
            Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id
        )
    )
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found"
        )

    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(
            snoozed_until=snoozed_until,
            snoozed_by_id=current_user.user_id,
            updated_at=datetime.now(UTC),
        )
    )
    await db.commit()
    await db.refresh(alert)

    return AlertResponse.model_validate(alert)
