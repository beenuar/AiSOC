"""Case management endpoints."""
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.case import Case, CaseTask, CaseTimeline

router = APIRouter(prefix="/cases", tags=["cases"])


class CaseResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    case_number: str
    title: str
    description: str | None
    status: str
    priority: str
    severity: str
    case_type: str
    mitre_tactics: list
    mitre_techniques: list
    assigned_to_id: uuid.UUID | None
    sla_deadline: datetime | None
    sla_breached: bool
    alert_ids: list
    tags: list
    ticket_refs: list
    summary: str | None
    resolution: str | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CaseListResponse(BaseModel):
    items: list[CaseResponse]
    total: int
    page: int
    page_size: int
    pages: int


class CreateCaseRequest(BaseModel):
    title: str
    description: str | None = None
    priority: str = "medium"
    severity: str = "medium"
    case_type: str = "security_incident"
    alert_ids: list[uuid.UUID] = []
    tags: list[str] = []


class UpdateCaseRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    priority: str | None = None
    severity: str | None = None
    assigned_to_id: uuid.UUID | None = None
    tags: list[str] | None = None
    resolution: str | None = None
    lessons_learned: str | None = None


class AddTimelineEventRequest(BaseModel):
    content: str
    event_type: str = "comment"
    metadata: dict = {}


class TimelineEventResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    event_type: str
    content: str
    metadata: dict = Field(default_factory=dict, validation_alias="event_metadata")
    user_id: uuid.UUID | None
    is_automated: bool
    created_at: datetime

    model_config = {"from_attributes": True, "populate_by_name": True}


def _generate_case_number(tenant_id: uuid.UUID) -> str:
    """Generate a human-readable case number."""
    ts = int(datetime.now(UTC).timestamp())
    prefix = str(tenant_id)[:4].upper()
    return f"CASE-{prefix}-{ts % 1000000:06d}"


@router.get("", response_model=CaseListResponse)
async def list_cases(
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: DBSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    status: str | None = None,
    priority: str | None = None,
    assigned_to_me: bool = False,
) -> CaseListResponse:
    """List cases with filtering."""
    filters = [Case.tenant_id == current_user.tenant_id]
    if status:
        filters.append(Case.status == status)
    if priority:
        filters.append(Case.priority == priority)
    if assigned_to_me:
        filters.append(Case.assigned_to_id == current_user.user_id)

    count_result = await db.execute(
        select(func.count()).select_from(Case).where(and_(*filters))
    )
    total = count_result.scalar_one()

    offset = (page - 1) * page_size
    result = await db.execute(
        select(Case).where(and_(*filters)).order_by(Case.created_at.desc()).offset(offset).limit(page_size)
    )
    cases = result.scalars().all()

    return CaseListResponse(
        items=[CaseResponse.model_validate(c) for c in cases],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    request: CreateCaseRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:write"))],
    db: DBSession,
) -> CaseResponse:
    """Create a new security case."""
    case = Case(
        tenant_id=current_user.tenant_id,
        case_number=_generate_case_number(current_user.tenant_id),
        title=request.title,
        description=request.description,
        priority=request.priority,
        severity=request.severity,
        case_type=request.case_type,
        alert_ids=[str(aid) for aid in request.alert_ids],
        tags=request.tags,
        created_by_id=current_user.user_id,
    )
    db.add(case)
    await db.flush()

    # Add creation timeline event
    timeline_event = CaseTimeline(
        case_id=case.id,
        tenant_id=current_user.tenant_id,
        event_type="case_created",
        content=f"Case created by {current_user.email}",
        user_id=current_user.user_id,
    )
    db.add(timeline_event)
    await db.commit()
    await db.refresh(case)

    return CaseResponse.model_validate(case)


@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: DBSession,
) -> CaseResponse:
    """Get a case by ID."""
    result = await db.execute(
        select(Case).where(Case.id == case_id, Case.tenant_id == current_user.tenant_id)
    )
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return CaseResponse.model_validate(case)


@router.patch("/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: uuid.UUID,
    request: UpdateCaseRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:write"))],
    db: DBSession,
) -> CaseResponse:
    """Update a case."""
    result = await db.execute(
        select(Case).where(Case.id == case_id, Case.tenant_id == current_user.tenant_id)
    )
    case = result.scalar_one_or_none()
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    updates: dict = {}
    for field in ["title", "description", "status", "priority", "severity", "assigned_to_id", "tags", "resolution", "lessons_learned"]:
        val = getattr(request, field, None)
        if val is not None:
            updates[field] = val

    if request.status in ("closed", "cancelled") and "closed_at" not in updates:
        updates["closed_at"] = datetime.now(UTC)

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        await db.execute(update(Case).where(Case.id == case_id).values(**updates))

        # Add timeline event
        db.add(CaseTimeline(
            case_id=case_id,
            tenant_id=current_user.tenant_id,
            event_type="case_updated",
            content=f"Case updated by {current_user.email}: {', '.join(updates.keys())}",
            user_id=current_user.user_id,
            event_metadata={"changed_fields": list(updates.keys())},
        ))
        await db.commit()
        await db.refresh(case)

    return CaseResponse.model_validate(case)


@router.post("/{case_id}/timeline", response_model=TimelineEventResponse, status_code=status.HTTP_201_CREATED)
async def add_timeline_event(
    case_id: uuid.UUID,
    request: AddTimelineEventRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:write"))],
    db: DBSession,
) -> TimelineEventResponse:
    """Add a comment or event to the case timeline."""
    # Verify case exists for this tenant
    result = await db.execute(
        select(Case).where(Case.id == case_id, Case.tenant_id == current_user.tenant_id)
    )
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    event = CaseTimeline(
        case_id=case_id,
        tenant_id=current_user.tenant_id,
        event_type=request.event_type,
        content=request.content,
        event_metadata=request.metadata,
        user_id=current_user.user_id,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)

    return TimelineEventResponse.model_validate(event)


@router.get("/{case_id}/timeline", response_model=list[TimelineEventResponse])
async def get_timeline(
    case_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: DBSession,
) -> list[TimelineEventResponse]:
    """Get the full timeline for a case."""
    result = await db.execute(
        select(CaseTimeline)
        .where(CaseTimeline.case_id == case_id, CaseTimeline.tenant_id == current_user.tenant_id)
        .order_by(CaseTimeline.created_at.asc())
    )
    events = result.scalars().all()
    return [TimelineEventResponse.model_validate(e) for e in events]
