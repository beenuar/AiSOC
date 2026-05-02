"""Detection rule management endpoints."""
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.detection_rule import DetectionRule

router = APIRouter(prefix="/rules", tags=["detection_rules"])


class DetectionRuleResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    name: str
    description: str | None
    rule_language: str
    rule_body: str
    category: str
    status: str
    severity: str
    confidence: int
    mitre_tactics: list
    mitre_techniques: list
    fp_rate: float
    total_hits: int
    last_triggered: datetime | None
    tags: list
    is_builtin: bool
    version: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class CreateRuleRequest(BaseModel):
    name: str
    description: str | None = None
    rule_language: str
    rule_body: str
    category: str
    severity: str = "medium"
    confidence: int = 50
    mitre_tactics: list[str] = []
    mitre_techniques: list[str] = []
    tags: list[str] = []


class UpdateRuleRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    rule_body: str | None = None
    status: str | None = None
    severity: str | None = None
    confidence: int | None = None
    tags: list[str] | None = None


@router.get("", response_model=list[DetectionRuleResponse])
async def list_rules(
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
    category: str | None = Query(default=None),
    rule_language: str | None = Query(default=None),
    include_builtin: bool = Query(default=True),
) -> list[DetectionRuleResponse]:
    """List detection rules for the tenant (includes built-in platform rules)."""
    # Return tenant's own rules + platform-wide built-in rules
    filters = [
        or_(
            DetectionRule.tenant_id == current_user.tenant_id,
            and_(DetectionRule.tenant_id.is_(None), DetectionRule.is_builtin == True),
        )
    ]
    if not include_builtin:
        filters = [DetectionRule.tenant_id == current_user.tenant_id]
    if category:
        filters.append(DetectionRule.category == category)
    if rule_language:
        filters.append(DetectionRule.rule_language == rule_language)

    result = await db.execute(
        select(DetectionRule).where(and_(*filters)).order_by(DetectionRule.name)
    )
    rules = result.scalars().all()
    return [DetectionRuleResponse.model_validate(r) for r in rules]


@router.post("", response_model=DetectionRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_rule(
    request: CreateRuleRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> DetectionRuleResponse:
    """Create a new detection rule."""
    rule = DetectionRule(
        tenant_id=current_user.tenant_id,
        name=request.name,
        description=request.description,
        rule_language=request.rule_language,
        rule_body=request.rule_body,
        category=request.category,
        severity=request.severity,
        confidence=request.confidence,
        mitre_tactics=request.mitre_tactics,
        mitre_techniques=request.mitre_techniques,
        tags=request.tags,
        created_by_id=current_user.user_id,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return DetectionRuleResponse.model_validate(rule)


@router.get("/{rule_id}", response_model=DetectionRuleResponse)
async def get_rule(
    rule_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:read"))],
    db: DBSession,
) -> DetectionRuleResponse:
    """Get a detection rule by ID."""
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == rule_id,
            or_(
                DetectionRule.tenant_id == current_user.tenant_id,
                DetectionRule.tenant_id.is_(None),
            ),
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return DetectionRuleResponse.model_validate(rule)


@router.patch("/{rule_id}", response_model=DetectionRuleResponse)
async def update_rule(
    rule_id: uuid.UUID,
    request: UpdateRuleRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> DetectionRuleResponse:
    """Update a detection rule (only tenant-owned rules)."""
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == rule_id,
            DetectionRule.tenant_id == current_user.tenant_id,
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found or cannot be modified",
        )

    updates: dict = {}
    for field in ["name", "description", "rule_body", "status", "severity", "confidence", "tags"]:
        val = getattr(request, field, None)
        if val is not None:
            updates[field] = val

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        updates["version"] = rule.version + 1
        await db.execute(update(DetectionRule).where(DetectionRule.id == rule_id).values(**updates))
        await db.commit()
        await db.refresh(rule)

    return DetectionRuleResponse.model_validate(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("rules:write"))],
    db: DBSession,
) -> None:
    """Delete a tenant-owned detection rule."""
    result = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == rule_id,
            DetectionRule.tenant_id == current_user.tenant_id,
        )
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found or cannot be deleted",
        )
    await db.delete(rule)
    await db.commit()
