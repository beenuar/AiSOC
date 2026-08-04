"""Self-service data lifecycle: retention policies + custom parsers (Wave 5)."""

from __future__ import annotations

import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.models.data_lifecycle import CustomParserRow, RetentionPolicyRow
from app.services.pipeline_transforms import TransformError, apply_transforms, validate_transforms
from app.services.retention import resolve_policy

router = APIRouter(prefix="/data-lifecycle", tags=["data_lifecycle"])


# ── Retention (W5.1) ───────────────────────────────────────────────────────


class RetentionOut(BaseModel):
    raw_events_days: int
    alerts_days: int
    audit_days: int


class RetentionUpdate(BaseModel):
    raw_events_days: int | None = Field(None, ge=1, le=3650)
    alerts_days: int | None = Field(None, ge=1, le=3650)
    audit_days: int | None = Field(None, ge=1, le=3650)


@router.get("/retention", response_model=RetentionOut)
async def get_retention(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> RetentionOut:
    row = (await db.execute(select(RetentionPolicyRow).where(RetentionPolicyRow.tenant_id == current_user.tenant_id))).scalar_one_or_none()
    cfg = {} if row is None else {"raw_events_days": row.raw_events_days, "alerts_days": row.alerts_days, "audit_days": row.audit_days}
    return RetentionOut(**resolve_policy(cfg).as_dict())


@router.put("/retention", response_model=RetentionOut)
async def put_retention(
    body: RetentionUpdate,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> RetentionOut:
    row = (await db.execute(select(RetentionPolicyRow).where(RetentionPolicyRow.tenant_id == current_user.tenant_id))).scalar_one_or_none()
    if row is None:
        row = RetentionPolicyRow(tenant_id=current_user.tenant_id)
        db.add(row)
    merged = resolve_policy(
        {
            "raw_events_days": body.raw_events_days if body.raw_events_days is not None else row.raw_events_days,
            "alerts_days": body.alerts_days if body.alerts_days is not None else row.alerts_days,
            "audit_days": body.audit_days if body.audit_days is not None else row.audit_days,
        }
    )
    row.raw_events_days = merged.raw_events_days
    row.alerts_days = merged.alerts_days
    row.audit_days = merged.audit_days
    row.updated_by = current_user.user_id
    await db.commit()
    return RetentionOut(**merged.as_dict())


# ── Custom parsers (W5.2, built on the W5.3 DSL) ───────────────────────────


class ParserIn(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    source: str = "generic"
    transforms: list[dict[str, Any]] = Field(default_factory=list)
    enabled: bool = True


class ParserOut(BaseModel):
    id: uuid.UUID
    name: str
    source: str
    transforms: list[dict[str, Any]]
    enabled: bool


class ParserTestIn(BaseModel):
    transforms: list[dict[str, Any]]
    sample_event: dict[str, Any]


class ParserTestOut(BaseModel):
    event: dict[str, Any]
    warnings: list[str]


def _to_out(row: CustomParserRow) -> ParserOut:
    return ParserOut(id=row.id, name=row.name, source=row.source, transforms=list(row.transforms or []), enabled=row.enabled)


@router.get("/parsers", response_model=list[ParserOut])
async def list_parsers(
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
    db: DBSession,
) -> list[ParserOut]:
    rows = (await db.execute(select(CustomParserRow).where(CustomParserRow.tenant_id == current_user.tenant_id))).scalars().all()
    return [_to_out(r) for r in rows]


@router.post("/parsers", response_model=ParserOut, status_code=status.HTTP_201_CREATED)
async def create_parser(
    body: ParserIn,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> ParserOut:
    try:
        validate_transforms(body.transforms)
    except TransformError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    row = CustomParserRow(
        tenant_id=current_user.tenant_id,
        name=body.name,
        source=body.source,
        transforms=body.transforms,
        enabled=body.enabled,
        created_by=current_user.user_id,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return _to_out(row)


@router.post("/parsers/test", response_model=ParserTestOut)
async def test_parser(
    body: ParserTestIn,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
) -> ParserTestOut:
    """Dry-run a parser pipeline against a sample event — validate + preview
    the reshaped event without persisting anything (W5.2/W5.3)."""
    try:
        validate_transforms(body.transforms)
    except TransformError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    result = apply_transforms(body.sample_event, body.transforms)
    return ParserTestOut(event=result.event, warnings=result.warnings)


@router.delete("/parsers/{parser_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_parser(
    parser_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
    db: DBSession,
) -> None:
    row = (
        await db.execute(
            select(CustomParserRow).where(CustomParserRow.id == parser_id, CustomParserRow.tenant_id == current_user.tenant_id)
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="parser not found")
    await db.delete(row)
    await db.commit()
