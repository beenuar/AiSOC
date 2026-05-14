"""L0–L4 auto-remediation maturity tier endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.remediation import RemediationGateLog, RemediationMaturity, RemediationWhitelist
from app.models.tenant import User

router = APIRouter(prefix="/remediation", tags=["remediation"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class MaturityConfig(BaseModel):
    maturity_tier: int = Field(..., ge=0, le=4)
    action_overrides: dict[str, Any] = Field(default_factory=dict)


class MaturityOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    maturity_tier: int
    action_overrides: dict[str, Any]
    changed_at: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class GateLogOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    action_id: uuid.UUID
    action_type: str
    blast_radius: str
    maturity_tier: int
    decision: str
    rationale: str | None
    actor: str
    created_at: str

    model_config = ConfigDict(from_attributes=True)


class WhitelistCreate(BaseModel):
    action_type: str
    blast_radius: str
    constraints: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None


class WhitelistOut(WhitelistCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    approved_by: uuid.UUID | None
    created_at: str

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Maturity config endpoints
# ---------------------------------------------------------------------------


@router.get("/config", response_model=MaturityOut)
async def get_maturity_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RemediationMaturity:
    result = await db.execute(select(RemediationMaturity).where(RemediationMaturity.tenant_id == current_user.tenant_id))
    config = result.scalar_one_or_none()
    if not config:
        config = RemediationMaturity(
            tenant_id=current_user.tenant_id,
            maturity_tier=0,
        )
        db.add(config)
        await db.commit()
        await db.refresh(config)
    return config


@router.put("/config", response_model=MaturityOut)
async def update_maturity_config(
    body: MaturityConfig,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RemediationMaturity:
    result = await db.execute(select(RemediationMaturity).where(RemediationMaturity.tenant_id == current_user.tenant_id))
    config = result.scalar_one_or_none()
    if not config:
        config = RemediationMaturity(tenant_id=current_user.tenant_id)
        db.add(config)

    config.maturity_tier = body.maturity_tier  # type: ignore[assignment]
    config.action_overrides = body.action_overrides  # type: ignore[assignment]
    config.changed_by = current_user.id  # type: ignore[assignment]
    config.changed_at = datetime.now(UTC)  # type: ignore[assignment]
    await db.commit()
    await db.refresh(config)
    return config


# ---------------------------------------------------------------------------
# Gate log (audit trail)
# ---------------------------------------------------------------------------


@router.get("/gate-log", response_model=list[GateLogOut])
async def list_gate_log(
    decision: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[RemediationGateLog]:
    q = select(RemediationGateLog).where(RemediationGateLog.tenant_id == current_user.tenant_id)
    if decision:
        q = q.where(RemediationGateLog.decision == decision)
    q = q.order_by(RemediationGateLog.created_at.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Whitelist endpoints
# ---------------------------------------------------------------------------


@router.get("/whitelist", response_model=list[WhitelistOut])
async def list_whitelist(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[RemediationWhitelist]:
    result = await db.execute(select(RemediationWhitelist).where(RemediationWhitelist.tenant_id == current_user.tenant_id))
    return list(result.scalars().all())


@router.post("/whitelist", response_model=WhitelistOut, status_code=status.HTTP_201_CREATED)
async def add_to_whitelist(
    body: WhitelistCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RemediationWhitelist:
    entry = RemediationWhitelist(
        **body.model_dump(),
        tenant_id=current_user.tenant_id,
        approved_by=current_user.id,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return entry


@router.delete("/whitelist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def remove_from_whitelist(
    entry_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    entry = await db.get(RemediationWhitelist, entry_id)
    if not entry or entry.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Whitelist entry not found")
    await db.delete(entry)
    await db.commit()
