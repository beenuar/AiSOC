"""Insider-threat module endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.insider_threat import InsiderIndicator, InsiderPeerGroup, UserRiskProfile
from app.models.tenant import User

router = APIRouter(prefix="/insider-threat", tags=["insider-threat"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class RiskProfileOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    user_id: uuid.UUID | None
    external_user_ref: str | None
    risk_score: float
    risk_tier: str
    failed_auth_24h: int
    off_hours_events_7d: int
    data_staging_score: float
    peer_anomaly_score: float
    privilege_delta: int
    is_watchlisted: bool
    watchlist_reason: str | None
    last_evaluated_at: str
    updated_at: str

    class Config:
        from_attributes = True


class WatchlistUpdate(BaseModel):
    is_watchlisted: bool
    watchlist_reason: str | None = None


class IndicatorOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    profile_id: uuid.UUID
    indicator_type: str
    severity: str
    description: str
    source_alert_id: uuid.UUID | None
    evidence: dict[str, Any]
    occurred_at: str
    acknowledged_at: str | None

    class Config:
        from_attributes = True


class IndicatorCreate(BaseModel):
    profile_id: uuid.UUID
    indicator_type: str
    severity: str = "medium"
    description: str
    source_alert_id: uuid.UUID | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime | None = None


class PeerGroupCreate(BaseModel):
    name: str
    description: str | None = None
    criteria: dict[str, Any] = Field(default_factory=dict)


class PeerGroupOut(PeerGroupCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    created_at: str

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Risk profiles
# ---------------------------------------------------------------------------


@router.get("/profiles", response_model=list[RiskProfileOut])
async def list_profiles(
    risk_tier: str | None = Query(None),
    watchlisted_only: bool = Query(False),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[UserRiskProfile]:
    q = select(UserRiskProfile).where(UserRiskProfile.tenant_id == current_user.tenant_id)
    if risk_tier:
        q = q.where(UserRiskProfile.risk_tier == risk_tier)
    if watchlisted_only:
        q = q.where(UserRiskProfile.is_watchlisted.is_(True))
    q = q.order_by(UserRiskProfile.risk_score.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.get("/profiles/{profile_id}", response_model=RiskProfileOut)
async def get_profile(
    profile_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserRiskProfile:
    profile = await db.get(UserRiskProfile, profile_id)
    if not profile or profile.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@router.patch("/profiles/{profile_id}/watchlist", response_model=RiskProfileOut)
async def update_watchlist(
    profile_id: uuid.UUID,
    body: WatchlistUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserRiskProfile:
    profile = await db.get(UserRiskProfile, profile_id)
    if not profile or profile.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Profile not found")
    profile.is_watchlisted = body.is_watchlisted  # type: ignore[assignment]
    profile.watchlist_reason = body.watchlist_reason  # type: ignore[assignment]
    if body.is_watchlisted:
        profile.watchlisted_at = datetime.now(UTC)  # type: ignore[assignment]
        profile.watchlisted_by = current_user.id  # type: ignore[assignment]
    await db.commit()
    await db.refresh(profile)
    return profile


# ---------------------------------------------------------------------------
# Indicators
# ---------------------------------------------------------------------------


@router.get("/indicators", response_model=list[IndicatorOut])
async def list_indicators(
    severity: str | None = Query(None),
    indicator_type: str | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[InsiderIndicator]:
    q = select(InsiderIndicator).where(InsiderIndicator.tenant_id == current_user.tenant_id)
    if severity:
        q = q.where(InsiderIndicator.severity == severity)
    if indicator_type:
        q = q.where(InsiderIndicator.indicator_type == indicator_type)
    q = q.order_by(InsiderIndicator.occurred_at.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/indicators", response_model=IndicatorOut, status_code=status.HTTP_201_CREATED)
async def create_indicator(
    body: IndicatorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InsiderIndicator:
    profile = await db.get(UserRiskProfile, body.profile_id)
    if not profile or profile.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Profile not found")
    data = body.model_dump()
    if data.get("occurred_at") is None:
        data["occurred_at"] = datetime.now(UTC)
    indicator = InsiderIndicator(**data, tenant_id=current_user.tenant_id)
    db.add(indicator)
    await db.commit()
    await db.refresh(indicator)
    return indicator


@router.post("/indicators/{indicator_id}/acknowledge", response_model=IndicatorOut)
async def acknowledge_indicator(
    indicator_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InsiderIndicator:
    indicator = await db.get(InsiderIndicator, indicator_id)
    if not indicator or indicator.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Indicator not found")
    indicator.acknowledged_by = current_user.id  # type: ignore[assignment]
    indicator.acknowledged_at = datetime.now(UTC)  # type: ignore[assignment]
    await db.commit()
    await db.refresh(indicator)
    return indicator


# ---------------------------------------------------------------------------
# Peer groups
# ---------------------------------------------------------------------------


@router.get("/peer-groups", response_model=list[PeerGroupOut])
async def list_peer_groups(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[InsiderPeerGroup]:
    result = await db.execute(
        select(InsiderPeerGroup).where(InsiderPeerGroup.tenant_id == current_user.tenant_id).order_by(InsiderPeerGroup.name)
    )
    return list(result.scalars().all())


@router.post("/peer-groups", response_model=PeerGroupOut, status_code=status.HTTP_201_CREATED)
async def create_peer_group(
    body: PeerGroupCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> InsiderPeerGroup:
    group = InsiderPeerGroup(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(group)
    await db.commit()
    await db.refresh(group)
    return group
