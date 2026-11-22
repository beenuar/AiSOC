"""Insider-threat module endpoints.

Authorization
-------------
Writes require ``cases:write``. Watchlisting a person, recording an indicator
against them and acknowledging one are investigative acts about a subject —
the same class of judgement as working a case, held by every investigating
role and withheld from ``viewer``. It was ``viewer`` that mattered: a
read-only account could put an employee on the watchlist with a reason of its
choosing, or manufacture indicators against one.

``settings:write`` was the alternative and is the wrong shape. It would
restrict the module to tenant administrators, which takes insider-threat work
away from the analysts the module exists for, and watchlisting a subject is
not tenant configuration.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import CurrentUser, require_permission
from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.insider_threat import (
    InsiderIndicator,
    InsiderPeerGroup,
    InsiderWatchlistPolicy,
    UserRiskProfile,
)
from app.services import insider_watchlist

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
    watchlist_expires_at: datetime | None = None
    watchlist_source: str = "manual"
    last_evaluated_at: str
    updated_at: str

    model_config = ConfigDict(from_attributes=True)


class WatchlistUpdate(BaseModel):
    is_watchlisted: bool
    watchlist_reason: str | None = None
    #: Required when watchlisting — a watchlist row is never indefinite.
    #: Omitted, the tenant's `default_expiry_days` (or 30) is applied.
    watchlist_expires_at: datetime | None = None


class WatchlistResult(RiskProfileOut):
    """The PATCH response: the profile plus what watchlisting actually did.

    `elevation_active` says whether a managed business-context rule now
    matches this identity; when it cannot (`external_user_ref` is empty),
    `elevation_gap` names the missing piece rather than implying elevation
    silently. `lookback_case_id` is the departure-review case the
    transition opened, when it opened one.
    """

    elevation_active: bool = False
    elevation_gap: str | None = None
    lookback_case_id: uuid.UUID | None = None


class WatchlistPolicyBody(BaseModel):
    hr_sync_enabled: bool = False
    default_expiry_days: int = Field(30, ge=1, le=365)
    hr_grace_days: int = Field(14, ge=1, le=90)
    lookback_days: int = Field(30, ge=1, le=90)


class WatchlistPolicyOut(WatchlistPolicyBody):
    tenant_id: uuid.UUID
    updated_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


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

    model_config = ConfigDict(from_attributes=True)


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

    model_config = ConfigDict(from_attributes=True)


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
    current_user: CurrentUser = Depends(get_current_user),
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
    current_user: CurrentUser = Depends(get_current_user),
) -> UserRiskProfile:
    profile = await db.get(UserRiskProfile, profile_id)
    if not profile or profile.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


@router.patch("/profiles/{profile_id}/watchlist", response_model=WatchlistResult)
async def update_watchlist(
    profile_id: uuid.UUID,
    body: WatchlistUpdate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:write"))],
) -> WatchlistResult:
    """Watchlist (or clear) a profile — the switch that now does something.

    Watchlisting requires a reason and an expiry (422 names the one that is
    missing; an omitted expiry falls back to the tenant's policy default so
    the console's one-click path still works). The transition onto the list
    rebuilds the tenant's managed business-context rules and opens the
    departure-review lookback case; clearing withdraws the managed rules.
    """
    profile = await db.get(UserRiskProfile, profile_id)
    if not profile or profile.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Profile not found")

    policy = await db.get(InsiderWatchlistPolicy, current_user.tenant_id)
    lookback_days = int(policy.lookback_days) if policy else 30
    default_days = int(policy.default_expiry_days) if policy else 30

    outcome: insider_watchlist.WatchlistOutcome | None = None
    if body.is_watchlisted:
        expires_at = body.watchlist_expires_at or (datetime.now(UTC) + timedelta(days=default_days))
        try:
            outcome = await insider_watchlist.apply_watchlist(
                db,
                profile,
                reason=(body.watchlist_reason or "").strip(),
                expires_at=expires_at,
                source="manual",
                actor_id=current_user.user_id,
                lookback_days=lookback_days,
            )
        except insider_watchlist.WatchlistValidationError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
    else:
        profile.watchlist_reason = body.watchlist_reason  # type: ignore[assignment]
        await insider_watchlist.clear_watchlist(db, profile)

    await db.commit()
    await db.refresh(profile)
    result = WatchlistResult.model_validate(profile)
    if outcome is not None:
        result.elevation_active = outcome.elevation_active
        result.elevation_gap = outcome.elevation_gap
        result.lookback_case_id = outcome.lookback_case_id
    return result


# ---------------------------------------------------------------------------
# Watchlist policy (the HR door's switch — tenant configuration)
# ---------------------------------------------------------------------------


@router.get("/watchlist-policy", response_model=WatchlistPolicyOut)
async def get_watchlist_policy(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(get_current_user)],
) -> WatchlistPolicyOut:
    """The tenant's policy; an absent row is the honest default (all off)."""
    policy = await db.get(InsiderWatchlistPolicy, current_user.tenant_id)
    if policy is None:
        return WatchlistPolicyOut(tenant_id=current_user.tenant_id)
    return WatchlistPolicyOut.model_validate(policy)


@router.put("/watchlist-policy", response_model=WatchlistPolicyOut)
async def put_watchlist_policy(
    body: WatchlistPolicyBody,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
) -> WatchlistPolicyOut:
    """Upsert the policy. `settings:write`, not `cases:write`: switching on
    an automated door that watches the HR store is tenant configuration,
    unlike watchlisting one subject, which is investigative work."""
    policy = await db.get(InsiderWatchlistPolicy, current_user.tenant_id)
    if policy is None:
        policy = InsiderWatchlistPolicy(tenant_id=current_user.tenant_id)
        db.add(policy)
    policy.hr_sync_enabled = body.hr_sync_enabled
    policy.default_expiry_days = body.default_expiry_days
    policy.hr_grace_days = body.hr_grace_days
    policy.lookback_days = body.lookback_days
    policy.updated_by = current_user.user_id
    await db.commit()
    await db.refresh(policy)
    return WatchlistPolicyOut.model_validate(policy)


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
    current_user: CurrentUser = Depends(get_current_user),
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
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:write"))],
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
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:write"))],
) -> InsiderIndicator:
    indicator = await db.get(InsiderIndicator, indicator_id)
    if not indicator or indicator.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Indicator not found")
    indicator.acknowledged_by = current_user.user_id  # type: ignore[assignment]
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
    current_user: CurrentUser = Depends(get_current_user),
) -> list[InsiderPeerGroup]:
    result = await db.execute(
        select(InsiderPeerGroup).where(InsiderPeerGroup.tenant_id == current_user.tenant_id).order_by(InsiderPeerGroup.name)
    )
    return list(result.scalars().all())


@router.post("/peer-groups", response_model=PeerGroupOut, status_code=status.HTTP_201_CREATED)
async def create_peer_group(
    body: PeerGroupCreate,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[CurrentUser, Depends(require_permission("cases:write"))],
) -> InsiderPeerGroup:
    group = InsiderPeerGroup(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(group)
    await db.commit()
    await db.refresh(group)
    return group
