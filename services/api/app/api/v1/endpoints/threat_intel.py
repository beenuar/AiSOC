"""Internal threat-intel generation endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.auth import get_current_user
from app.db.database import get_db
from app.models.tenant import User
from app.models.threat_intel import ThreatActor, ThreatIntelFeed, ThreatIntelIOC

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class IOCCreate(BaseModel):
    ioc_type: str
    value: str
    confidence: int = Field(50, ge=0, le=100)
    severity: str = "medium"
    tlp: str = "amber"
    threat_actor: str | None = None
    campaign: str | None = None
    malware_family: str | None = None
    tags: list[str] | None = None
    source: str = "internal"
    source_ref: str | None = None
    expires_at: datetime | None = None
    linked_alerts: list[uuid.UUID] | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class IOCOut(IOCCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    is_active: bool
    false_positive: bool
    first_seen: str
    last_seen: str
    created_at: str

    class Config:
        from_attributes = True


class ThreatActorCreate(BaseModel):
    name: str
    aliases: list[str] | None = None
    motivation: str | None = None
    sophistication: str | None = None
    country_of_origin: str | None = None
    target_sectors: list[str] | None = None
    ttps: list[str] | None = None
    description: str | None = None
    first_observed: datetime | None = None
    last_activity: datetime | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class ThreatActorOut(ThreatActorCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    is_active: bool
    created_at: str

    class Config:
        from_attributes = True


class FeedCreate(BaseModel):
    name: str
    feed_type: str
    url: str | None = None
    api_key_ref: str | None = None
    poll_interval: int = 3600
    config: dict[str, Any] = Field(default_factory=dict)


class FeedOut(FeedCreate):
    id: uuid.UUID
    tenant_id: uuid.UUID
    is_enabled: bool
    last_polled_at: str | None = None
    created_at: str

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# IOC endpoints
# ---------------------------------------------------------------------------


@router.get("/iocs", response_model=list[IOCOut])
async def list_iocs(
    ioc_type: str | None = Query(None),
    severity: str | None = Query(None),
    is_active: bool | None = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatIntelIOC]:
    q = select(ThreatIntelIOC).where(ThreatIntelIOC.tenant_id == current_user.tenant_id)
    if ioc_type:
        q = q.where(ThreatIntelIOC.ioc_type == ioc_type)
    if severity:
        q = q.where(ThreatIntelIOC.severity == severity)
    if is_active is not None:
        q = q.where(ThreatIntelIOC.is_active == is_active)
    q = q.order_by(ThreatIntelIOC.last_seen.desc()).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/iocs", response_model=IOCOut, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    body: IOCCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatIntelIOC:
    ioc = ThreatIntelIOC(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.get("/iocs/{ioc_id}", response_model=IOCOut)
async def get_ioc(
    ioc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatIntelIOC:
    ioc = await db.get(ThreatIntelIOC, ioc_id)
    if not ioc or ioc.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc


@router.delete("/iocs/{ioc_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_ioc(
    ioc_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    ioc = await db.get(ThreatIntelIOC, ioc_id)
    if not ioc or ioc.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="IOC not found")
    await db.delete(ioc)
    await db.commit()


# ---------------------------------------------------------------------------
# Threat actor endpoints
# ---------------------------------------------------------------------------


@router.get("/actors", response_model=list[ThreatActorOut])
async def list_actors(
    is_active: bool | None = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatActor]:
    q = select(ThreatActor).where(ThreatActor.tenant_id == current_user.tenant_id)
    if is_active is not None:
        q = q.where(ThreatActor.is_active == is_active)
    q = q.order_by(ThreatActor.name).offset(offset).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


@router.post("/actors", response_model=ThreatActorOut, status_code=status.HTTP_201_CREATED)
async def create_actor(
    body: ThreatActorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatActor:
    actor = ThreatActor(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(actor)
    await db.commit()
    await db.refresh(actor)
    return actor


# ---------------------------------------------------------------------------
# Feed management endpoints
# ---------------------------------------------------------------------------


@router.get("/feeds", response_model=list[FeedOut])
async def list_feeds(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ThreatIntelFeed]:
    result = await db.execute(
        select(ThreatIntelFeed).where(ThreatIntelFeed.tenant_id == current_user.tenant_id).order_by(ThreatIntelFeed.name)
    )
    return list(result.scalars().all())


@router.post("/feeds", response_model=FeedOut, status_code=status.HTTP_201_CREATED)
async def create_feed(
    body: FeedCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatIntelFeed:
    feed = ThreatIntelFeed(**body.model_dump(), tenant_id=current_user.tenant_id)
    db.add(feed)
    await db.commit()
    await db.refresh(feed)
    return feed


@router.delete("/feeds/{feed_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_feed(
    feed_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    feed = await db.get(ThreatIntelFeed, feed_id)
    if not feed or feed.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="Feed not found")
    await db.delete(feed)
    await db.commit()
