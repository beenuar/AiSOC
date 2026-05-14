"""UEBA REST API routes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.models.ueba import EntityBaseline, PeerGroup, UEBAAnomaly
from app.services.scoring import ScoringService

router = APIRouter(prefix="/api/v1/ueba", tags=["ueba"])

# ---------------------------------------------------------------------------
# DB dependency
# ---------------------------------------------------------------------------
_engine = create_async_engine(settings.database_url)
_session_factory = async_sessionmaker(_engine, expire_on_commit=False)


async def get_db() -> AsyncSession:  # type: ignore[return]
    async with _session_factory() as session:
        yield session


DB = Annotated[AsyncSession, Depends(get_db)]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ScoreEventRequest(BaseModel):
    tenant_id: uuid.UUID
    entity_type: str = Field(..., pattern="^(user|device|ip)$")
    entity_id: str
    event_type: str
    features: dict[str, float]
    peer_group_id: str | None = None
    source_event_id: str | None = None


class AnomalyOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    entity_type: str
    entity_id: str
    event_type: str
    anomaly_score: float
    risk_level: str
    features: dict
    peer_group_id: str | None
    peer_deviation_score: float | None
    detected_at: datetime
    acknowledged: bool

    model_config = ConfigDict(from_attributes=True)


class BaselineOut(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    entity_type: str
    entity_id: str
    feature_stats: dict
    window_start: datetime
    window_end: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/score", response_model=AnomalyOut | None, status_code=200)
async def score_event(body: ScoreEventRequest, db: DB) -> AnomalyOut | None:
    """Score a single event and return the anomaly record if anomalous."""
    async with db.begin():
        svc = ScoringService(db)
        anomaly = await svc.score_event(
            tenant_id=body.tenant_id,
            entity_type=body.entity_type,
            entity_id=body.entity_id,
            event_type=body.event_type,
            features=body.features,
            source_event_id=body.source_event_id,
            peer_group_id=body.peer_group_id,
        )
    return AnomalyOut.model_validate(anomaly) if anomaly else None


@router.get("/anomalies", response_model=list[AnomalyOut])
async def list_anomalies(
    db: DB,
    tenant_id: uuid.UUID = Query(...),
    entity_type: str | None = Query(None),
    entity_id: str | None = Query(None),
    risk_level: str | None = Query(None),
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(50, ge=1, le=500),
) -> list[AnomalyOut]:
    since = datetime.now(UTC) - timedelta(hours=hours)
    q = (
        select(UEBAAnomaly)
        .where(UEBAAnomaly.tenant_id == tenant_id, UEBAAnomaly.detected_at >= since)
        .order_by(desc(UEBAAnomaly.detected_at))
        .limit(limit)
    )
    if entity_type:
        q = q.where(UEBAAnomaly.entity_type == entity_type)
    if entity_id:
        q = q.where(UEBAAnomaly.entity_id == entity_id)
    if risk_level:
        q = q.where(UEBAAnomaly.risk_level == risk_level)

    result = await db.execute(q)
    return [AnomalyOut.model_validate(row) for row in result.scalars().all()]


@router.patch("/anomalies/{anomaly_id}/acknowledge", response_model=AnomalyOut)
async def acknowledge_anomaly(anomaly_id: uuid.UUID, db: DB) -> AnomalyOut:
    result = await db.execute(select(UEBAAnomaly).where(UEBAAnomaly.id == anomaly_id))
    anomaly = result.scalar_one_or_none()
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    async with db.begin_nested():
        anomaly.acknowledged = True
    return AnomalyOut.model_validate(anomaly)


@router.get("/baselines", response_model=list[BaselineOut])
async def list_baselines(
    db: DB,
    tenant_id: uuid.UUID = Query(...),
    entity_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
) -> list[BaselineOut]:
    q = select(EntityBaseline).where(EntityBaseline.tenant_id == tenant_id).order_by(desc(EntityBaseline.updated_at)).limit(limit)
    if entity_type:
        q = q.where(EntityBaseline.entity_type == entity_type)
    result = await db.execute(q)
    return [BaselineOut.model_validate(row) for row in result.scalars().all()]


@router.get("/peer-groups", response_model=list[dict])
async def list_peer_groups(
    db: DB,
    tenant_id: uuid.UUID = Query(...),
) -> list[dict]:
    result = await db.execute(select(PeerGroup).where(PeerGroup.tenant_id == tenant_id))
    return [
        {
            "id": pg.id,
            "label": pg.label,
            "entity_type": pg.entity_type,
            "member_count": pg.member_count,
            "updated_at": pg.updated_at.isoformat() if pg.updated_at else None,
        }
        for pg in result.scalars().all()
    ]
