"""SLA tracking API endpoints.

GET  /api/v1/sla/metrics          — Aggregated MTTD/MTTR/MTTC metrics
GET  /api/v1/sla/config           — Current per-severity SLA targets
PUT  /api/v1/sla/config/{severity} — Update SLA target for a severity
POST /api/v1/sla/events           — Record a lifecycle event for an alert
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.sla import AlertSLAEvent, TenantSLAConfig
from app.services.sla import compute_sla_metrics

router = APIRouter(prefix="/sla", tags=["sla"])

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_EVENT_TYPES = {"detected", "acknowledged", "resolved", "closed"}


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class SLAConfigOut(BaseModel):
    id: uuid.UUID
    severity: str
    mttd_target: int
    mttr_target: int
    mttc_target: int
    updated_at: datetime

    class Config:
        from_attributes = True


class SLAConfigUpdate(BaseModel):
    mttd_target: int = Field(..., ge=1, le=10080, description="Minutes")
    mttr_target: int = Field(..., ge=1, le=10080, description="Minutes")
    mttc_target: int = Field(..., ge=1, le=10080, description="Minutes")


class SLAEventCreate(BaseModel):
    alert_id: uuid.UUID
    severity: str
    event_type: str
    occurred_at: datetime | None = None
    metadata: dict = Field(default_factory=dict)


class SLAEventOut(BaseModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    severity: str
    event_type: str
    occurred_at: datetime
    metadata: dict

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/metrics")
async def get_sla_metrics(
    current_user: Annotated[AuthUser, Depends(require_permission("sla:read"))],
    db: TenantDBSession,
    days: int = Query(default=30, ge=1, le=365, description="Look-back window in days"),
):
    """Return aggregated MTTD / MTTR / MTTC metrics for the tenant."""
    return await compute_sla_metrics(db, current_user.tenant_id, days=days)


@router.get("/config", response_model=list[SLAConfigOut])
async def get_sla_config(
    current_user: Annotated[AuthUser, Depends(require_permission("sla:read"))],
    db: TenantDBSession,
) -> list[SLAConfigOut]:
    """Return per-severity SLA configuration for the tenant."""
    rows = await db.execute(
        select(TenantSLAConfig).where(
            TenantSLAConfig.tenant_id == current_user.tenant_id
        )
    )
    return rows.scalars().all()  # type: ignore[return-value]


@router.put("/config/{severity}", response_model=SLAConfigOut)
async def update_sla_config(
    severity: str,
    body: SLAConfigUpdate,
    current_user: Annotated[AuthUser, Depends(require_permission("sla:write"))],
    db: TenantDBSession,
) -> SLAConfigOut:
    """Upsert SLA targets for a given severity."""
    if severity not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"severity must be one of {sorted(VALID_SEVERITIES)}",
        )

    result = await db.execute(
        select(TenantSLAConfig).where(
            TenantSLAConfig.tenant_id == current_user.tenant_id,
            TenantSLAConfig.severity == severity,
        )
    )
    config = result.scalar_one_or_none()

    if config is None:
        config = TenantSLAConfig(
            tenant_id=current_user.tenant_id,
            severity=severity,
        )
        db.add(config)

    config.mttd_target = body.mttd_target
    config.mttr_target = body.mttr_target
    config.mttc_target = body.mttc_target
    config.updated_at = datetime.utcnow()

    await db.commit()
    await db.refresh(config)
    return config  # type: ignore[return-value]


@router.post("/events", response_model=SLAEventOut, status_code=201)
async def record_sla_event(
    body: SLAEventCreate,
    current_user: Annotated[AuthUser, Depends(require_permission("sla:write"))],
    db: TenantDBSession,
) -> SLAEventOut:
    """Record a lifecycle event (detected/acknowledged/resolved/closed) for an alert."""
    if body.severity not in VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"severity must be one of {sorted(VALID_SEVERITIES)}",
        )
    if body.event_type not in VALID_EVENT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"event_type must be one of {sorted(VALID_EVENT_TYPES)}",
        )

    event = AlertSLAEvent(
        tenant_id=current_user.tenant_id,
        alert_id=body.alert_id,
        severity=body.severity,
        event_type=body.event_type,
        occurred_at=body.occurred_at or datetime.utcnow(),
        actor_id=current_user.id,
        metadata=body.metadata,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event  # type: ignore[return-value]
