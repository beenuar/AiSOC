"""SLA tracking API endpoints.

GET  /api/v1/sla/metrics            — Aggregated MTTD/MTTR/MTTC metrics (+ optional 2026 KPI bar)
GET  /api/v1/sla/config             — Current per-severity SLA targets
PUT  /api/v1/sla/config/{severity}  — Update SLA target for a severity
GET  /api/v1/sla/kpi-targets        — Tenant 2026 KPI bar targets (defaults + overrides)
PUT  /api/v1/sla/kpi-targets        — Patch KPI bar targets (deep-merge ``kpi_bar`` in tenant settings)
POST /api/v1/sla/events             — Record a lifecycle event for an alert
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, require_permission
from app.core.config import get_settings
from app.db.rls import TenantDBSession
from app.models.sla import AlertSLAEvent, TenantSLAConfig
from app.services import sla as sla_service

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


class KpiBarTargetsOut(BaseModel):
    false_positive_rate_max_pct: float = Field(..., ge=0, le=100)
    alert_to_incident_ratio_min: float = Field(..., ge=1)
    mitre_technique_tagging_min_pct: float = Field(..., ge=0, le=100)
    mitre_subtechnique_tagging_min_pct: float = Field(..., ge=0, le=100)


class KpiBarTargetsUpdate(BaseModel):
    false_positive_rate_max_pct: float | None = Field(default=None, ge=0, le=100)
    alert_to_incident_ratio_min: float | None = Field(default=None, ge=1)
    mitre_technique_tagging_min_pct: float | None = Field(default=None, ge=0, le=100)
    mitre_subtechnique_tagging_min_pct: float | None = Field(default=None, ge=0, le=100)


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
    return await sla_service.compute_sla_metrics(db, current_user.tenant_id, days=days)


def _require_kpi_bar_feature() -> None:
    if not get_settings().AISOC_FEATURE_KPI_BAR:
        raise HTTPException(status_code=404, detail="2026 KPI bar feature is disabled")


@router.get("/kpi-targets", response_model=KpiBarTargetsOut)
async def get_kpi_bar_targets(
    current_user: Annotated[AuthUser, Depends(require_permission("sla:read"))],
    db: TenantDBSession,
) -> KpiBarTargetsOut:
    """Return merged 2026 KPI bar targets (published defaults plus tenant ``settings.kpi_bar``)."""
    _require_kpi_bar_feature()
    merged = await sla_service.load_kpi_bar_targets(db, current_user.tenant_id)
    return KpiBarTargetsOut.model_validate(merged)


@router.put("/kpi-targets", response_model=KpiBarTargetsOut)
async def put_kpi_bar_targets(
    body: KpiBarTargetsUpdate,
    current_user: Annotated[AuthUser, Depends(require_permission("sla:write"))],
    db: TenantDBSession,
) -> KpiBarTargetsOut:
    """Patch tenant KPI bar targets; unspecified fields keep previous values."""
    _require_kpi_bar_feature()
    patch = {k: float(v) for k, v in body.model_dump(exclude_unset=True).items() if v is not None}
    try:
        merged = await sla_service.patch_tenant_kpi_bar_targets(db, current_user.tenant_id, patch)
    except ValueError:
        raise HTTPException(status_code=404, detail="Tenant not found") from None
    return KpiBarTargetsOut.model_validate(merged)


@router.get("/config", response_model=list[SLAConfigOut])
async def get_sla_config(
    current_user: Annotated[AuthUser, Depends(require_permission("sla:read"))],
    db: TenantDBSession,
) -> list[SLAConfigOut]:
    """Return per-severity SLA configuration for the tenant."""
    rows = await db.execute(select(TenantSLAConfig).where(TenantSLAConfig.tenant_id == current_user.tenant_id))
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
        # ORM attr is `metadata_` (DB column is still `metadata`) — `metadata`
        # itself is reserved on Declarative `Base`.
        metadata_=body.metadata,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event  # type: ignore[return-value]
