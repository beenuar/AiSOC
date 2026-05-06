"""Analyst override feedback endpoint.

Allows analysts to correct AI-generated alert verdicts. Corrections are:
  1. Persisted to the alerts table (disposition field).
  2. Published as an event for downstream institutional memory ingestion.
  3. Used to update SOC FPR metrics.
"""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update

from app.api.v1.deps import AuthUser, DBSession
from app.models.alert import Alert

import structlog

logger = structlog.get_logger()

router = APIRouter(prefix="/feedback", tags=["feedback"])


class AlertOverrideRequest(BaseModel):
    alert_id: str
    original_verdict: str = Field(..., description="The AI-generated verdict being overridden")
    corrected_verdict: str = Field(
        ...,
        description="Analyst's verdict: true_positive | false_positive | benign | escalate",
    )
    reason: str | None = Field(None, description="Optional free-text justification")


class AlertOverrideResponse(BaseModel):
    alert_id: str
    corrected_verdict: str
    recorded_at: str


@router.post("/alert-override", response_model=AlertOverrideResponse)
async def submit_alert_override(
    payload: AlertOverrideRequest,
    user: AuthUser,
    db: DBSession,
) -> AlertOverrideResponse:
    """Record an analyst verdict correction on an alert.

    This persists the override disposition and emits a structured log event
    that the institutional memory ingester picks up asynchronously.
    """
    valid_verdicts = {"true_positive", "false_positive", "benign", "escalate"}
    if payload.corrected_verdict not in valid_verdicts:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"corrected_verdict must be one of: {', '.join(sorted(valid_verdicts))}",
        )

    # Verify the alert belongs to this tenant
    row = await db.scalar(
        select(Alert).where(
            Alert.id == payload.alert_id,
            Alert.tenant_id == user.tenant_id,
        )
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    # Persist disposition on the alert
    now = datetime.now(UTC)
    await db.execute(
        update(Alert)
        .where(Alert.id == payload.alert_id, Alert.tenant_id == user.tenant_id)
        .values(
            disposition=payload.corrected_verdict,
            updated_at=now,
        )
    )
    await db.commit()

    # Structured log event — picked up by institutional memory ingester
    logger.info(
        "analyst.override",
        tenant_id=user.tenant_id,
        alert_id=payload.alert_id,
        analyst_id=str(user.id),
        original_verdict=payload.original_verdict,
        corrected_verdict=payload.corrected_verdict,
        reason=payload.reason,
        recorded_at=now.isoformat(),
    )

    return AlertOverrideResponse(
        alert_id=payload.alert_id,
        corrected_verdict=payload.corrected_verdict,
        recorded_at=now.isoformat(),
    )


class OverrideSummaryResponse(BaseModel):
    total_overrides: int
    false_positive_corrections: int
    true_positive_corrections: int
    benign_corrections: int


@router.get("/summary", response_model=OverrideSummaryResponse)
async def get_override_summary(
    user: AuthUser,
    db: DBSession,
) -> OverrideSummaryResponse:
    """Return a summary of analyst overrides for this tenant."""
    from sqlalchemy import func, and_

    total = await db.scalar(
        select(func.count()).where(
            and_(Alert.tenant_id == user.tenant_id, Alert.disposition.isnot(None))
        )
    ) or 0
    fp = await db.scalar(
        select(func.count()).where(
            and_(Alert.tenant_id == user.tenant_id, Alert.disposition == "false_positive")
        )
    ) or 0
    tp = await db.scalar(
        select(func.count()).where(
            and_(Alert.tenant_id == user.tenant_id, Alert.disposition == "true_positive")
        )
    ) or 0
    benign = await db.scalar(
        select(func.count()).where(
            and_(Alert.tenant_id == user.tenant_id, Alert.disposition == "benign")
        )
    ) or 0

    return OverrideSummaryResponse(
        total_overrides=total,
        false_positive_corrections=fp,
        true_positive_corrections=tp,
        benign_corrections=benign,
    )
