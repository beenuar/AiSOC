"""Analyst override feedback + retroactive re-disposition — Tier 1.5.

Pipeline
--------
1. ``POST /feedback/alert-override`` — analyst corrects an AI verdict.
   * Persists the corrected ``disposition`` on the alert.
   * Records the lesson in ``aisoc_institutional_memory`` (so future
     investigations of similar alerts pull this up).
   * Returns *retroactive candidates* — past alerts in the same tenant
     that share the alert's signature and would now be re-dispositioned.
2. ``POST /feedback/redisposition/apply`` — analyst opts in (or auto-
   applies via UI) to update the disposition on a chosen subset of
   those candidates.
3. ``GET  /feedback/overrides`` — lists every override the agent has
   "learned" for this tenant.
4. ``GET  /feedback/summary`` — counts of dispositions for the FPR card.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select, update

from app.api.v1.deps import AuthUser, DBSession
from app.models.alert import Alert
from app.services.override_learning import (
    apply_redisposition,
    find_redisposition_candidates,
    list_overrides,
    record_override,
)

logger = structlog.get_logger()

router = APIRouter(prefix="/feedback", tags=["feedback"])

_VALID_VERDICTS = {"true_positive", "false_positive", "benign", "escalate"}


def _coerce_uuid(value: str, field: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"{field} must be a valid UUID",
        ) from exc


class AlertOverrideRequest(BaseModel):
    alert_id: str
    original_verdict: str = Field(..., description="The AI-generated verdict being overridden")
    corrected_verdict: str = Field(
        ...,
        description="Analyst's verdict: true_positive | false_positive | benign | escalate",
    )
    reason: str | None = Field(None, description="Optional free-text justification")


class RedispositionCandidateModel(BaseModel):
    alert_id: str
    title: str
    severity: str
    current_disposition: str | None
    proposed_disposition: str
    event_time: str


class AlertOverrideResponse(BaseModel):
    alert_id: str
    corrected_verdict: str
    recorded_at: str
    memory_key: str | None = None
    redisposition_candidates: list[RedispositionCandidateModel] = Field(default_factory=list)


@router.post("/alert-override", response_model=AlertOverrideResponse)
async def submit_alert_override(
    payload: AlertOverrideRequest,
    user: AuthUser,
    db: DBSession,
) -> AlertOverrideResponse:
    """Record an analyst verdict correction on an alert and surface
    retroactive re-disposition candidates."""
    if payload.corrected_verdict not in _VALID_VERDICTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"corrected_verdict must be one of: {', '.join(sorted(_VALID_VERDICTS))}",
        )
    alert_uuid = _coerce_uuid(payload.alert_id, "alert_id")

    alert = await db.scalar(
        select(Alert).where(
            Alert.id == alert_uuid,
            Alert.tenant_id == user.tenant_id,
        )
    )
    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    now = datetime.now(UTC)
    await db.execute(
        update(Alert)
        .where(Alert.id == alert_uuid, Alert.tenant_id == user.tenant_id)
        .values(disposition=payload.corrected_verdict, updated_at=now)
    )
    await db.commit()

    # Persist into institutional memory.
    signature = await record_override(
        db,
        tenant_id=user.tenant_id,
        alert=alert,
        original_verdict=payload.original_verdict,
        corrected_verdict=payload.corrected_verdict,
        analyst_id=user.user_id,
        reason=payload.reason,
    )

    # Find similar past alerts that would now disposition differently.
    candidates: list[RedispositionCandidateModel] = []
    memory_key: str | None = None
    if signature is not None:
        memory_key = signature.memory_key()
        raw_candidates = await find_redisposition_candidates(
            db,
            tenant_id=user.tenant_id,
            signature=signature,
            corrected_verdict=payload.corrected_verdict,
            exclude_alert_id=alert_uuid,
        )
        candidates = [RedispositionCandidateModel(**c.to_dict()) for c in raw_candidates]

    logger.info(
        "analyst.override",
        tenant_id=str(user.tenant_id),
        alert_id=payload.alert_id,
        analyst_id=str(user.user_id),
        original_verdict=payload.original_verdict,
        corrected_verdict=payload.corrected_verdict,
        reason=payload.reason,
        memory_key=memory_key,
        candidate_count=len(candidates),
        recorded_at=now.isoformat(),
    )

    return AlertOverrideResponse(
        alert_id=payload.alert_id,
        corrected_verdict=payload.corrected_verdict,
        recorded_at=now.isoformat(),
        memory_key=memory_key,
        redisposition_candidates=candidates,
    )


class RedispositionApplyRequest(BaseModel):
    alert_ids: list[str]
    new_disposition: str


class RedispositionApplyResponse(BaseModel):
    updated: int
    new_disposition: str


@router.post("/redisposition/apply", response_model=RedispositionApplyResponse)
async def apply_redisposition_endpoint(
    payload: RedispositionApplyRequest,
    user: AuthUser,
    db: DBSession,
) -> RedispositionApplyResponse:
    """Bulk-update the disposition on past alerts the analyst confirmed."""
    if payload.new_disposition not in _VALID_VERDICTS:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"new_disposition must be one of: {', '.join(sorted(_VALID_VERDICTS))}",
        )
    if not payload.alert_ids:
        return RedispositionApplyResponse(updated=0, new_disposition=payload.new_disposition)

    ids = [_coerce_uuid(aid, "alert_ids") for aid in payload.alert_ids]
    rowcount = await apply_redisposition(
        db,
        tenant_id=user.tenant_id,
        alert_ids=ids,
        new_disposition=payload.new_disposition,
        analyst_id=user.user_id,
    )
    return RedispositionApplyResponse(updated=rowcount, new_disposition=payload.new_disposition)


class OverrideEntryModel(BaseModel):
    key: str
    tags: list[str]
    reason: str | None
    created_at: str | None
    value: dict


@router.get("/overrides", response_model=list[OverrideEntryModel])
async def list_overrides_endpoint(
    user: AuthUser,
    db: DBSession,
    limit: int = 100,
) -> list[OverrideEntryModel]:
    """List analyst-override entries the agent has 'learned' from."""
    rows = await list_overrides(db, tenant_id=user.tenant_id, limit=limit)
    return [OverrideEntryModel(**r) for r in rows]


class OverrideSummaryResponse(BaseModel):
    total_overrides: int
    false_positive_corrections: int
    true_positive_corrections: int
    benign_corrections: int
    escalate_corrections: int


@router.get("/summary", response_model=OverrideSummaryResponse)
async def get_override_summary(
    user: AuthUser,
    db: DBSession,
) -> OverrideSummaryResponse:
    """Return a summary of analyst overrides for this tenant."""
    counts: dict[str, int] = {
        "true_positive": 0,
        "false_positive": 0,
        "benign": 0,
        "escalate": 0,
    }
    rows = await db.execute(
        select(Alert.disposition, func.count())
        .where(
            and_(
                Alert.tenant_id == user.tenant_id,
                Alert.disposition.isnot(None),
            )
        )
        .group_by(Alert.disposition)
    )
    total = 0
    for disp, cnt in rows.all():
        if disp in counts:
            counts[disp] = int(cnt or 0)
        total += int(cnt or 0)

    return OverrideSummaryResponse(
        total_overrides=total,
        false_positive_corrections=counts["false_positive"],
        true_positive_corrections=counts["true_positive"],
        benign_corrections=counts["benign"],
        escalate_corrections=counts["escalate"],
    )
