from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.models.alert import AnalystFeedback, FusedAlert, FusionDecision, RawAlert
from app.workers.consumer import FusionWorker

router = APIRouter()

_worker_ref: FusionWorker | None = None


def set_worker(worker: FusionWorker) -> None:
    global _worker_ref
    _worker_ref = worker


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-fusion"}


@router.get("/metrics")
async def metrics():
    if _worker_ref is None:
        return {"status": "worker not started"}
    return {"status": "ok", "metrics": FusionWorker.get_metrics()}


@router.get("/ml/status")
async def ml_status():
    """Return current ML model training status."""
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    return _worker_ref.engine.ml_scorer.status()


@router.post("/ml/feedback")
async def submit_feedback(feedback: AnalystFeedback):
    """Submit analyst feedback to improve ML ranker."""
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    await _worker_ref.engine.ml_scorer.record_feedback(feedback)
    return {"status": "accepted", "alert_id": str(feedback.alert_id)}


@router.post("/ml/retrain")
async def trigger_retrain():
    """Manually trigger ML model retraining."""
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    result = await _worker_ref.engine.ml_scorer.retrain()
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Risk-Based Alerting (entity rollup)
# ─────────────────────────────────────────────────────────────────────────────


def _require_entity_risk():
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    eng = _worker_ref.engine.entity_risk
    if eng is None:
        raise HTTPException(status_code=503, detail="Entity risk engine not configured")
    if not eng.enabled:
        raise HTTPException(status_code=404, detail="Entity risk engine is disabled")
    return eng


@router.get("/entity-risk/queue")
async def entity_risk_queue(
    tenant_id: UUID,
    limit: int = Query(default=25, ge=1, le=200),
    promoted_only: bool = False,
):
    """Return the top entities by current decayed risk score for a tenant.

    The entity-centric queue replaces the per-alert queue when RBA is
    enabled — analysts work the highest-risk entities and the contributing
    alerts are surfaced as evidence. Closes the 2026 KPI bar of
    ``alert-to-incident ratio ≥ 50:1``.
    """
    eng = _require_entity_risk()
    records = await eng.top_entities(tenant_id, limit=limit, promoted_only=promoted_only)
    return {
        "tenant_id": str(tenant_id),
        "threshold": eng.threshold,
        "entities": [r.to_dict() for r in records],
    }


@router.get("/entity-risk/stats")
async def entity_risk_stats(tenant_id: UUID):
    """Tenant-scoped queue stats for dashboards (banding, totals, threshold)."""
    eng = _require_entity_risk()
    return {"tenant_id": str(tenant_id), **(await eng.stats(tenant_id))}


@router.get("/entity-risk/{entity_type}/{entity_value}")
async def entity_risk_detail(entity_type: str, entity_value: str, tenant_id: UUID):
    """Return the full risk record (contributing alerts + severity histogram)
    for a single entity, used by the alert-detail drawer."""
    if entity_type == "ip":
        entity_type = "src_ip"
    eng = _require_entity_risk()
    record = await eng.get(tenant_id, entity_type, entity_value)
    if record is None:
        raise HTTPException(status_code=404, detail="entity_not_found")
    return record.to_dict()


# ─────────────────────────────────────────────────────────────────────────────
# Detection confidence + explainability (Wave 1)
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/confidence/score")
async def score_confidence(alert: RawAlert):
    """Run an alert through the confidence + explainability scorer in
    isolation and return the rationale chain.

    This is the same ``ConfidenceScorer`` that the live fusion pipeline
    uses, exposed here so the UI / detection lab can preview a confidence
    score without round-tripping through Kafka. The scorer is pure and
    stateless — no side effects on dedup / correlation / RBA state.

    Returns the projection of the alert as a ``FusedAlert``-shaped object
    where ``confidence_label`` / ``confidence_score`` /
    ``confidence_rationale`` are populated and other downstream fields
    are left at their defaults.
    """
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    scorer = _worker_ref.engine.confidence_scorer

    fused = FusedAlert(
        id=alert.id,
        tenant_id=alert.tenant_id,
        incident_id=None,
        fusion_decision=FusionDecision.NEW_INCIDENT,
        duplicate_of=None,
        alert=alert,
    )
    scored = scorer.score(fused)
    return {
        "alert_id": str(scored.id),
        "confidence_label": scored.confidence_label.value,
        "confidence_score": scored.confidence_score,
        "rationale": [f.model_dump() for f in scored.confidence_rationale],
    }
