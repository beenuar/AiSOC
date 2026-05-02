from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.models.alert import AnalystFeedback
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
