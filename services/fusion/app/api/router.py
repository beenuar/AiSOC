from fastapi import APIRouter
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
