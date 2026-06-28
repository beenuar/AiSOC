import asyncio
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI

from app._health import install_health_routes
from app.api.router import router, set_worker
from app.core.config import settings
from app.core.logging import configure_logging, logger
from app.services.confidence import ConfidenceScorer
from app.services.correlator import Correlator
from app.services.deduplicator import Deduplicator
from app.services.entity_risk import EntityRiskEngine
from app.services.fusion_engine import FusionEngine
from app.workers.consumer import FusionWorker


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    logger.info("Starting AiSOC Alert Fusion Service", port=settings.http_port)

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=False)

    dedup = Deduplicator(redis_client)
    correlator = Correlator(redis_client)
    entity_risk = EntityRiskEngine(redis_client)
    confidence_scorer = ConfidenceScorer(enabled=settings.confidence_enabled)
    engine = FusionEngine(
        dedup,
        correlator,
        entity_risk=entity_risk,
        confidence_scorer=confidence_scorer,
    )
    worker = FusionWorker(engine)
    set_worker(worker)

    # Start Kafka worker as a background task
    worker_task = asyncio.create_task(worker.start())
    app.state.worker_task = worker_task
    app.state.redis = redis_client

    # Phase 2.6 — flip /readyz to 200 now that Redis is open + the
    # Kafka consumer is running.
    app.state.mark_ready()

    logger.info("Alert Fusion Service ready")
    yield

    # Phase 2.6 — flip /readyz to 503 at the start of shutdown so the
    # orchestrator stops sending traffic before we tear Kafka down.
    app.state.mark_not_ready()

    # Shutdown
    logger.info("Shutting down Alert Fusion Service")
    await worker.stop()
    worker_task.cancel()
    await redis_client.aclose()
    logger.info("Alert Fusion Service stopped")


app = FastAPI(
    title="AiSOC Alert Fusion Service",
    description="Real-time alert deduplication and correlation engine",
    version="0.1.0",
    lifespan=lifespan,
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-fusion")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready

app.include_router(router)
