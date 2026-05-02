import asyncio
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI

from app.api.router import router, set_worker
from app.core.config import settings
from app.core.logging import configure_logging, logger
from app.services.correlator import Correlator
from app.services.deduplicator import Deduplicator
from app.services.fusion_engine import FusionEngine
from app.workers.consumer import FusionWorker


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    logger.info("Starting AiSOC Alert Fusion Service", port=settings.http_port)

    redis_client = aioredis.from_url(settings.redis_url, decode_responses=False)

    dedup = Deduplicator(redis_client)
    correlator = Correlator(redis_client)
    engine = FusionEngine(dedup, correlator)
    worker = FusionWorker(engine)
    set_worker(worker)

    # Start Kafka worker as a background task
    worker_task = asyncio.create_task(worker.start())
    app.state.worker_task = worker_task
    app.state.redis = redis_client

    logger.info("Alert Fusion Service ready")
    yield

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

app.include_router(router)
