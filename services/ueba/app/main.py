"""UEBA FastAPI application entry-point."""

from __future__ import annotations

import asyncio
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app._health import install_health_routes
from app.core.config import settings
from app.core.cors import build_cors_kwargs

# ---------------------------------------------------------------------------
# OpenTelemetry setup (best-effort)
# ---------------------------------------------------------------------------
try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create({SERVICE_NAME: settings.service_name})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=settings.otel_endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _otel_enabled = True
except Exception:
    _otel_enabled = False

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
from app.api.routes import router  # noqa: E402  (after OTel init)

app = FastAPI(
    title="AiSOC UEBA Service",
    description="User & Entity Behaviour Analytics — baseline, anomaly scoring, peer-group analysis.",
    version="0.1.0",
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
# /readyz flips on once the Kafka consumer task is created in the
# startup hook.
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-ueba")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready

# UEBA endpoints don't carry browser session cookies (the API service does),
# so we can stay with allow_credentials=False and a permissive default. Setting
# AISOC_CORS_ORIGINS still tightens this in production deploys without code
# changes.
app.add_middleware(
    CORSMiddleware,
    **build_cors_kwargs(service_name="ueba", allow_credentials=False),
)

app.include_router(router)

if _otel_enabled:
    FastAPIInstrumentor.instrument_app(app)

# ---------------------------------------------------------------------------
# Kafka consumer lifecycle
# ---------------------------------------------------------------------------
_consumer_task: asyncio.Task | None = None  # type: ignore[type-arg]


@app.on_event("startup")
async def _start_kafka() -> None:
    global _consumer_task
    from app.services.kafka_consumer import UEBAKafkaConsumer

    consumer = UEBAKafkaConsumer()
    _consumer_task = asyncio.create_task(consumer.run(), name="ueba-kafka-consumer")
    LOG.info("UEBA service started (OTel=%s)", _otel_enabled)
    # Phase 2.6 — Kafka consumer is up; HTTP surface is serving.
    app.state.mark_ready()


@app.on_event("shutdown")
async def _stop_kafka() -> None:
    # Phase 2.6 — drain readiness before tearing the consumer down.
    app.state.mark_not_ready()
    if _consumer_task and not _consumer_task.done():
        _consumer_task.cancel()
        try:
            await _consumer_task
        except asyncio.CancelledError:
            pass  # expected after cancel(); task is done
    LOG.info("UEBA service stopped.")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": settings.service_name}
