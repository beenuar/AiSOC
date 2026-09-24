"""UEBA FastAPI application entry-point."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware

from app._health import install_health_routes, register_subscription
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
#
# /readyz used to flip on the moment the Kafka consumer task was *created*,
# which is not the same thing as it running: the first scoreable event raised
# UndefinedColumnError, the task ended, and this endpoint kept answering 200.
# The startup hook now registers a probe over the consumer itself, so
# readiness is re-evaluated per request instead of latched once.
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
_consumer: Any = None


def _log_consumer_exit(task: asyncio.Task) -> None:  # type: ignore[type-arg]
    """Retrieve the consumer task's outcome and say what it was.

    This callback is the reason a dead consumer is now findable. The task was
    parked in a module global, so it was never garbage-collected, so asyncio
    never emitted its "Task exception was never retrieved" warning — the
    exception that stopped UEBA from ever writing an anomaly existed only
    inside an object nobody read.
    """
    if task.cancelled():
        LOG.info("UEBA Kafka consumer task cancelled (shutdown).")
        return
    exc = task.exception()
    if exc is None:
        LOG.error(
            "UEBA Kafka consumer task ended without an error. The subscription is gone "
            "and no further events will be scored; /readyz now reports 503."
        )
        return
    LOG.error(
        "UEBA Kafka consumer task died: %s: %s. The subscription is gone and no further " "events will be scored; /readyz now reports 503.",
        type(exc).__name__,
        exc,
        exc_info=exc,
    )


@app.on_event("startup")
async def _start_kafka() -> None:
    global _consumer_task, _consumer
    from app.services.kafka_consumer import UEBAKafkaConsumer

    _consumer = UEBAKafkaConsumer()
    _consumer_task = asyncio.create_task(_consumer.run(), name="ueba-kafka-consumer")
    _consumer_task.add_done_callback(_log_consumer_exit)

    # Readiness depends on the consumer still being attached, not on this
    # function having reached its last line.
    register_subscription(app, settings.kafka_input_topic, lambda: bool(_consumer and _consumer.attached))

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
async def health() -> Response:
    """Service status, including whether the consumer is actually consuming.

    This endpoint returned a hardcoded ``{"status": "ok"}`` and so reported
    exactly the same thing whether UEBA was scoring every event or had been
    detached from its topic since the first one. It now answers 503 when the
    consumer is not attached, and carries the counters — including the last
    handler error — that say which of the two it is.
    """
    attached = bool(_consumer and _consumer.attached)
    body: dict[str, Any] = {
        "status": "ok" if attached else "degraded",
        "service": settings.service_name,
        "consumer": {
            "topic": settings.kafka_input_topic,
            "attached": attached,
            **(_consumer.stats() if _consumer else {}),
        },
    }
    if not attached:
        body["consumer"]["hint"] = (
            "the subscription is not attached — see this service's logs for the "
            "consumer task's exception, and GET /api/v1/health/dead-letters for "
            "events it refused"
        )
    return Response(
        content=json.dumps(body),
        media_type="application/json",
        status_code=200 if attached else 503,
    )
