"""Purple Team service — FastAPI application entry point."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings

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

    _resource = Resource.create({SERVICE_NAME: settings.service_name})
    _provider = TracerProvider(resource=_resource)
    _exporter = OTLPSpanExporter(endpoint=settings.otel_endpoint, insecure=True)
    _provider.add_span_processor(BatchSpanProcessor(_exporter))
    trace.set_tracer_provider(_provider)
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
from app.api.routes import router  # noqa: E402
from app.services.scheduler import DriftScheduler  # noqa: E402

# Detection drift scheduler — owned by the FastAPI lifespan so it
# starts/stops cleanly with the service.
_drift_scheduler: DriftScheduler | None = None


@asynccontextmanager
async def _lifespan(app: FastAPI):
    global _drift_scheduler
    LOG.info("Purple Team service started (OTel=%s)", _otel_enabled)

    if settings.drift_scheduler_enabled and settings.drift_snapshot_interval_seconds > 0:
        engine = create_async_engine(settings.database_url, pool_pre_ping=True)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        _drift_scheduler = DriftScheduler(
            session_factory=session_factory,
            interval_seconds=settings.drift_snapshot_interval_seconds,
        )
        _drift_scheduler.start()
    else:
        LOG.info("Detection drift scheduler disabled by config")

    try:
        yield
    finally:
        if _drift_scheduler is not None:
            _drift_scheduler.stop()


app = FastAPI(
    title="AiSOC Purple Team Service",
    description=("Atomic Red Team execution, Caldera adversary emulation, ATT&CK coverage heatmap, and tabletop exercise simulator."),
    version="0.1.0",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

if _otel_enabled:
    FastAPIInstrumentor.instrument_app(app)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": settings.service_name}
