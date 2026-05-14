"""Honeytokens service — FastAPI application entry point."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

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

app = FastAPI(
    title="AiSOC Honeytokens Service",
    description="Generate, deploy, and manage honeytokens with first-touch alerting.",
    version="0.1.0",
)

# Honeytoken trip pixels/links are intentionally fetched from arbitrary
# origins (that's the detection), so we keep allow_credentials=False and a
# permissive default — AISOC_CORS_ORIGINS still lets operators tighten this
# per-deploy without code changes.
app.add_middleware(
    CORSMiddleware,
    **build_cors_kwargs(service_name="honeytokens", allow_credentials=False),
)

app.include_router(router)

if _otel_enabled:
    FastAPIInstrumentor.instrument_app(app)


@app.on_event("startup")
async def _startup() -> None:
    LOG.info("Honeytokens service started (OTel=%s)", _otel_enabled)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": settings.service_name}
