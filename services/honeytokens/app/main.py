"""Honeytokens service — FastAPI application entry point."""

from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app._health import install_health_routes
from app.core.config import settings
from app.core.cors import build_cors_kwargs

# OpenTelemetry moved to app/core/telemetry.py (issue #1848): the exporter
# here was built inline against settings.otel_endpoint, whose default of
# http://localhost:4317 is the service's own container, so tracing never
# reached the collector and the batch processor retried a refused connection
# every few seconds. instrument_service_app() below is guarded, quiet by default,
# and targets the compose collector when OTEL_EXPORTER=otlp is set.
from app.core.telemetry import instrument_service_app

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

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-honeytokens")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready

# Honeytoken trip pixels/links are intentionally fetched from arbitrary
# origins (that's the detection), so we keep allow_credentials=False and a
# permissive default — AISOC_CORS_ORIGINS still lets operators tighten this
# per-deploy without code changes.
app.add_middleware(
    CORSMiddleware,
    **build_cors_kwargs(service_name="honeytokens", allow_credentials=False),
)

app.include_router(router)

_otel_enabled = instrument_service_app(app, settings.service_name)


@app.on_event("startup")
async def _startup() -> None:
    LOG.info("Honeytokens service started (OTel=%s)", _otel_enabled)
    # Phase 2.6 — no async dependencies to warm up; the router is
    # immediately serviceable.
    app.state.mark_ready()

    # GHSA-9q6p-m345-h3hj (F58). A trip whose delivery failed is journalled
    # rather than lost, and this is the awaited path that empties the
    # journal. Without it the table is a record of signals nobody received,
    # which is a more honest version of the same defect but not a fix.
    from app.api.routes import _session_factory
    from app.services.outbox import drain_forever

    app.state.outbox_drain = asyncio.create_task(drain_forever(_session_factory))


@app.on_event("shutdown")
async def _shutdown() -> None:
    # Phase 2.6 — drain readiness so the orchestrator stops
    # routing traffic to a draining pod.
    app.state.mark_not_ready()

    task = getattr(app.state, "outbox_drain", None)
    if task is not None:
        task.cancel()
        # Bounded rather than a bare `await task`: a drain wedged on an
        # unresponsive receiver must not hold the pod open through its whole
        # shutdown grace period. Losing the wait costs nothing — the journal
        # is durable and the next replica drains it.
        with contextlib.suppress(asyncio.CancelledError, TimeoutError):
            await asyncio.wait_for(task, timeout=5.0)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": settings.service_name}
