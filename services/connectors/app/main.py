"""
AiSOC Connectors Service.

Hosts the connector catalog/test endpoints and runs the in-process
``ConnectorScheduler`` that polls every enabled connector instance on its
configured cadence.

We use FastAPI's ``lifespan`` context manager (rather than the deprecated
``@app.on_event("startup")``/``@app.on_event("shutdown")``) so the scheduler's
async lifecycle hangs off the same event loop ``uvicorn`` runs the HTTP
server on.

The scheduler is opt-out via ``AISOC_CONNECTORS_DISABLE_SCHEDULER=1`` so unit
tests, one-shot CLI entrypoints, and the schema-only catalog mode can keep
running this app without spinning up a polling loop.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app._health import install_health_routes
from app.api.router import router
from app.db.engine import dispose_engine
from app.scheduler import ConnectorScheduler, scheduler_disabled
from app.security.cors import build_cors_kwargs

logger = logging.getLogger("aisoc.connectors.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start/stop the scheduler alongside the HTTP server."""
    scheduler: ConnectorScheduler | None = None
    if scheduler_disabled():
        logger.info("connector.scheduler.disabled AISOC_CONNECTORS_DISABLE_SCHEDULER set; HTTP only mode")
    else:
        try:
            scheduler = ConnectorScheduler()
            await scheduler.start()
            app.state.scheduler = scheduler
        except Exception:
            # We deliberately let the HTTP server come up even if the
            # scheduler can't start (e.g. DATABASE_URL unset). Operators
            # can hit /health and the catalog endpoints to inspect the
            # build; the missing scheduler will show up as no polls in
            # the connectors UI rather than a refusing-to-start service.
            logger.exception("connector.scheduler.start_failed")
            scheduler = None

    # Phase 2.6 — even if the scheduler couldn't start, the HTTP
    # surface (catalog endpoints, /health) is up and serving, so
    # /readyz can return 200. If the operator needs "readyz only
    # passes when the scheduler is healthy", they should flip the
    # AISOC_CONNECTORS_DISABLE_SCHEDULER env var off and let the
    # service refuse to start on a Postgres outage instead.
    app.state.mark_ready()
    try:
        yield
    finally:
        # Phase 2.6 — drain readiness before tearing down work.
        app.state.mark_not_ready()
        if scheduler is not None:
            try:
                await scheduler.stop()
            except Exception:  # pragma: no cover - best-effort shutdown
                logger.exception("connector.scheduler.stop_failed")
        try:
            await dispose_engine()
        except Exception:  # pragma: no cover - best-effort shutdown
            logger.exception("connector.engine.dispose_failed")


app = FastAPI(
    title="AiSOC Connectors",
    description="Security source connectors: CrowdStrike, Splunk, AWS Security Hub, Okta, Microsoft Sentinel",
    version="0.1.0",
    lifespan=lifespan,
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-connectors")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready

# Before P2-A1 this service combined ``allow_origins=["*"]`` with
# ``allow_credentials=True`` — the canonical CORS misconfiguration that lets
# any origin make cookie/Authorization-bearing requests once the browser-side
# wildcard rule is bypassed. The shared helper now refuses to start with that
# combo in production (raises CORSConfigurationError) and auto-disables
# credentials with a warning in dev.
app.add_middleware(
    CORSMiddleware,
    **build_cors_kwargs(service_name="connectors", allow_credentials=True),
)

app.include_router(router, prefix="/api/v1")
