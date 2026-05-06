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

from app.api.router import router
from app.db.engine import dispose_engine
from app.scheduler import ConnectorScheduler, scheduler_disabled

logger = logging.getLogger("aisoc.connectors.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start/stop the scheduler alongside the HTTP server."""
    scheduler: ConnectorScheduler | None = None
    if scheduler_disabled():
        logger.info(
            "connector.scheduler.disabled "
            "AISOC_CONNECTORS_DISABLE_SCHEDULER set; HTTP only mode"
        )
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

    try:
        yield
    finally:
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api/v1")
