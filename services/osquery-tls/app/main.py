"""AiSOC osquery TLS service — FastAPI application entry point."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app._health import install_health_routes
from app.api.v1 import router as v1_router
from app.core.config import settings

logging.basicConfig(level=getattr(logging, settings.log_level.upper(), logging.INFO))

app = FastAPI(
    title="AiSOC osquery TLS",
    description=(
        "Implements the osquery TLS plugin spec so osqueryd agents can be pointed at AiSOC directly, without a separate fleet manager."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
# osquery TLS endpoints are stateless config / log relays, so we
# can flip /readyz on immediately at import time — there's no
# async warm-up to wait for.
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-osquery-tls")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready


@app.on_event("startup")
async def _osquery_tls_ready() -> None:
    app.state.mark_ready()


@app.on_event("shutdown")
async def _osquery_tls_draining() -> None:
    app.state.mark_not_ready()


app.include_router(v1_router)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})
