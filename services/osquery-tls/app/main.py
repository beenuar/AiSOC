"""AiSOC osquery TLS service — FastAPI application entry point."""

from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.responses import JSONResponse

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

app.include_router(v1_router)


@app.get("/healthz", include_in_schema=False)
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})
