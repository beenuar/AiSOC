"""
AiSOC Action Execution Service entry point.

Wires the legacy ``ActionType``-keyed router and the new ``(vendor_id,
capability)``-keyed live-actions router under ``/api/v1``. The two
layers coexist by design: the legacy router still backs the established
human-in-the-loop UI (approvals, blast-radius gates, ChatOps callbacks),
while the live-actions router exposes the generic interface that the
agent loop and plugin SDK consume.

Builtin executor adapters are registered at import time via FastAPI's
startup hook so they're available before the first request lands. We
use the startup hook (rather than module-level execution) so that test
fixtures can reset the registry between tests with
``app.live_actions.reset_for_tests()`` and re-trigger registration
without restarting the process.
"""

from __future__ import annotations

import structlog
from fastapi import FastAPI

from app._health import install_health_routes
from app.api.live_actions_router import router as live_actions_router
from app.api.router import router as legacy_router
from app.live_actions import register_builtin_executors

logger = structlog.get_logger(__name__)

app = FastAPI(
    title="AiSOC Action Execution Service",
    description=(
        "Blast-radius gated response action execution with human-in-the-loop "
        "approvals (legacy router) and the generic (vendor_id, capability) "
        "live-actions interface used by the agent loop and plugin SDK."
    ),
    version="0.2.0",
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
# /readyz flips to 200 once the builtin executor registration is
# complete (in the startup hook below).
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-actions")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready

app.include_router(legacy_router, prefix="/api/v1")
app.include_router(live_actions_router, prefix="/api/v1")


@app.on_event("startup")
async def _register_builtin_live_actions() -> None:
    """Register in-tree adapters with the live-action registry on boot.

    ``overwrite=True`` so a hot-reload (uvicorn --reload) doesn't crash
    on duplicate-registration errors. The registry's normal default of
    ``overwrite=False`` still protects plugins from clobbering each
    other.
    """
    count = register_builtin_executors(overwrite=True)
    logger.info("live_actions.bootstrap_complete", builtin_count=count)
    # Phase 2.6 — the registry is now populated, so flip /readyz on.
    app.state.mark_ready()


@app.on_event("shutdown")
async def _drain_readyz() -> None:
    """Phase 2.6 — drain /readyz at the start of shutdown so the
    orchestrator stops sending new requests while in-flight ones
    finish.
    """
    app.state.mark_not_ready()


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "aisoc-actions"}
