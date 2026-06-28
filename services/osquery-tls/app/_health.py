"""
Phase 2.6 — shared liveness + readiness probes for AiSOC FastAPI
services.

The "liveness vs readiness" distinction is the single most-missed
detail in self-deployed Python services. The two checks answer
DIFFERENT questions and k8s (and any sensible load balancer)
treats the answers differently:

  * ``/livez``  — "is this process still running?". Returns 200 if
                  the Python interpreter is responsive. Failure here
                  means the orchestrator should RESTART the pod —
                  not pull it from the load balancer, but kill it
                  and reschedule.

  * ``/readyz`` — "is this process ready to accept traffic?".
                  Returns 200 ONLY after the lifespan startup hook
                  has finished. Failure here means the orchestrator
                  should NOT send traffic to this pod (yet) — but
                  should NOT kill it.

When a service ships only ``/healthz`` (or a single ``/health``)
and the orchestrator wires it as the liveness probe, the service
gets killed and restarted any time a dependency hiccups. When it's
wired as the readiness probe, the orchestrator never restarts
genuinely-stuck pods. You want BOTH, with different semantics.

Usage::

    from app._health import install_health_routes

    app = FastAPI(...)
    mark_ready, mark_not_ready = install_health_routes(
        app, service_name="aisoc-fusion"
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ... startup work ...
        mark_ready()
        try:
            yield
        finally:
            mark_not_ready()
            ... shutdown work ...

Services using the deprecated ``@app.on_event("startup")`` /
``@app.on_event("shutdown")`` hooks call ``mark_ready()`` /
``mark_not_ready()`` from those handlers respectively.

This module is intentionally dependency-free (only FastAPI) so it
can be vendored into every service tree without import-graph
side-effects. Each service ships its own copy under
``services/<svc>/app/_health.py`` because services don't share a
Python path — keep the file in sync via
``scripts/sync_health_module.py`` (CI gate).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Response


def install_health_routes(app: FastAPI, *, service_name: str) -> tuple[Callable[[], None], Callable[[], None]]:
    """Install ``/livez`` and ``/readyz`` on ``app``.

    Returns a ``(mark_ready, mark_not_ready)`` tuple the caller
    wires into their lifespan / startup handler. The readiness
    flag defaults to False, so ``/readyz`` returns 503 until
    ``mark_ready()`` is called — exactly the right behaviour for a
    rolling deploy where the orchestrator should hold traffic
    until the pod's dependencies are connected.
    """
    state: dict[str, bool] = {"ready": False}

    @app.get(
        "/livez",
        tags=["system"],
        include_in_schema=False,
    )
    async def _livez() -> dict[str, Any]:
        return {"status": "alive", "service": service_name}

    @app.get(
        "/readyz",
        tags=["system"],
        include_in_schema=False,
    )
    async def _readyz() -> Response:
        if state["ready"]:
            return Response(
                content='{"status":"ready","service":"' + service_name + '"}',
                media_type="application/json",
                status_code=200,
            )
        return Response(
            content='{"status":"starting","service":"' + service_name + '"}',
            media_type="application/json",
            status_code=503,
        )

    def mark_ready() -> None:
        state["ready"] = True

    def mark_not_ready() -> None:
        state["ready"] = False

    return mark_ready, mark_not_ready
