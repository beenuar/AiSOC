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

Readiness is a question, not a latch
------------------------------------

``mark_ready()`` answers "did startup finish", and for a service
whose only job is to answer HTTP that is the whole story. For a
service whose job is to *consume a topic* it is not: three
services in this repository created the consumer as a
fire-and-forget ``asyncio.create_task`` and called
``mark_ready()`` on the next line, so readiness recorded that the
task had been **created**, never that it was still running.

UEBA is what that cost. Its handler raised
``UndefinedColumnError`` on the first scoreable event, the
exception left the ``async for``, the ``finally`` stopped the
consumer, and the task ended — holding the exception, which
nothing retrieved because the task was parked in a module global
and so never garbage-collected. The container stayed ``running``
with restarts 0, ``/health`` returned 200 and ``/readyz``
returned 200, permanently. A consumer that has silently detached
is indistinguishable from an idle one, and the whole point of a
readiness probe is to tell those two apart.

So a service that owns a subscription registers a probe for it
with :func:`register_subscription`, and ``/readyz`` evaluates
every probe on each request. A probe that returns false — or
raises — is reported as detached and ``/readyz`` answers 503 with
the names, which is a readiness failure rather than a liveness
one on purpose: the orchestrator should stop routing to a
half-working replica, and killing the process would only hide a
schema or broker fault behind a restart loop.

``/livez`` deliberately does **not** consult the probes. It
answers "is the interpreter responsive", and wiring a detached
consumer into it would make every orchestrator restart the pod on
a fault a restart cannot fix.

This module is intentionally dependency-free (only FastAPI) so it
can be vendored into every service tree without import-graph
side-effects. Each service ships its own copy under
``services/<svc>/app/_health.py`` because services don't share a
Python path; ``scripts/audit_health_probes.py --check`` is the CI
gate that every service has one and wires it in.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from fastapi import FastAPI, Response

#: Where the probes registered against an app are kept. Read by ``/readyz``,
#: written by :func:`register_subscription`. On ``app.state`` rather than in a
#: module global because a module global is shared by every app in the
#: process, which makes two test clients interfere.
_STATE_ATTR = "health_subscriptions"


def _probe_detached(probes: dict[str, Callable[[], bool]]) -> list[str]:
    """Names of the subscriptions currently reporting not-attached.

    A probe that raises counts as detached. It is asking a live object
    whether it is still working; if that question itself fails, the honest
    answer is not "yes".
    """
    detached: list[str] = []
    for name, probe in sorted(probes.items()):
        try:
            attached = bool(probe())
        except Exception:  # noqa: BLE001 — an unanswerable probe is not a healthy one
            attached = False
        if not attached:
            detached.append(name)
    return detached


def register_subscription(app: FastAPI, name: str, probe: Callable[[], bool]) -> None:
    """Make ``/readyz`` depend on *probe* returning true.

    Call this once per subscription the service owns, after
    :func:`install_health_routes`. *probe* must be cheap and non-blocking —
    it runs on every ``/readyz`` request — so it should read a flag the
    consumer maintains or check ``task.done()``, not round-trip to a broker.
    """
    probes = getattr(app.state, _STATE_ATTR, None)
    if probes is None:  # pragma: no cover — install_health_routes was not called
        raise RuntimeError("register_subscription requires install_health_routes(app) first")
    probes[name] = probe


def install_health_routes(app: FastAPI, *, service_name: str) -> tuple[Callable[[], None], Callable[[], None]]:
    """Install ``/livez`` and ``/readyz`` on ``app``.

    Returns a ``(mark_ready, mark_not_ready)`` tuple the caller
    wires into their lifespan / startup handler. The readiness
    flag defaults to False, so ``/readyz`` returns 503 until
    ``mark_ready()`` is called — exactly the right behaviour for a
    rolling deploy where the orchestrator should hold traffic
    until the pod's dependencies are connected.

    Startup having finished is necessary and not sufficient: any
    subscription registered with :func:`register_subscription`
    must also still be attached. See the module docstring.
    """
    state: dict[str, bool] = {"ready": False}
    probes: dict[str, Callable[[], bool]] = {}
    setattr(app.state, _STATE_ATTR, probes)

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
        body: dict[str, Any] = {"status": "ready", "service": service_name}
        status_code = 200

        if not state["ready"]:
            body["status"] = "starting"
            status_code = 503
        else:
            detached = _probe_detached(probes)
            if detached:
                body["status"] = "degraded"
                body["detached"] = detached
                status_code = 503

        # Named subscriptions are reported either way, so a 200 says which
        # ones were checked rather than only that nothing was wrong. A probe
        # list that is unexpectedly empty is then visible in the same place
        # the verdict is.
        if probes:
            body["subscriptions"] = sorted(probes)

        return Response(
            content=json.dumps(body),
            media_type="application/json",
            status_code=status_code,
        )

    def mark_ready() -> None:
        state["ready"] = True

    def mark_not_ready() -> None:
        state["ready"] = False

    return mark_ready, mark_not_ready
