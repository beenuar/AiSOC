"""Every route the app publishes must be the route that answers for it.

FastAPI matches in registration order. If ``DELETE /{action}`` is registered
before ``DELETE /grants``, a request for ``/autonomy-policy/grants`` is taken
by the first route with ``action="grants"`` and the revocation handler is
simply unreachable. Nothing in review catches it: the two declarations sit
hundreds of lines apart and each is correct on its own.

That is not hypothetical here. ``DELETE /api/v1/autonomy-policy/grants`` was
unreachable from the day it shipped, so an operator could earn an autonomy
grant and had no way to hand it back: a safety control that failed in the one
direction that matters. ``GET /api/v1/assets/vulnerabilities`` had gone the
same way earlier.

Why the previous version of this file never saw either
------------------------------------------------------
It read ``app.routes`` and filtered for ``APIRoute``. On the FastAPI version
these services pin, ``include_router`` does not put routes there: it appends a
single ``_IncludedRouter`` object, and the only ``APIRoute``\\ s the list holds
are the handful of docs and probe routes the app was born with. Filtering that
list yields **zero** routes, so the check compared zero pairs, found zero
problems and reported success, over an app serving 456 operations. Run against
a newer FastAPI it failed, and the failure was real; that disagreement is the
only reason anyone looked.

So the corpus comes from ``app.openapi()``, which is what the deployed app
publishes, and reachability is decided by **sending a request** and reading
back which route Starlette matched. Both of those reflect the served app
rather than an internal list whose meaning changed under us. The same lesson
is recorded on the shadow-reconcile route test in ``services/actions``.

And because "found nothing" and "scanned nothing" print the same word, the
check refuses a corpus smaller than :data:`MINIMUM_PUBLISHED_OPERATIONS`
rather than reporting an empty app clean. That is the rule
``scripts/gate_toolkit.py`` applies to every gate under ``scripts/``; it
applies here for the same reason.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

#: The floor the corpus has to clear before any verdict is rendered. The app
#: publishes several hundred operations; the failure this guards against is
#: the corpus collapsing to the seven docs and probe routes, which is exactly
#: what happened when the inventory came from ``app.routes``. A floor cannot
#: be a target, so it sits well under the real count and is only ever tripped
#: by a collapse.
MINIMUM_PUBLISHED_OPERATIONS = 200

#: Verbs worth probing. ``head``/``options``/``trace`` are answered by
#: Starlette itself rather than by a declared handler.
PROBED_METHODS = ("get", "put", "post", "delete", "patch")

_PARAM = re.compile(r"\{[^}]+\}")


class EmptyRouteCorpus(RuntimeError):
    """Raised when there is not enough of an app to render a verdict about."""


def _shape(path: str) -> tuple[str, ...]:
    """A path reduced to which segments are literal and which are parameters.

    Compared rather than the path itself because the route object reports its
    own path without whatever prefix it was included under, so the strings
    never match even when the routes do.
    """
    return tuple("{}" if s.startswith("{") and s.endswith("}") else s for s in path.split("/") if s)


def _probe_url(path: str) -> str:
    """A concrete URL for a published path, with parameters filled in.

    The filler is alphanumeric, which satisfies every path convertor in this
    tree including the one guarding ``{action}``.
    """
    counter = 0

    def fill(_: re.Match[str]) -> str:
        nonlocal counter
        counter += 1
        return f"aisocprobe{counter}"

    return _PARAM.sub(fill, path)


class _RouteRecorder:
    """ASGI wrapper that remembers which route Starlette matched.

    ``scope`` is one dict all the way down, so the route the router records on
    it is visible again once the call returns. Routing happens before
    authentication, so a 401 still answers the only question being asked.

    ``finally``, because a handler that raises would otherwise leave the route
    unrecorded and read as unreachable.
    """

    def __init__(self, app: Any) -> None:
        self.app = app
        self.route: Any = None

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        self.route = None
        try:
            await self.app(scope, receive, send)
        finally:
            self.route = scope.get("route")


def _published_operations(app: FastAPI) -> list[tuple[str, str]]:
    return [(method, path) for path, operations in app.openapi()["paths"].items() for method in operations if method in PROBED_METHODS]


def unreachable_routes(app: FastAPI, *, minimum: int = MINIMUM_PUBLISHED_OPERATIONS) -> list[str]:
    """Every published operation that a *different* route answers for.

    Raises :class:`EmptyRouteCorpus` rather than returning ``[]`` when the app
    publishes less than ``minimum`` operations.
    """
    operations = _published_operations(app)
    if len(operations) < minimum:
        raise EmptyRouteCorpus(
            f"{len(operations)} published operation(s) is below the floor of {minimum}: "
            "refusing to report an app this small as clean, because a corpus that "
            "collapsed and a corpus with no problems are the same empty list."
        )

    recorder = _RouteRecorder(app)
    # Redirects are not followed: a handler that answers 302 would otherwise
    # have the *followed* request's route recorded over its own.
    client = TestClient(recorder, raise_server_exceptions=False, follow_redirects=False)

    problems: list[str] = []
    for method, path in operations:
        response = client.request(method.upper(), _probe_url(path))
        matched = recorder.route
        if matched is None:
            problems.append(f"{method.upper()} {path} is published but no route matched it (status {response.status_code})")
            continue
        served = _shape(getattr(matched, "path_format", ""))
        # The matched route carries no mount prefix, so compare the tail.
        declared_tail = _shape(path)[-len(served) :] if served else ()
        if served != declared_tail:
            problems.append(
                f"{method.upper()} {path} is unreachable: it is answered by "
                f"/{'/'.join(served)} ({matched.name}), which is registered first and matches it"
            )
    return problems


# ── the gate ───────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def deployed_app() -> FastAPI:
    # CI installs the full driver stack; a bare checkout may not, and the
    # synthetic cases below still give signal there.
    return pytest.importorskip("app.main", reason="full app dependencies not installed").app


def test_no_route_the_app_publishes_is_unreachable(deployed_app: FastAPI) -> None:
    problems = unreachable_routes(deployed_app)
    assert not problems, "unreachable routes found:\n  " + "\n  ".join(problems)


def test_the_corpus_is_the_deployed_app_rather_than_a_handful_of_probes(deployed_app: FastAPI) -> None:
    """The regression that made the previous gate vacuous.

    Reading ``app.routes`` here yields the docs and probe routes alone. If the
    inventory ever collapses back to that, this fails instead of the gate
    above quietly passing over nothing.
    """
    assert len(_published_operations(deployed_app)) >= MINIMUM_PUBLISHED_OPERATIONS


# ── the gate has to be able to fail ────────────────────────────────────────


def _synthetic(*, shadowed: bool) -> FastAPI:
    """The real defect, reduced: a collection behind a sibling parameter."""
    router = APIRouter(prefix="/autonomy-policy")

    if shadowed:

        @router.delete("/{action}")
        async def reset(action: str) -> dict:
            return {"action": action}

    else:

        @router.delete("/{action:autonomy_action}")
        async def reset(action: str) -> dict:  # type: ignore[misc]
            return {"action": action}

    @router.delete("/grants")
    async def revoke() -> dict:
        return {"revoked": True}

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    return app


@pytest.fixture(scope="module", autouse=True)
def _convertor_registered() -> Iterator[None]:
    # Registering the convertor is a side effect of importing the endpoint
    # module, which the synthetic control below relies on without wanting the
    # rest of the app.
    pytest.importorskip("app.api.v1.endpoints.autonomy_policy", reason="api package not importable")
    yield


def test_the_check_reports_a_shadowed_route() -> None:
    """A gate only demonstrates something if it can fail.

    Proven against the defect as it shipped: the parameterised route first,
    the collection after it.
    """
    problems = unreachable_routes(_synthetic(shadowed=True), minimum=1)
    assert len(problems) == 1, problems
    assert "DELETE /api/v1/autonomy-policy/grants is unreachable" in problems[0]
    assert "reset" in problems[0]


def test_the_check_passes_a_route_the_parameter_no_longer_swallows() -> None:
    """The control, with the declarations in the same order as the failing case.

    Only the constraint on the parameter differs, so a pass here is the
    constraint working rather than the ordering having been changed.
    """
    assert unreachable_routes(_synthetic(shadowed=False), minimum=1) == []


def test_the_check_refuses_an_app_with_nothing_in_it() -> None:
    with pytest.raises(EmptyRouteCorpus):
        unreachable_routes(FastAPI())


# ── the exclusion list cannot go stale ─────────────────────────────────────


def test_every_literal_sub_resource_of_the_autonomy_router_is_reserved() -> None:
    """The reserved set is what keeps ``{action}`` off its siblings.

    Derived from the router as it is actually served rather than read back
    from the tuple it was built from, so a sub-resource added later and not
    reserved fails here instead of becoming the next unreachable route.
    """
    autonomy_policy = pytest.importorskip("app.api.v1.endpoints.autonomy_policy")

    app = FastAPI()
    app.include_router(autonomy_policy.router)
    prefix_depth = len(_shape(autonomy_policy.router.prefix))

    literals = {
        segments[prefix_depth]
        for path in app.openapi()["paths"]
        if len(segments := _shape(path)) > prefix_depth and segments[prefix_depth] != "{}"
    }
    unreserved = literals - set(autonomy_policy.RESERVED_SEGMENTS)
    assert not unreserved, (
        f"sub-resource(s) {sorted(unreserved)} sit beside {{action}} but are not in RESERVED_SEGMENTS, so {{action}} can swallow them"
    )
