"""The FastAPI floor is a real constraint, not a preference.

On 2026-09-24 the `One real event through the real pipeline` job failed with
`AssertionError: Status code 204 must not have a response body` raised from
`app/api/v1/endpoints/community.py:183` — a plain `@router.delete(...,
status_code=204)` on an `async def ... -> None` handler, in a file byte-
identical to `main`. It passed on re-run with no code change.

The mechanism. `community.py` carries `from __future__ import annotations`, so
the `-> None` return annotation reaches FastAPI as the *string* `"None"`.
FastAPI resolves it through `ForwardRef`, which yields `NoneType` — a class, and
therefore truthy — instead of the `None` singleton it gets without PEP 563. A
truthy `response_model` means "this route returns a body", and FastAPI asserts
that a 204 does not. 0.117.0 treats the resolved annotation as "no body" again.

Measured, not inferred. Every release from 0.111.0 through 0.116.2 raises at
import; 0.117.0 onwards does not. The declared range was `>=0.111,<0.142`, so
29 of the 120 releases it permitted could not import this service at all, and
the Dockerfile's pip fallback pinned `>=0.111,<0.112` — squarely inside the
broken band. When a transient poetry failure triggered that fallback, the image
shipped 0.111.1 and the container died on startup.

These two tests are deliberately not one. The first pins the boundary so a
Dependabot bump cannot quietly lower the floor back into the broken band. The
second exercises the shape itself, so if a future FastAPI reintroduces the
behaviour above the floor, the failure names the route rather than the version.
"""

from __future__ import annotations

import fastapi
import pytest
from fastapi import APIRouter, FastAPI

# The oldest release that imports this service. Raising this is fine; lowering
# it needs a re-measurement, because below 0.117.0 the service does not start.
MINIMUM_FASTAPI = (0, 117)


def _release(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split(".")[:2] if part.isdigit())


def test_installed_fastapi_is_at_or_above_the_measured_floor() -> None:
    installed = _release(fastapi.__version__)
    assert installed >= MINIMUM_FASTAPI, (
        f"fastapi {fastapi.__version__} is below the {'.'.join(map(str, MINIMUM_FASTAPI))} floor. "
        f"Releases in [0.111.0, 0.116.2] cannot import app.api.v1.endpoints.community — "
        f"the service will die at startup, not fail a request."
    )


def test_a_204_route_returning_none_can_be_registered() -> None:
    """The shape from community.py:183, in a module that has PEP 563 active.

    This module's own `from __future__ import annotations` is what makes the
    test faithful: without it the annotation is the `None` singleton and every
    FastAPI release accepts the route, which is exactly why the original
    triage concluded the shape was fine on 0.111 and 0.115.
    """
    router = APIRouter()

    @router.delete("/publishers/keys/{fingerprint}", status_code=204)
    async def revoke(fingerprint: str) -> None:
        return None

    app = FastAPI()
    app.include_router(router)

    # Asserted through the generated schema rather than by walking
    # `app.routes`: 0.141 stopped flattening an included router into that list
    # and leaves an opaque `_IncludedRouter` there instead, so a test that
    # walks it would pass on the floor and fail on the ceiling for a reason
    # having nothing to do with the 204 behaviour under test.
    paths = app.openapi()["paths"]
    assert "/publishers/keys/{fingerprint}" in paths, sorted(paths)
    assert "delete" in paths["/publishers/keys/{fingerprint}"]


def test_the_real_endpoint_module_imports() -> None:
    """The file the failure actually pointed at, imported for real."""
    module = pytest.importorskip("app.api.v1.endpoints.community")
    paths = {getattr(route, "path", None) for route in module.router.routes}
    assert "/community/publishers/keys/{fingerprint}" in paths, sorted(p for p in paths if p)
