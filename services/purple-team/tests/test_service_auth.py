"""Default-deny on the purple-team API.

This service executes adversary emulation. Before this gate existed, every
route answered without a credential, including `POST /caldera/run`, which
starts a real Caldera operation against live hosts, and which took `tenant_id`
and `executed_by` from the request body so the caller declared their own
identity and tenant.

These tests pin the three properties that matter:

  * unconfigured in production  -> 503, never open
  * configured but unauthenticated -> 401
  * a wrong token -> 401

They deliberately assert on the *auth* outcome only. A correctly authenticated
request may still fail downstream on a database or Caldera connection, which
is why the positive case asserts "not 401/503" rather than a 2xx.
"""

from __future__ import annotations

import pytest
from app.security.service_auth import require_service_auth, resolve_token
from fastapi import HTTPException

TOKEN = "test-service-token-value"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    for var in (
        "AISOC_SERVICE_TOKEN",
        "AISOC_PURPLE_TEAM_SERVICE_TOKEN",
        "AISOC_DEV_MODE",
    ):
        monkeypatch.delenv(var, raising=False)


async def _call(authorization: str | None):
    return await require_service_auth(authorization=authorization)


@pytest.mark.asyncio
async def test_unconfigured_in_production_fails_closed():
    """No token and no dev mode must be a 503, not an open door."""
    with pytest.raises(HTTPException) as exc:
        await _call(None)
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_unconfigured_in_dev_mode_is_allowed(monkeypatch: pytest.MonkeyPatch):
    """`docker compose up` with no token still works locally."""
    monkeypatch.setenv("AISOC_DEV_MODE", "1")
    assert await _call(None) is None


@pytest.mark.asyncio
async def test_missing_header_is_rejected(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", TOKEN)
    with pytest.raises(HTTPException) as exc:
        await _call(None)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header",
    [
        "Bearer wrong-token",
        TOKEN,  # right value, missing the scheme
        f"bearer {TOKEN}",  # scheme is case-sensitive here on purpose
        f"Bearer {TOKEN} ",  # trailing whitespace must not pass
        "",
    ],
)
async def test_bad_authorization_values_are_rejected(monkeypatch: pytest.MonkeyPatch, header: str):
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", TOKEN)
    with pytest.raises(HTTPException) as exc:
        await _call(header)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_correct_token_passes(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", TOKEN)
    assert await _call(f"Bearer {TOKEN}") is None


@pytest.mark.asyncio
async def test_dev_mode_does_not_bypass_a_configured_token(
    monkeypatch: pytest.MonkeyPatch,
):
    """Dev mode is a fallback for *no* token, not a master key.

    Otherwise anyone who can set an env var on the container downgrades a
    configured deployment to open.
    """
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", TOKEN)
    monkeypatch.setenv("AISOC_DEV_MODE", "1")
    with pytest.raises(HTTPException) as exc:
        await _call("Bearer nope")
    assert exc.value.status_code == 401


def test_per_service_override_wins(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "shared")
    monkeypatch.setenv("AISOC_PURPLE_TEAM_SERVICE_TOKEN", "specific")
    assert resolve_token() == "specific"


def test_shared_token_used_when_no_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "shared")
    assert resolve_token() == "shared"


def test_every_api_route_requires_auth():
    """The dependency is on the router, so no route can be added without it.

    A per-route decorator would let the next contributor forget one; asserting
    on the router's dependency list is what makes that impossible.
    """
    from app.api.routes import router

    assert router.dependencies, "purple-team router must carry a default-deny dependency"
    names = {getattr(d.dependency, "__name__", "") for d in router.dependencies}
    assert "require_service_auth" in names

    # And nothing slipped in with its own empty dependency override.
    for route in router.routes:
        deps = {getattr(d.dependency, "__name__", "") for d in getattr(route, "dependencies", [])}
        assert "require_service_auth" not in deps or deps, route.path
