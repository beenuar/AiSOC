"""Regression tests for the realtime WS/SSE ticket flow — Issue #239.

Issue #239 closed a broken-access-control bug: ``services/realtime`` upgraded
WebSocket connections and served ``/sse`` to *any* caller. The fix mints a
short-TTL, audience-scoped HS256 ticket from ``POST /api/v1/realtime/ticket``
(signed with the shared ``AISOC_REALTIME_JWT_SECRET``, deliberately NOT
``SECRET_KEY``) which the Node edge verifies before accepting a connection.

These tests pin the API half of that contract so it cannot silently regress:

* ``realtime_ticket_secret`` resolution — configured / dev fallback / prod
  fail-closed / insecure placeholder.
* ``warn_if_insecure_defaults`` surfaces the missing secret in prod.
* ``mint_realtime_ticket`` — mints claims the Node verifier expects (aud, type,
  tenant_id, sub, exp), clamps TTL to the 60s ceiling, binds the tenant from the
  authenticated user (never the client), and fails closed with 503 when the
  shared secret is unconfigured in prod.

The Node-side signature/aud/exp verification is pinned separately in
``services/realtime/src/auth.test.ts``. The claim shape here must stay in sync
with ``RealtimeClaims`` / ``verifyRealtimeTicket`` there.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import uuid

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import realtime as realtime_ep
from app.core.config import DEV_REALTIME_TICKET_SECRET, Settings, realtime_ticket_secret, warn_if_insecure_defaults
from app.core.security import REALTIME_TICKET_AUDIENCE
from fastapi import HTTPException
from jose import jwt

# A real 64-char secret used across the "happy path" tests — anything outside
# INSECURE_SECRET_KEY_DEFAULTS and non-empty resolves as configured.
_REAL_SECRET = "r" * 64


def _settings(**overrides) -> Settings:
    """Construct Settings without reading the host .env (deterministic)."""
    base: dict = {
        "ENVIRONMENT": "production",
        "AISOC_REALTIME_JWT_SECRET": _REAL_SECRET,
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="admin",
        email="demo@example.com",
    )


# ─── realtime_ticket_secret resolution ──────────────────────────────────────


def test_secret_uses_configured_value_in_any_env():
    s = _settings(ENVIRONMENT="production", AISOC_REALTIME_JWT_SECRET=_REAL_SECRET)
    assert realtime_ticket_secret(s) == _REAL_SECRET


def test_secret_falls_back_to_dev_default_in_development():
    s = _settings(ENVIRONMENT="development", AISOC_REALTIME_JWT_SECRET="")
    assert realtime_ticket_secret(s) == DEV_REALTIME_TICKET_SECRET


def test_secret_is_none_in_prod_when_unset():
    """Production with the shared secret unset must fail closed (None)."""
    s = _settings(ENVIRONMENT="production", AISOC_REALTIME_JWT_SECRET="")
    assert realtime_ticket_secret(s) is None


def test_secret_is_none_in_prod_when_set_to_insecure_placeholder():
    """A well-known placeholder is treated as 'unset' — fail closed."""
    s = _settings(
        ENVIRONMENT="production",
        # SECRET_KEY placeholder is in INSECURE_SECRET_KEY_DEFAULTS.
        AISOC_REALTIME_JWT_SECRET="change-me-in-production-at-least-32-chars",
    )
    assert realtime_ticket_secret(s) is None


def test_missing_secret_in_prod_warns():
    s = _settings(ENVIRONMENT="production", AISOC_REALTIME_JWT_SECRET="")
    msgs = warn_if_insecure_defaults(s)
    assert any("AISOC_REALTIME_JWT_SECRET" in m for m in msgs)


def test_configured_secret_in_prod_does_not_warn():
    s = _settings(ENVIRONMENT="production", AISOC_REALTIME_JWT_SECRET=_REAL_SECRET)
    msgs = warn_if_insecure_defaults(s)
    assert not any("AISOC_REALTIME_JWT_SECRET" in m for m in msgs)


def test_missing_secret_in_dev_does_not_warn():
    """Dev has a built-in fallback, so no nag there."""
    s = _settings(ENVIRONMENT="development", AISOC_REALTIME_JWT_SECRET="")
    msgs = warn_if_insecure_defaults(s)
    assert not any("AISOC_REALTIME_JWT_SECRET" in m for m in msgs)


# ─── mint_realtime_ticket endpoint ───────────────────────────────────────────


@pytest.fixture
def configured(monkeypatch):
    """Point the endpoint module at a settings object with a real secret."""
    s = _settings(ENVIRONMENT="production", AISOC_REALTIME_JWT_SECRET=_REAL_SECRET)
    monkeypatch.setattr(realtime_ep, "settings", s)
    return s


@pytest.mark.asyncio
async def test_mint_returns_verifiable_ticket(configured):
    """The minted token must decode under the shared secret with the exact
    claims the Node verifier checks (aud, type, tenant_id, sub)."""
    tenant = uuid.uuid4()
    user = _user(tenant)

    ticket = await realtime_ep.mint_realtime_ticket(user)

    assert ticket.tenant_id == str(tenant)
    assert ticket.expires_in == configured.AISOC_REALTIME_TICKET_TTL_SECONDS

    claims = jwt.decode(
        ticket.token,
        _REAL_SECRET,
        algorithms=["HS256"],
        audience=REALTIME_TICKET_AUDIENCE,
    )
    assert claims["aud"] == REALTIME_TICKET_AUDIENCE
    assert claims["type"] == "realtime_ticket"
    assert claims["tenant_id"] == str(tenant)
    assert claims["sub"] == str(user.user_id)
    assert claims["exp"] > claims["iat"]


@pytest.mark.asyncio
async def test_mint_binds_tenant_from_user_not_client(configured):
    """Tenant is taken from the authenticated user — there is no client input
    that could smuggle a different tenant into the ticket."""
    tenant = uuid.uuid4()
    ticket = await realtime_ep.mint_realtime_ticket(_user(tenant))
    assert ticket.tenant_id == str(tenant)


@pytest.mark.asyncio
async def test_mint_rejects_foreign_audience(configured):
    """A ticket scoped to the realtime edge must not validate for any other
    audience — guards against a stolen ticket being replayed at the API."""
    ticket = await realtime_ep.mint_realtime_ticket(_user())
    with pytest.raises(jwt.JWTError):
        jwt.decode(
            ticket.token,
            _REAL_SECRET,
            algorithms=["HS256"],
            audience="some-other-service",
        )


@pytest.mark.asyncio
async def test_mint_clamps_ttl_to_60s_ceiling(monkeypatch):
    """A misconfigured long TTL can never mint a multi-minute bearer."""
    s = _settings(
        ENVIRONMENT="production",
        AISOC_REALTIME_JWT_SECRET=_REAL_SECRET,
        AISOC_REALTIME_TICKET_TTL_SECONDS=600,
    )
    monkeypatch.setattr(realtime_ep, "settings", s)
    ticket = await realtime_ep.mint_realtime_ticket(_user())
    assert ticket.expires_in == 60


@pytest.mark.asyncio
async def test_mint_fails_closed_with_503_when_secret_unconfigured(monkeypatch):
    """Production with the shared secret unset → 503, not a ticket nobody can
    verify. This is the fail-closed half of the #239 fix."""
    s = _settings(ENVIRONMENT="production", AISOC_REALTIME_JWT_SECRET="")
    monkeypatch.setattr(realtime_ep, "settings", s)

    with pytest.raises(HTTPException) as exc:
        await realtime_ep.mint_realtime_ticket(_user())

    assert exc.value.status_code == 503
    assert "AISOC_REALTIME_JWT_SECRET" in exc.value.detail


def test_endpoint_requires_authentication():
    """The route must depend on get_current_user so an unauthenticated caller
    is 401'd before any ticket is minted (the WS/SSE 401 contract starts here).
    """
    from app.api.v1.deps import get_current_user

    route = next(r for r in realtime_ep.router.routes if getattr(r, "path", None) == "/realtime/ticket")
    dep_calls = [d.call for d in route.dependant.dependencies]
    assert get_current_user in dep_calls
