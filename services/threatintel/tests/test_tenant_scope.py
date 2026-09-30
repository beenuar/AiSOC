"""Unit tests for the vendored tenant-scope resolver.

Vendored byte-identical into each service that carries
``app/security/tenant_scope.py``, and kept in lockstep by
``scripts/sync_vendored_tenant_scope.py``. The module is the thing that
decides which tenant a request may read, so every copy is tested where it
lives rather than trusting that the one covered by ``tests/isolation`` stands
in for the other five.

The cross-service two-tenant replay lives in
``tests/isolation/test_route_tenant_scope.py``; this file covers the
credential and intersection logic on its own.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid

import pytest
from app.security import tenant_scope as ts
from fastapi import HTTPException

SECRET = "unit-test-secret-key-at-least-32-characters"
SERVICE_TOKEN = "unit-test-service-token"

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _token(
    tenant: uuid.UUID | None = TENANT_A,
    *,
    secret: str = SECRET,
    alg: str = "HS256",
    token_type: str = "access",
    ttl: int = 600,
    sub: str = "user-1",
) -> str:
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    claims: dict[str, object] = {"sub": sub, "type": token_type, "exp": int(time.time()) + ttl}
    if tenant is not None:
        claims["tenant_id"] = str(tenant)
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


@pytest.fixture(autouse=True)
def _configured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.delenv("AISOC_DEV_MODE", raising=False)
    monkeypatch.delenv(f"AISOC_{ts.SERVICE_NAME}_SERVICE_TOKEN", raising=False)


# ---------------------------------------------------------------------------
# Token verification
# ---------------------------------------------------------------------------


def test_valid_token_yields_its_tenant() -> None:
    claims = ts.verify_console_token(_token(), SECRET)
    assert claims is not None and claims["tenant_id"] == str(TENANT_A)


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [
        # An `alg: none` header is the classic downgrade: a verifier that
        # reads the header to decide how to verify must refuse anything else.
        ("alg none", {"alg": "none"}),
        ("wrong key", {"secret": "a-completely-different-secret-key-32ch"}),
        # A refresh token is long-lived by design; buying access with it would
        # make the short access-token expiry meaningless.
        ("refresh token", {"token_type": "refresh"}),
        ("expired", {"ttl": -3600}),
        ("no tenant claim", {"tenant": None}),
    ],
)
def test_unacceptable_tokens_are_refused(label: str, kwargs: dict) -> None:
    assert ts.verify_console_token(_token(**kwargs), SECRET) is None, label


@pytest.mark.parametrize("malformed", ["", "not-a-jwt", "a.b", "a.b.c.d", "...", "%%%.%%%.%%%"])
def test_malformed_tokens_are_refused(malformed: str) -> None:
    assert ts.verify_console_token(malformed, SECRET) is None


def test_no_secret_means_no_verification() -> None:
    """An unconfigured secret must not verify anything, least of all everything."""
    assert ts.verify_console_token(_token(), "") is None


@pytest.mark.parametrize("placeholder", sorted(ts.INSECURE_SECRET_DEFAULTS))
def test_placeholder_secrets_count_as_unset(placeholder: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A shipped placeholder must resolve to no secret, and so verify nothing.

    This used to assert that ``resolve_console_secret.__doc__`` was truthy and
    that each member of ``INSECURE_SECRET_DEFAULTS`` was in
    ``INSECURE_SECRET_DEFAULTS`` — a docstring standing in for behaviour, and
    a tautology. It never called ``resolve_console_secret`` with a placeholder
    at all, so it would have passed on an implementation that accepted every
    one of them.
    """
    monkeypatch.setenv("SECRET_KEY", placeholder)
    assert ts.resolve_console_secret() == "", f"{placeholder!r} was accepted as a usable secret"
    # The consequence, which is the thing that matters: a token signed with a
    # placeholder cannot buy access, because there is no secret to verify it.
    assert ts.verify_console_token(_token(secret=placeholder), ts.resolve_console_secret()) is None


def test_a_real_secret_is_returned_verbatim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", SECRET)
    assert ts.resolve_console_secret() == SECRET


@pytest.mark.parametrize("unusable", ["", "   ", "\n"])
def test_an_absent_or_blank_secret_resolves_to_nothing(unusable: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SECRET_KEY", unusable)
    assert ts.resolve_console_secret() == ""


# ---------------------------------------------------------------------------
# Intersection
# ---------------------------------------------------------------------------


def _principal(*tenants: uuid.UUID) -> ts.TenantPrincipal:
    return ts.TenantPrincipal(tenant_ids=frozenset(tenants), subject="console:test")


def test_no_request_tenant_means_the_callers_own() -> None:
    assert ts.resolve_scoped_tenant(_principal(TENANT_A)) == TENANT_A


def test_a_tenant_inside_scope_is_honoured() -> None:
    assert ts.resolve_scoped_tenant(_principal(TENANT_A, TENANT_B), TENANT_B) == TENANT_B


def test_a_tenant_outside_scope_narrows_to_nothing() -> None:
    with pytest.raises(ts.TenantScopeError):
        ts.resolve_scoped_tenant(_principal(TENANT_A), TENANT_B)


def test_empty_scope_refuses_rather_than_widening() -> None:
    """The invariant every cross-tenant leak in this codebase has broken."""
    with pytest.raises(ts.TenantScopeError):
        ts.resolve_scoped_tenant(ts.EMPTY_PRINCIPAL)
    with pytest.raises(ts.TenantScopeError):
        ts.resolve_scoped_tenant(ts.EMPTY_PRINCIPAL, TENANT_A)


def test_a_multi_tenant_caller_must_name_one() -> None:
    """Silently picking one of several would be a coin toss over customers."""
    with pytest.raises(ts.TenantScopeError):
        ts.resolve_scoped_tenant(_principal(TENANT_A, TENANT_B))


def test_a_non_uuid_request_tenant_is_refused() -> None:
    with pytest.raises(ts.TenantScopeError):
        ts.resolve_scoped_tenant(_principal(TENANT_A), "not-a-uuid")


@pytest.mark.parametrize("placeholder", ["", "  ", "default", "DEFAULT", "none", "null"])
def test_a_placeholder_means_the_caller_did_not_ask(placeholder: str) -> None:
    """A placeholder is the absence of a request, not a tenant named "default".

    Several request models default `tenant_id` to the literal `"default"`.
    That string names no tenant anywhere — migration 001 seeds the canonical
    tenant with it as a *slug* and the demo seed renames that to `demo` — so
    treating it as a requested tenant would refuse every caller who left the
    field at its default.
    """
    assert ts.resolve_scoped_tenant(_principal(TENANT_A), placeholder) == TENANT_A


def test_a_placeholder_still_cannot_widen_an_empty_scope() -> None:
    with pytest.raises(ts.TenantScopeError):
        ts.resolve_scoped_tenant(ts.EMPTY_PRINCIPAL, "default")


def test_scoped_tenant_or_403_surfaces_a_refusal_as_403() -> None:
    with pytest.raises(HTTPException) as exc:
        ts.scoped_tenant_or_403(_principal(TENANT_A), TENANT_B)
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# The dependency
# ---------------------------------------------------------------------------


# `require_console_or_service_auth` is a FastAPI dependency: its parameters
# are normally resolved by FastAPI from the request. Calling it directly means
# supplying both, including the tenant header as an explicit `None` — leaving
# it out hands the function FastAPI's `Header(...)` sentinel rather than the
# absent value the test means to describe.


@pytest.mark.asyncio
async def test_console_session_resolves_to_its_own_tenant() -> None:
    principal = await ts.require_console_or_service_auth(authorization=f"Bearer {_token()}", x_aisoc_tenant_id=None)
    assert principal.tenant_ids == frozenset({TENANT_A})
    assert principal.delegated is False


@pytest.mark.asyncio
async def test_service_token_must_declare_the_tenant_it_acts_for() -> None:
    """A service credential identifies a service, not a tenant."""
    with pytest.raises(HTTPException) as exc:
        await ts.require_console_or_service_auth(authorization=f"Bearer {SERVICE_TOKEN}", x_aisoc_tenant_id=None)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_service_token_with_a_declared_tenant_is_delegated() -> None:
    principal = await ts.require_console_or_service_auth(
        authorization=f"Bearer {SERVICE_TOKEN}",
        x_aisoc_tenant_id=str(TENANT_B),
    )
    assert principal.tenant_ids == frozenset({TENANT_B})
    assert principal.delegated is True


@pytest.mark.asyncio
async def test_a_declared_tenant_must_be_a_uuid() -> None:
    with pytest.raises(HTTPException) as exc:
        await ts.require_console_or_service_auth(
            authorization=f"Bearer {SERVICE_TOKEN}",
            x_aisoc_tenant_id="the-big-customer",
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer ", "Bearer nonsense"])
async def test_a_missing_or_unrecognised_credential_is_401(header: str | None) -> None:
    with pytest.raises(HTTPException) as exc:
        await ts.require_console_or_service_auth(authorization=header, x_aisoc_tenant_id=None)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_unconfigured_credentials_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """No credential material and no dev mode serves 503, never the route."""
    monkeypatch.setenv("SECRET_KEY", "")
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "")
    monkeypatch.delenv("AISOC_DEV_MODE", raising=False)
    with pytest.raises(HTTPException) as exc:
        await ts.require_console_or_service_auth(authorization="Bearer anything", x_aisoc_tenant_id=None)
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_dev_mode_only_applies_with_nothing_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Dev mode is a fallback for an unconfigured stack, not an auth bypass.

    With a secret configured, `AISOC_DEV_MODE` must not let an unauthenticated
    caller through — otherwise setting one flag in the wrong environment opens
    every tenant-scoped route.
    """
    monkeypatch.setenv("AISOC_DEV_MODE", "1")
    monkeypatch.setenv("AISOC_DEV_AUTH_BYPASS", "1")
    monkeypatch.delenv("AISOC_PUBLISHED_BIND_ADDRS", raising=False)
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SERVICE_TOKEN)
    with pytest.raises(HTTPException) as exc:
        await ts.require_console_or_service_auth(authorization=None, x_aisoc_tenant_id=None)
    assert exc.value.status_code == 401

    monkeypatch.setenv("SECRET_KEY", "")
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "")
    ts._BYPASS_LOGGED.clear()
    principal = await ts.require_console_or_service_auth(authorization=None, x_aisoc_tenant_id=None)
    assert principal.tenant_ids == frozenset({ts.DEV_TENANT_ID})


@pytest.mark.asyncio
async def test_dev_mode_alone_no_longer_admits_an_uncredentialed_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defect, stated as a test.

    `AISOC_DEV_MODE` selects table autocreate, docs URLs, the metrics gate,
    log formatting, the GraphiQL UI and an ephemeral vault key. It also
    defaults to `1` on ten services in `docker-compose.yml`, while nothing
    generates a service token. So a hand-copied `.env` and a plain
    `docker compose up` admitted a caller with no credential at all, and the
    only thing that had to be true for it was a flag nobody set for this
    purpose.
    """
    monkeypatch.setenv("AISOC_DEV_MODE", "1")
    monkeypatch.delenv("AISOC_DEV_AUTH_BYPASS", raising=False)
    monkeypatch.delenv("AISOC_PUBLISHED_BIND_ADDRS", raising=False)
    monkeypatch.setenv("SECRET_KEY", "")
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "")
    ts._BYPASS_LOGGED.clear()
    with pytest.raises(HTTPException) as exc:
        await ts.require_console_or_service_auth(authorization=None, x_aisoc_tenant_id=None)
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_the_bypass_is_refused_on_a_reachable_published_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An anonymous principal is a convenience only on loopback.

    The service binds `0.0.0.0` inside its container and cannot work out for
    itself whether anyone else can reach it, so compose passes the published
    addresses in. Both directions, because a check that only ever refuses is
    indistinguishable from one that removed the shim.
    """
    monkeypatch.setenv("AISOC_DEV_MODE", "1")
    monkeypatch.setenv("AISOC_DEV_AUTH_BYPASS", "1")
    monkeypatch.setenv("SECRET_KEY", "")
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "")

    for published in ("0.0.0.0", "192.168.1.10", "127.0.0.1,0.0.0.0:8080", "aisoc.example.com"):
        monkeypatch.setenv("AISOC_PUBLISHED_BIND_ADDRS", published)
        ts._BYPASS_LOGGED.clear()
        with pytest.raises(HTTPException) as exc:
            await ts.require_console_or_service_auth(authorization=None, x_aisoc_tenant_id=None)
        assert exc.value.status_code == 503, published

    for published in ("127.0.0.1", "localhost:8080", "::1", "[::1]:9000"):
        monkeypatch.setenv("AISOC_PUBLISHED_BIND_ADDRS", published)
        ts._BYPASS_LOGGED.clear()
        principal = await ts.require_console_or_service_auth(authorization=None, x_aisoc_tenant_id=None)
        assert principal.tenant_ids == frozenset({ts.DEV_TENANT_ID}), published


def test_the_dev_tenant_is_not_the_canonical_tenant() -> None:
    """The crux, and it was byte-identical.

    `DEV_TENANT_ID` was `…0001`, the tenant migration 001 seeds and that
    `bootstrap_admin` puts the real administrator into. So an unauthenticated
    caller admitted by the shim was scoped to the operator's own data rather
    than to a demo tenant.
    """
    import uuid as _uuid

    assert ts.DEV_TENANT_ID != _uuid.UUID("00000000-0000-0000-0000-000000000001")


@pytest.mark.asyncio
async def test_a_per_service_token_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"AISOC_{ts.SERVICE_NAME}_SERVICE_TOKEN", "service-specific")
    principal = await ts.require_console_or_service_auth(
        authorization="Bearer service-specific",
        x_aisoc_tenant_id=str(TENANT_A),
    )
    assert principal.delegated is True
    # The shared token must no longer be accepted once an override exists.
    with pytest.raises(HTTPException):
        await ts.require_console_or_service_auth(
            authorization=f"Bearer {SERVICE_TOKEN}",
            x_aisoc_tenant_id=str(TENANT_A),
        )
