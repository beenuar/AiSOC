"""Route-level tenant isolation: the credential decides, not the caller.

The per-store suites in this directory prove that *if* a read is given a
tenant, it cannot see another one's rows. That leaves the question this file
answers: where did the tenant come from?

For `/fusion/entity-risk/*` the answer was "the query string", on both the API
gateway and the fusion service, with no auth dependency on either. The console
reaches fusion directly through a Next rewrite when `FUSION_URL` is set, so an
anonymous request naming any tenant UUID returned that tenant's entity-risk
queue. Storage-layer key prefixing did not help and was never going to:
`aisoc:fusion:rba:topn:{tenant}` isolates whichever tenant it is handed.

Three layers here, deliberately:

1. **Credential logic, offline.** The vendored HS256 verifier and the
   intersection rule, exercised directly. Runs everywhere, no containers.
2. **Two-tenant live replay against Redis.** Seeds A and B through the real
   `EntityRiskEngine`, then drives the real fusion router over ASGI. Skips
   cleanly without a Redis.
3. **A meta-assertion** that the repository-wide gate reports no violations,
   so a new route cannot reintroduce the shape without this suite noticing.

Every live assertion checks that the *outsider's* rows genuinely exist before
asserting they were not returned. A scoped read against an empty store passes
for the wrong reason, and that is the failure mode this comment exists to
prevent somebody reintroducing.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
FUSION_ROOT = REPO_ROOT / "services" / "fusion"
if str(FUSION_ROOT) not in sys.path:
    sys.path.insert(0, str(FUSION_ROOT))

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")

SECRET = "isolation-suite-secret-key-at-least-32-chars"
SERVICE_TOKEN = "isolation-suite-service-token"

REDIS_URL = os.getenv("AISOC_ISOLATION_REDIS_URL", "redis://localhost:6379/9")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def console_token(
    tenant: uuid.UUID | None,
    *,
    sub: str = "analyst",
    secret: str = SECRET,
    token_type: str = "access",
    alg: str = "HS256",
    ttl: int = 600,
) -> str:
    """Mint a token the way services/api's ``create_access_token`` does."""
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    claims: dict[str, object] = {"sub": sub, "type": token_type, "exp": int(time.time()) + ttl}
    if tenant is not None:
        claims["tenant_id"] = str(tenant)
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64(hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


@pytest.fixture
def scope_module(monkeypatch: pytest.MonkeyPatch):
    """The vendored resolver, with credential material configured."""
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.delenv("AISOC_DEV_MODE", raising=False)
    from app.security import tenant_scope  # noqa: PLC0415

    return tenant_scope


# ---------------------------------------------------------------------------
# Layer 1 — the credential logic, offline
# ---------------------------------------------------------------------------


def test_console_token_yields_only_its_own_tenant(scope_module) -> None:
    claims = scope_module.verify_console_token(console_token(TENANT_A), SECRET)
    assert claims is not None
    assert claims["tenant_id"] == str(TENANT_A)


@pytest.mark.parametrize(
    ("label", "token_kwargs", "secret"),
    [
        # "alg": "none" is the classic downgrade. A verifier that reads the
        # header to decide how to verify must refuse anything but HS256.
        ("alg none", {"alg": "none"}, SECRET),
        ("wrong signing key", {}, "a-different-secret-key-at-least-32-chars"),
        # A refresh token is long-lived by design; if it bought access the
        # short access-token expiry would mean nothing.
        ("refresh token", {"token_type": "refresh"}, SECRET),
        ("expired", {"ttl": -3600}, SECRET),
    ],
)
def test_unacceptable_tokens_are_refused(scope_module, label: str, token_kwargs: dict, secret: str) -> None:
    token = console_token(TENANT_A, secret=secret, **token_kwargs)
    assert scope_module.verify_console_token(token, SECRET) is None, f"{label} was accepted"


def test_token_without_a_tenant_claim_is_refused(scope_module) -> None:
    """No tenant on the token is an empty scope, never an unscoped one."""
    assert scope_module.verify_console_token(console_token(None), SECRET) is None


def test_requested_tenant_inside_scope_is_honoured(scope_module) -> None:
    principal = scope_module.TenantPrincipal(tenant_ids=frozenset({TENANT_A}), subject="console:a")
    assert scope_module.resolve_scoped_tenant(principal, TENANT_A) == TENANT_A
    assert scope_module.resolve_scoped_tenant(principal, None) == TENANT_A


def test_requested_tenant_outside_scope_narrows_to_nothing(scope_module) -> None:
    principal = scope_module.TenantPrincipal(tenant_ids=frozenset({TENANT_A}), subject="console:a")
    with pytest.raises(scope_module.TenantScopeError):
        scope_module.resolve_scoped_tenant(principal, TENANT_B)


def test_empty_scope_refuses_rather_than_widening(scope_module) -> None:
    """The invariant every cross-tenant leak here has broken."""
    with pytest.raises(scope_module.TenantScopeError):
        scope_module.resolve_scoped_tenant(scope_module.EMPTY_PRINCIPAL, None)
    with pytest.raises(scope_module.TenantScopeError):
        scope_module.resolve_scoped_tenant(scope_module.EMPTY_PRINCIPAL, TENANT_A)


# ---------------------------------------------------------------------------
# Layer 2 — two-tenant live replay against the real router
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_entity_risk_routes_refuse_a_foreign_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed A and B for real, then try to read A as B through the real routes."""
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.delenv("AISOC_DEV_MODE", raising=False)
    monkeypatch.setenv("RBA_ENABLED", "true")

    pytest.importorskip("httpx")
    pytest.importorskip("redis")
    import httpx  # noqa: PLC0415
    import redis.asyncio as aioredis  # noqa: PLC0415
    from fastapi import FastAPI  # noqa: PLC0415

    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis.ping()
    except Exception:  # noqa: BLE001
        pytest.skip(f"no Redis at {REDIS_URL}")

    from app.api import router as router_mod  # noqa: PLC0415
    from app.models.alert import AlertSeverity, RawAlert  # noqa: PLC0415
    from app.services.entity_risk import EntityRiskEngine  # noqa: PLC0415

    def alert(tenant: uuid.UUID, user: str, host: str) -> RawAlert:
        return RawAlert(
            id=uuid.uuid4(),
            tenant_id=tenant,
            title=f"seed for {user}",
            description="isolation replay",
            severity=AlertSeverity.HIGH,
            source="isolation-suite",
            username=user,
            hostname=host,
        )

    await redis.flushdb()
    engine = EntityRiskEngine(redis)
    try:
        for _ in range(3):
            await engine.observe(alert(TENANT_A, "ceo@tenant-a.test", "a-dc-01"))
        await engine.observe(alert(TENANT_B, "intern@tenant-b.test", "b-lap-09"))

        a_rows = await engine.top_entities(TENANT_A, limit=25)
        b_rows = await engine.top_entities(TENANT_B, limit=25)
        # Non-vacuity: if A has no rows, "B did not see A's rows" is trivially
        # true and proves nothing about the scoping.
        assert a_rows, "tenant A seeded no rows — the assertions below would be vacuous"
        assert b_rows, "tenant B seeded no rows — the assertions below would be vacuous"
        a_values = {r.entity_value for r in a_rows}

        class _Engine:
            entity_risk = engine

        class _Worker:
            engine = _Engine()

        monkeypatch.setattr(router_mod, "_worker_ref", _Worker())

        app = FastAPI()
        app.include_router(router_mod.router)
        transport = httpx.ASGITransport(app=app)

        async with httpx.AsyncClient(transport=transport, base_url="http://fusion.test") as client:
            path = f"/entity-risk/queue?tenant_id={TENANT_A}"

            # 1. No credential at all — the pre-fix leak.
            anon = await client.get(path)
            assert anon.status_code == 401, f"anonymous read returned {anon.status_code}: {anon.text[:200]}"

            # 2. A service token that declares no tenant. Absent is not all.
            undeclared = await client.get(path, headers={"Authorization": f"Bearer {SERVICE_TOKEN}"})
            assert undeclared.status_code == 403

            # 3. A service token acting for B, reaching for A.
            delegated = await client.get(
                path,
                headers={"Authorization": f"Bearer {SERVICE_TOKEN}", "X-AiSOC-Tenant-ID": str(TENANT_B)},
            )
            assert delegated.status_code == 403

            # 4. A console session for B, reaching for A.
            as_b = await client.get(path, headers={"Authorization": f"Bearer {console_token(TENANT_B)}"})
            assert as_b.status_code == 403, f"tenant B read tenant A's queue: {as_b.text[:300]}"

            # 5. The legitimate reads still work, and B's contains none of A's.
            own_a = await client.get("/entity-risk/queue", headers={"Authorization": f"Bearer {console_token(TENANT_A)}"})
            assert own_a.status_code == 200
            assert {e["entity_value"] for e in own_a.json()["entities"]} == a_values

            own_b = await client.get("/entity-risk/queue", headers={"Authorization": f"Bearer {console_token(TENANT_B)}"})
            assert own_b.status_code == 200
            b_seen = {e["entity_value"] for e in own_b.json()["entities"]}
            assert b_seen, "tenant B's own scoped read returned nothing — the isolation may be over-broad"
            assert not (b_seen & a_values), f"tenant A values leaked into tenant B's read: {sorted(b_seen & a_values)}"

            # 6. The other two entity-risk routes carry the same guard.
            for foreign in (
                f"/entity-risk/stats?tenant_id={TENANT_A}",
                f"/entity-risk/user/ceo@tenant-a.test?tenant_id={TENANT_A}",
            ):
                resp = await client.get(foreign, headers={"Authorization": f"Bearer {console_token(TENANT_B)}"})
                assert resp.status_code == 403, f"{foreign} returned {resp.status_code} to tenant B"
    finally:
        await redis.flushdb()
        await redis.aclose()


# ---------------------------------------------------------------------------
# Layer 3 — the repository-wide gate must stay green
# ---------------------------------------------------------------------------


def test_no_route_takes_an_unscoped_tenant_identifier() -> None:
    """Run the AST gate over the tree so a new route cannot reintroduce this."""
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "check_route_tenant_scope.py")],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, f"check_route_tenant_scope reported violations:\n{result.stdout}\n{result.stderr}"


def test_the_gate_itself_detects_injected_drift() -> None:
    """A gate nobody has seen fail is indistinguishable from one that cannot."""
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "check_route_tenant_scope.py"), "--self-test"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, f"gate self-test failed:\n{result.stdout}\n{result.stderr}"


def test_vendored_tenant_scope_copies_have_not_drifted() -> None:
    """Six services carry this verifier; a fix in one is a fix in none."""
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "sync_vendored_tenant_scope.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, f"vendored copies drifted:\n{result.stdout}\n{result.stderr}"
