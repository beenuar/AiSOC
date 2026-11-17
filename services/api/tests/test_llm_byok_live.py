"""Tenant BYOK through authenticated API requests, Postgres and provider HTTP.

Run with the API migration chain and both DATABASE_URL (runtime role) and
DATABASE_MIGRATION_URL (fixture owner). No app dependency, resolver, vault or
HTTP client is replaced. The local provider speaks chat completions over a
real socket; no request leaves the test host. AISOC_BYOK_LIVE_REQUIRED=1 turns
missing prerequisites into failures in integration.yml.
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import uuid
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


@pytest.fixture
def provider_http(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    requests: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            """Keep fixture credentials out of HTTP access logs."""

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": body})
            payload = json.dumps(
                {
                    "id": "byok-live-fixture",
                    "object": "chat.completion",
                    "created": 1,
                    "model": body["model"],
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
            ).encode()
            self.send_response(200 if self.path.endswith("/v1/chat/completions") else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    # The real SSRF guard supports explicit exact-host tunnel allowlisting.
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "127.0.0.1")
    monkeypatch.delenv("AISOC_SSRF_EXTRA_BLOCKED_HOSTS", raising=False)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest_asyncio.fixture
async def live_byok(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest):
    required = os.getenv("AISOC_BYOK_LIVE_REQUIRED", "").lower() not in {"", "0", "false"}
    runtime_dsn = os.getenv("DATABASE_URL", "")
    owner_dsn = os.getenv("DATABASE_MIGRATION_URL", "")
    if "postgres" not in runtime_dsn or "postgres" not in owner_dsn:
        if required:
            pytest.fail("BYOK live tests require runtime and owner PostgreSQL URLs")
        pytest.skip("requires the migrated PostgreSQL runtime/owner pair (integration.yml)")

    from app.api.v1.endpoints import llm_credentials, llm_status
    from app.core.config import settings
    from app.core.security import hash_api_key
    from app.db import database
    from app.security import credential_vault

    owner = create_async_engine(owner_dsn)
    try:
        async with owner.connect() as connection:
            await connection.execute(text("SELECT 1"))
        async with database.engine.connect() as connection:
            role = (await connection.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))).one()
            assert not role.rolsuper and not role.rolbypassrls, "code under test must use the NOBYPASSRLS runtime role"
            await connection.execute(text("SELECT tenant_id FROM tenant_llm_credentials LIMIT 0"))
    except Exception as exc:
        await owner.dispose()
        await database.engine.dispose()
        if required:
            pytest.fail(f"BYOK live prerequisites failed: {type(exc).__name__}: {exc}")
        pytest.skip(f"requires migrated PostgreSQL ({type(exc).__name__})")

    base, requests = request.getfixturevalue("provider_http")
    gateway = base + "/gateway/v1"
    tenant_endpoint = base + "/tenant/v1"
    for name in ("OPENAI_BASE_URL", "LLM_BASE_URL", "OPENAI_MODEL", "LLM_MODEL", "AISOC_LLM_MODEL", "LLM_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("LLM_GATEWAY_URL", gateway)
    monkeypatch.setenv("LITELLM_MASTER_KEY", "gateway-live-fixture-key")
    monkeypatch.setenv("OPENAI_API_KEY", "foreign-provider-fixture-key")
    monkeypatch.setenv("AISOC_AIRGAPPED", "false")
    monkeypatch.setattr(settings, "AISOC_AIRGAPPED", False)
    monkeypatch.setattr(settings, "AISOC_CREDENTIAL_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(settings, "AISOC_CREDENTIAL_KEY_ROTATION_FROM", "")
    monkeypatch.setattr(settings, "AISOC_CREDENTIAL_ENVELOPE", "off")
    credential_vault.reset_vault_for_tests()

    tenants = (uuid.uuid4(), uuid.uuid4())
    keys = tuple("aisoc_" + secrets.token_hex(32) for _ in tenants)
    async with owner.begin() as connection:
        for tenant, key in zip(tenants, keys, strict=True):
            await connection.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, 'BYOK live fixture', :slug)"),
                {"id": tenant, "slug": "byok-live-" + str(tenant)},
            )
            user_id = uuid.uuid4()
            await connection.execute(
                text(
                    "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                    "VALUES (:id, :tenant, :email, :username, '!', 'tenant_admin', TRUE)"
                ),
                {"id": user_id, "tenant": tenant, "email": f"byok-{user_id}@example.test", "username": f"byok-{user_id}"},
            )
            await connection.execute(
                text(
                    "INSERT INTO api_keys (id, tenant_id, user_id, name, key_prefix, hashed_key, scopes, is_active) "
                    "VALUES (:id, :tenant, :user_id, 'BYOK live fixture', :prefix, :hashed, CAST(:scopes AS jsonb), TRUE)"
                ),
                {
                    "id": uuid.uuid4(),
                    "tenant": tenant,
                    "user_id": user_id,
                    "prefix": key[:20],
                    "hashed": hash_api_key(key),
                    "scopes": json.dumps(["settings:read", "settings:write"]),
                },
            )

    app = FastAPI()
    app.include_router(llm_status.router, prefix="/api/v1")
    app.include_router(llm_credentials.router, prefix="/api/v1")
    assert not app.dependency_overrides
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://api.test") as client:
            yield {
                "client": client,
                "owner": owner,
                "tenants": tenants,
                "headers": [{"Authorization": "Bearer " + key} for key in keys],
                "gateway": gateway,
                "endpoint": tenant_endpoint,
                "requests": requests,
            }
    finally:
        async with owner.begin() as connection:
            for tenant in tenants:
                await connection.execute(text("DELETE FROM api_keys WHERE tenant_id = :tenant"), {"tenant": tenant})
                await connection.execute(text("DELETE FROM users WHERE tenant_id = :tenant"), {"tenant": tenant})
                await connection.execute(text("DELETE FROM tenants WHERE id = :tenant"), {"tenant": tenant})
        credential_vault.reset_vault_for_tests()
        await database.engine.dispose()
        await owner.dispose()


async def _save(fixture, **fields):
    response = await fixture["client"].put("/api/v1/llm/credentials", headers=fixture["headers"][0], json={"enabled": True, **fields})
    assert response.status_code == 200, response.text
    return response.json()


async def _status(fixture, tenant=0):
    response = await fixture["client"].get("/api/v1/llm/status", headers=fixture["headers"][tenant])
    assert response.status_code == 200, response.text
    return response.json()


async def _resolve(fixture):
    from app.db.database import AsyncSessionLocal
    from app.db.rls import set_rls_context
    from app.services.llm_resolver import resolve_llm_config

    async with AsyncSessionLocal() as session:
        await set_rls_context(session, fixture["tenants"][0])
        return await resolve_llm_config(session, fixture["tenants"][0])


@pytest.mark.asyncio
@pytest.mark.parametrize("allowlisted", [False, True])
@pytest.mark.parametrize(
    ("provider", "base_url", "model"),
    [
        ("openai", "https://api.openai.com/v1", "gpt-4o-mini"),
        ("anthropic", "https://api.anthropic.com/v1", "claude-haiku-4-5-20251001"),
    ],
)
async def test_hosted_key_only_row_drives_real_status_and_resolver(live_byok, monkeypatch, provider, base_url, model, allowlisted):
    if allowlisted:
        from app.core.config import settings

        monkeypatch.setattr(settings, "AISOC_AIRGAPPED", True)
        monkeypatch.setattr(settings, "AISOC_AIRGAP_ALLOWLIST", [f"api.{provider}.com"])
    await _save(live_byok, provider=provider, api_key="tenant-live-fixture-key")
    snap = await _status(live_byok)
    cfg = await _resolve(live_byok)
    assert (snap["base_url"], snap["model"], snap["source"], snap["key_set"]) == (base_url, model, "tenant", True)
    assert (cfg.base_url, cfg.model, cfg.api_key) == (base_url, model, "tenant-live-fixture-key")
    assert cfg.allowed
    assert snap["effective_path"] == "live" and snap["airgap_compliant"] is True
    assert "tenant-live-fixture-key" not in json.dumps(snap)
    # A second authenticated tenant has no row and retains its own baseline.
    assert (await _status(live_byok, tenant=1))["base_url"] == live_byok["gateway"]
    assert not live_byok["requests"], "resolving status must not call a provider"


@pytest.mark.asyncio
@pytest.mark.parametrize("same_gateway", [False, True])
async def test_no_stored_key_reaches_only_the_selected_endpoint(live_byok, same_gateway):
    endpoint = live_byok["gateway"] if same_gateway else live_byok["endpoint"]
    model = "aisoc-summary" if same_gateway else "local-fixture-model"
    await _save(live_byok, provider="local-litellm" if same_gateway else "local-ollama", base_url=endpoint, model=model)
    snap = await _status(live_byok)
    cfg = await _resolve(live_byok)
    assert snap["base_url"] == endpoint and snap["effective_path"] == "live"
    assert snap["key_set"] is same_gateway
    assert cfg.allowed and cfg.api_key == ("gateway-live-fixture-key" if same_gateway else None)
    result = await live_byok["client"].post("/api/v1/llm/credentials/test", headers=live_byok["headers"][0])
    assert result.status_code == 200, result.text
    assert result.json()["outcome"] == "ok", result.text
    assert len(live_byok["requests"]) == 1
    request = live_byok["requests"][0]
    assert request["path"] == ("/gateway/v1/chat/completions" if same_gateway else "/tenant/v1/chat/completions")
    assert request["body"]["model"] == model
    assert request["headers"]["authorization"] == "Bearer " + ("gateway-live-fixture-key" if same_gateway else "aisoc-no-auth")
    assert "foreign-provider-fixture-key" not in str(request)
    if not same_gateway:
        assert "gateway-live-fixture-key" not in str(request)


@pytest.mark.asyncio
async def test_real_vault_round_trip_and_corrupt_foreign_key_refusal(live_byok):
    await _save(live_byok, provider="custom", base_url=live_byok["endpoint"], model="tenant-model", api_key="tenant-live-fixture-key")
    async with live_byok["owner"].connect() as connection:
        token = (
            await connection.execute(
                text("SELECT api_key_vault FROM tenant_llm_credentials WHERE tenant_id = :tenant"), {"tenant": live_byok["tenants"][0]}
            )
        ).scalar_one()
    assert token.startswith("vault:v1:") and "tenant-live-fixture-key" not in token
    assert (await _resolve(live_byok)).api_key == "tenant-live-fixture-key"
    result = await live_byok["client"].post("/api/v1/llm/credentials/test", headers=live_byok["headers"][0])
    assert result.status_code == 200 and result.json()["outcome"] == "ok", result.text
    assert live_byok["requests"][0]["headers"]["authorization"] == "Bearer tenant-live-fixture-key"
    async with live_byok["owner"].begin() as connection:
        await connection.execute(
            text("UPDATE tenant_llm_credentials SET api_key_vault = 'vault:v1:corrupt' WHERE tenant_id = :tenant"),
            {"tenant": live_byok["tenants"][0]},
        )
    cfg = await _resolve(live_byok)
    assert not cfg.allowed and cfg.api_key is None
    snap = await _status(live_byok)
    assert snap["key_set"] is False and snap["effective_path"] == "fallback"
    result = await live_byok["client"].post("/api/v1/llm/credentials/test", headers=live_byok["headers"][0])
    assert result.status_code == 200 and result.json()["outcome"] == "refused", result.text
    assert len(live_byok["requests"]) == 1, "corrupt credentials must not trigger another provider request"


@pytest.mark.asyncio
async def test_disabled_row_returns_to_gateway_without_cross_tenant_override(live_byok):
    await _save(
        live_byok, provider="custom", base_url=live_byok["endpoint"], model="tenant-model", api_key="tenant-live-fixture-key", enabled=False
    )
    snap = await _status(live_byok)
    cfg = await _resolve(live_byok)
    assert (snap["base_url"], snap["model"], snap["source"]) == (live_byok["gateway"], "aisoc-summary", "environment")
    assert (cfg.base_url, cfg.model, cfg.api_key) == (live_byok["gateway"], "aisoc-summary", "gateway-live-fixture-key")
    assert not live_byok["requests"]


@pytest.mark.asyncio
async def test_status_redacts_saved_url_secrets_for_a_key_without_settings_scope(live_byok):
    from app.core.security import hash_api_key

    endpoint = live_byok["endpoint"].replace("http://", "http://url-user:url-secret@") + "?api_key=query-secret#fragment-secret"
    await _save(live_byok, provider="custom", base_url=endpoint, model="tenant-model", api_key="tenant-live-fixture-key")
    key = "aisoc_" + secrets.token_hex(32)
    async with live_byok["owner"].begin() as connection:
        user_id = (
            await connection.execute(text("SELECT id FROM users WHERE tenant_id = :tenant"), {"tenant": live_byok["tenants"][0]})
        ).scalar_one()
        await connection.execute(
            text(
                "INSERT INTO api_keys (id, tenant_id, user_id, name, key_prefix, hashed_key, scopes, is_active) "
                "VALUES (:id, :tenant, :user_id, 'BYOK status reader', :prefix, :hashed, CAST(:scopes AS jsonb), TRUE)"
            ),
            {
                "id": uuid.uuid4(),
                "tenant": live_byok["tenants"][0],
                "user_id": user_id,
                "prefix": key[:20],
                "hashed": hash_api_key(key),
                "scopes": json.dumps(["alerts:read"]),
            },
        )
    headers = {"Authorization": "Bearer " + key}
    credentials = await live_byok["client"].get("/api/v1/llm/credentials", headers=headers)
    assert credentials.status_code == 403
    response = await live_byok["client"].get("/api/v1/llm/status", headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["base_url"] == live_byok["endpoint"]
    for secret in ("url-user", "url-secret", "query-secret", "fragment-secret", "tenant-live-fixture-key"):
        assert secret not in response.text
    assert (await _resolve(live_byok)).base_url == endpoint
    assert not live_byok["requests"]
