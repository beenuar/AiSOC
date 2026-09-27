"""The MCP server registry: what it refuses, what it hides, and who may read it.

Gap-closure Phase 5.2 gate.

Four properties, each asserted by name below:

* a target that could never be safe is refused at save time, with a message
  an operator can act on
* the defaults are closed: a server saved with no further thought is disabled
  and advertises no tool at all
* a credential is vault ciphertext at rest and never leaves on a console
  response; only the service path gets plaintext, and only for the tenant it
  named
* the internal route is reachable, is service-token only, and refuses a
  console session even though that session is perfectly valid

The database is a real one. Postgres-only column types compile down to their
SQLite equivalents the way ``test_bootstrap_admin.py`` already does, so these
exercise the real statements rather than a stub that agrees with them.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import mcp_servers as endpoint_module
from app.api.v1.endpoints.mcp_servers import router as mcp_router
from app.db.database import Base, get_db
from app.db.rls import get_tenant_db
from app.models.mcp_server import McpServer
from app.security.credential_vault import reset_vault_for_tests
from app.services.mcp_registry import (
    McpRegistryError,
    create_server,
    delete_server,
    list_servers,
    resolve_servers_for_agent,
    update_server,
    validate_target,
)
from cryptography.fernet import Fernet
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

TENANT = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
OTHER_TENANT = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")
USER = uuid.UUID("11111111-1111-1111-1111-111111111111")

SERVICE_TOKEN = "service-token-for-the-agents-worker"


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


# Two real Fernet keys, generated per run rather than written down.
#
# They have to be *valid*: an invalid key makes the vault fall back to an
# ephemeral process-local one, which would let the "credential will not
# decrypt" test below pass for the wrong reason. Generating them keeps a
# secret-shaped literal out of the tree entirely, which is better than
# explaining one to the secret scanner, and the two are distinct by
# construction rather than by somebody checking.
VAULT_KEY = Fernet.generate_key().decode()
OTHER_VAULT_KEY = Fernet.generate_key().decode()


@pytest.fixture(autouse=True)
def _vault_key(monkeypatch):
    """A deterministic vault key, and no leakage between tests."""
    monkeypatch.setenv("AISOC_CREDENTIAL_KEY", VAULT_KEY)
    reset_vault_for_tests()
    yield
    reset_vault_for_tests()


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        # Only this table. A whole-metadata create_all drags in models using
        # Postgres ARRAY, which SQLite cannot render. The FKs to tenants and
        # users are not created here, which is why the rows below carry bare
        # UUIDs: this exercises the registry's own statements, not referential
        # integrity, which the migration's own constraints hold.
        await conn.run_sync(Base.metadata.create_all, tables=[McpServer.__table__])
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


# ---------------------------------------------------------------------------
# What is refused, and why
# ---------------------------------------------------------------------------


class TestTargetRefusals:
    """Structural refusals at save time.

    This is not the SSRF control. That one resolves DNS and lives in the
    agents service immediately before the socket opens, because a name that
    resolved publicly at save time can resolve to link-local an hour later.
    What these prove is that an operator gets an immediate, readable refusal
    for the targets that are wrong on their face.
    """

    @pytest.mark.parametrize(
        ("url", "fragment"),
        [
            ("http://169.254.169.254/mcp", "metadata"),
            ("https://metadata.google.internal/mcp", "metadata"),
            ("http://127.0.0.1/mcp", "not an address"),
            ("http://[::1]/mcp", "not an address"),
            ("file:///etc/passwd", "scheme"),
            ("ftp://vendor.example/mcp", "scheme"),
            ("https://user:pw@vendor.example/mcp", "userinfo"),
            ("https:///mcp", "hostname"),
            ("", "needs a URL"),
        ],
    )
    def test_a_target_that_could_never_be_safe_is_refused(self, url: str, fragment: str) -> None:
        with pytest.raises(McpRegistryError) as exc:
            validate_target(transport="streamable_http", url=url, command=None)
        assert fragment in str(exc.value)

    def test_a_public_https_target_passes(self) -> None:
        validate_target(transport="streamable_http", url="https://mcp.vendor.example/mcp", command=None)

    def test_the_transports_cannot_be_mixed(self) -> None:
        with pytest.raises(McpRegistryError, match="has no command"):
            validate_target(transport="streamable_http", url="https://vendor.example/mcp", command="/usr/bin/vendor-mcp")
        with pytest.raises(McpRegistryError, match="has no URL"):
            validate_target(transport="stdio", url="https://vendor.example/mcp", command="/usr/bin/vendor-mcp")

    def test_an_unknown_transport_is_refused(self) -> None:
        with pytest.raises(McpRegistryError, match="transport must be one of"):
            validate_target(transport="websocket", url="https://vendor.example/mcp", command=None)

    def test_air_gap_mode_refuses_a_public_server(self, monkeypatch) -> None:
        """Air-gap is a deployment posture, and a third-party MCP server is egress."""
        from app.core import airgap as airgap_module

        monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True, raising=False)
        with pytest.raises(McpRegistryError):
            validate_target(transport="streamable_http", url="https://mcp.vendor.example/mcp", command=None)

    def test_air_gap_mode_still_permits_an_internal_server(self, monkeypatch) -> None:
        from app.core import airgap as airgap_module

        monkeypatch.setattr(airgap_module.settings, "AISOC_AIRGAPPED", True, raising=False)
        validate_target(transport="streamable_http", url="https://mcp.corp.internal/mcp", command=None)


class TestValueRefusals:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", ["", "a", "vendor server", "vendor/../etc", "-vendor", "vendor-", "vendor.example"])
    async def test_a_name_that_could_not_be_a_tool_name_is_refused(self, session_factory, name: str) -> None:
        async with session_factory() as db:
            with pytest.raises(McpRegistryError, match="name must be"):
                await create_server(db, tenant_id=TENANT, created_by=USER, name=name, url="https://vendor.example/mcp")

    @pytest.mark.asyncio
    async def test_a_name_is_normalised_to_the_case_the_tool_id_will_carry(self, session_factory) -> None:
        """``mcp.<name>.<tool>`` is one string, so the stored name is the one the model sees."""
        async with session_factory() as db:
            row = await create_server(db, tenant_id=TENANT, created_by=USER, name="  Vendor_MCP  ", url="https://vendor.example/mcp")
            await db.commit()
        assert row.name == "vendor_mcp"

    @pytest.mark.asyncio
    async def test_an_allowlist_entry_that_is_not_a_tool_name_is_refused_not_trimmed(self, session_factory) -> None:
        """A dropped typo is an allowlist wider than the operator believes."""
        async with session_factory() as db:
            with pytest.raises(McpRegistryError, match="is not a tool name"):
                await create_server(
                    db,
                    tenant_id=TENANT,
                    created_by=USER,
                    name="vendor",
                    url="https://vendor.example/mcp",
                    tool_allowlist=["get_host", "drop table alerts"],
                )

    @pytest.mark.asyncio
    async def test_bounds_are_refused_outside_their_range(self, session_factory) -> None:
        async with session_factory() as db:
            with pytest.raises(McpRegistryError, match="timeout_seconds"):
                await create_server(
                    db, tenant_id=TENANT, created_by=USER, name="vendor", url="https://vendor.example/mcp", timeout_seconds=0
                )
            with pytest.raises(McpRegistryError, match="max_response_bytes"):
                await create_server(
                    db,
                    tenant_id=TENANT,
                    created_by=USER,
                    name="vendor",
                    url="https://vendor.example/mcp",
                    max_response_bytes=64 * 1024 * 1024,
                )

    @pytest.mark.asyncio
    async def test_a_duplicate_name_within_a_tenant_is_refused(self, session_factory) -> None:
        async with session_factory() as db:
            await create_server(db, tenant_id=TENANT, created_by=USER, name="vendor", url="https://vendor.example/mcp")
            await db.commit()
        async with session_factory() as db:
            with pytest.raises(McpRegistryError, match="already registered"):
                await create_server(db, tenant_id=TENANT, created_by=USER, name="vendor", url="https://other.example/mcp")

    @pytest.mark.asyncio
    async def test_the_same_name_in_another_tenant_is_fine(self, session_factory) -> None:
        async with session_factory() as db:
            await create_server(db, tenant_id=TENANT, created_by=USER, name="vendor", url="https://vendor.example/mcp")
            await create_server(db, tenant_id=OTHER_TENANT, created_by=USER, name="vendor", url="https://vendor.example/mcp")
            await db.commit()
        async with session_factory() as db:
            assert len(await list_servers(db, TENANT)) == 1
            assert len(await list_servers(db, OTHER_TENANT)) == 1


# ---------------------------------------------------------------------------
# Closed defaults
# ---------------------------------------------------------------------------


class TestClosedDefaults:
    @pytest.mark.asyncio
    async def test_a_server_saved_with_no_further_thought_advertises_nothing(self, session_factory) -> None:
        """Registering is not the same decision as reaching."""
        async with session_factory() as db:
            row = await create_server(db, tenant_id=TENANT, created_by=USER, name="vendor", url="https://vendor.example/mcp")
            await db.commit()
        assert row.enabled is False
        assert row.tool_allowlist == []
        assert row.transport == "streamable_http"
        assert row.timeout_seconds == 20
        assert row.max_response_bytes == 65536

    @pytest.mark.asyncio
    async def test_a_disabled_server_is_not_resolved_for_the_agent(self, session_factory) -> None:
        async with session_factory() as db:
            await create_server(
                db,
                tenant_id=TENANT,
                created_by=USER,
                name="vendor",
                url="https://vendor.example/mcp",
                tool_allowlist=["get_host"],
                enabled=False,
            )
            await db.commit()
        async with session_factory() as db:
            assert await resolve_servers_for_agent(db, TENANT) == []

    @pytest.mark.asyncio
    async def test_an_enabled_server_resolves_with_its_bounds(self, session_factory) -> None:
        async with session_factory() as db:
            await create_server(
                db,
                tenant_id=TENANT,
                created_by=USER,
                name="vendor",
                url="https://vendor.example/mcp",
                credential={"authorization": "Bearer vendor-secret"},
                tool_allowlist=["get_host", "get_host", "get_detections"],
                timeout_seconds=7,
                max_response_bytes=4096,
                enabled=True,
            )
            await db.commit()
        async with session_factory() as db:
            resolved = await resolve_servers_for_agent(db, TENANT)
        assert len(resolved) == 1
        server = resolved[0]
        assert server.name == "vendor"
        # Duplicates dropped, operator order preserved.
        assert server.tool_allowlist == ["get_host", "get_detections"]
        assert server.timeout_seconds == 7
        assert server.max_response_bytes == 4096
        assert server.auth == {"authorization": "Bearer vendor-secret"}


# ---------------------------------------------------------------------------
# The credential
# ---------------------------------------------------------------------------


class TestCredentialHandling:
    @pytest.mark.asyncio
    async def test_the_credential_is_ciphertext_at_rest(self, session_factory) -> None:
        async with session_factory() as db:
            row = await create_server(
                db,
                tenant_id=TENANT,
                created_by=USER,
                name="vendor",
                url="https://vendor.example/mcp",
                credential={"authorization": "Bearer vendor-secret"},
            )
            await db.commit()
        stored = row.auth_config["authorization"]
        assert stored.startswith("vault:")
        assert "vendor-secret" not in stored

    @pytest.mark.asyncio
    async def test_a_row_whose_credential_will_not_decrypt_is_dropped_not_downgraded(self, session_factory, monkeypatch) -> None:
        """An unauthenticated call the operator believes is authenticated is worse than none.

        The vendor's 401 would reach the agent as "that tool is unavailable",
        which is indistinguishable from the tool not existing.
        """
        async with session_factory() as db:
            await create_server(
                db,
                tenant_id=TENANT,
                created_by=USER,
                name="vendor",
                url="https://vendor.example/mcp",
                credential={"authorization": "Bearer vendor-secret"},
                enabled=True,
            )
            await create_server(
                db,
                tenant_id=TENANT,
                created_by=USER,
                name="healthy",
                url="https://healthy.example/mcp",
                enabled=True,
            )
            await db.commit()

        # Rotate the key out from under the stored ciphertext.
        monkeypatch.setenv("AISOC_CREDENTIAL_KEY", OTHER_VAULT_KEY)
        reset_vault_for_tests()

        async with session_factory() as db:
            resolved = await resolve_servers_for_agent(db, TENANT)
        # The unreadable row is gone; the one beside it still resolves, so one
        # bad credential does not take a tenant's whole MCP surface down.
        assert [s.name for s in resolved] == ["healthy"]

    @pytest.mark.asyncio
    async def test_updating_a_credential_re_encrypts_and_leaves_the_rest(self, session_factory) -> None:
        async with session_factory() as db:
            row = await create_server(
                db,
                tenant_id=TENANT,
                created_by=USER,
                name="vendor",
                url="https://vendor.example/mcp",
                credential={"authorization": "Bearer first"},
                tool_allowlist=["get_host"],
            )
            await db.commit()
            server_id = row.id
        async with session_factory() as db:
            updated = await update_server(
                db, tenant_id=TENANT, server_id=server_id, changes={"credential": {"authorization": "Bearer second"}}
            )
            await db.commit()
        assert updated.tool_allowlist == ["get_host"]
        assert "second" not in updated.auth_config["authorization"]
        async with session_factory() as db:
            await update_server(db, tenant_id=TENANT, server_id=server_id, changes={"enabled": True})
            await db.commit()
        async with session_factory() as db:
            resolved = await resolve_servers_for_agent(db, TENANT)
        assert resolved[0].auth == {"authorization": "Bearer second"}

    @pytest.mark.asyncio
    async def test_another_tenants_row_is_not_updatable_or_deletable(self, session_factory) -> None:
        async with session_factory() as db:
            row = await create_server(db, tenant_id=TENANT, created_by=USER, name="vendor", url="https://vendor.example/mcp")
            await db.commit()
            server_id = row.id
        async with session_factory() as db:
            with pytest.raises(McpRegistryError, match="no such MCP server"):
                await update_server(db, tenant_id=OTHER_TENANT, server_id=server_id, changes={"enabled": True})
            assert await delete_server(db, tenant_id=OTHER_TENANT, server_id=server_id) is False
            assert await delete_server(db, tenant_id=TENANT, server_id=server_id) is True


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_set_config(monkeypatch):
    """SQLite has no ``set_config``, and RLS is not what these tests measure.

    The tenant predicate these routes rely on is in the WHERE clause, which
    SQLite executes exactly as Postgres would. The RLS policy behind it is
    proven by ``check_rls_policy_shape.py`` over the migration and by the
    live-container isolation suite; asserting it here would need a Postgres.
    """

    async def _noop(_session, _tenant_id):
        return None

    monkeypatch.setattr(endpoint_module, "set_rls_context", _noop)


def _app(session_factory, *, user: CurrentUser | None) -> FastAPI:
    app = FastAPI()
    app.include_router(mcp_router, prefix="/api/v1")

    async def _db():
        async with session_factory() as session:
            yield session

    # Both, deliberately. ``TenantDBSession`` resolves through ``get_tenant_db``
    # rather than ``get_db``, so overriding only the latter leaves the console
    # routes reaching for a real Postgres.
    app.dependency_overrides[get_db] = _db
    app.dependency_overrides[get_tenant_db] = _db
    if user is not None:
        app.dependency_overrides[get_current_user] = lambda: user
    return app


def _console_user() -> CurrentUser:
    return CurrentUser(user_id=USER, tenant_id=TENANT, role="tenant_admin", email="admin@example.invalid", scopes=["*"])


class TestRoutes:
    @pytest.mark.asyncio
    async def test_the_console_never_sees_the_credential(self, session_factory) -> None:
        async with session_factory() as db:
            await create_server(
                db,
                tenant_id=TENANT,
                created_by=USER,
                name="vendor",
                url="https://vendor.example/mcp",
                credential={"authorization": "Bearer vendor-secret"},
            )
            await db.commit()

        body = TestClient(_app(session_factory, user=_console_user())).get("/api/v1/mcp-servers").json()
        assert body["read_only_by_default"] is True
        assert body["servers"][0]["has_credential"] is True
        assert "vendor-secret" not in str(body)
        assert "auth_config" not in body["servers"][0]
        assert "vault:" not in str(body)

    @pytest.mark.asyncio
    async def test_the_internal_route_is_reachable_and_is_not_shadowed(self, session_factory, monkeypatch) -> None:
        """Assert by sending a request.

        ``include_router`` does not populate ``routes[].path`` on the pinned
        FastAPI, so a route inventory read off the router measures nothing.
        This also fails if a later ``GET /{server_id}`` is declared above
        ``/resolved`` and swallows it, which would turn the agent's only way
        to learn its servers into a 422 about a malformed UUID.
        """
        monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)
        async with session_factory() as db:
            await create_server(
                db,
                tenant_id=TENANT,
                created_by=USER,
                name="vendor",
                url="https://vendor.example/mcp",
                credential={"authorization": "Bearer vendor-secret"},
                tool_allowlist=["get_host"],
                enabled=True,
            )
            await db.commit()

        client = TestClient(_app(session_factory, user=None))
        response = client.get(
            "/api/v1/mcp-servers/resolved",
            params={"tenant_id": str(TENANT)},
            headers={"X-AiSOC-Service-Token": SERVICE_TOKEN},
        )
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["servers"][0]["auth"] == {"authorization": "Bearer vendor-secret"}

    @pytest.mark.asyncio
    async def test_the_internal_route_refuses_without_the_token(self, session_factory, monkeypatch) -> None:
        monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)
        client = TestClient(_app(session_factory, user=None))
        assert client.get("/api/v1/mcp-servers/resolved", params={"tenant_id": str(TENANT)}).status_code == 401
        assert (
            client.get(
                "/api/v1/mcp-servers/resolved",
                params={"tenant_id": str(TENANT)},
                headers={"X-AiSOC-Service-Token": "wrong"},
            ).status_code
            == 401
        )

    @pytest.mark.asyncio
    async def test_an_unset_service_token_shuts_the_internal_route_rather_than_opening_it(self, session_factory, monkeypatch) -> None:
        """The familiar failure: empty configured secret compared against an absent header."""
        monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
        client = TestClient(_app(session_factory, user=None))
        assert client.get("/api/v1/mcp-servers/resolved", params={"tenant_id": str(TENANT)}).status_code == 401
        assert (
            client.get(
                "/api/v1/mcp-servers/resolved",
                params={"tenant_id": str(TENANT)},
                headers={"X-AiSOC-Service-Token": ""},
            ).status_code
            == 401
        )

    @pytest.mark.asyncio
    async def test_a_valid_console_session_is_still_refused_plaintext(self, session_factory, monkeypatch) -> None:
        """No session fallback on this one route, unlike every other dual-mode route.

        A console user who can read their tenant's alerts must not thereby be
        able to read the bearer token their operator configured for a vendor.
        """
        monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)
        client = TestClient(_app(session_factory, user=_console_user()))
        assert client.get("/api/v1/mcp-servers/resolved", params={"tenant_id": str(TENANT)}).status_code == 401

    @pytest.mark.asyncio
    async def test_the_internal_route_requires_a_named_tenant(self, session_factory, monkeypatch) -> None:
        """Omitting it must not read as "every tenant" on a route returning credentials."""
        monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", SERVICE_TOKEN)
        client = TestClient(_app(session_factory, user=None))
        response = client.get("/api/v1/mcp-servers/resolved", headers={"X-AiSOC-Service-Token": SERVICE_TOKEN})
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_creating_through_the_route_refuses_a_metadata_target(self, session_factory) -> None:
        client = TestClient(_app(session_factory, user=_console_user()))
        response = client.post(
            "/api/v1/mcp-servers",
            json={"name": "vendor", "url": "http://169.254.169.254/mcp"},
        )
        assert response.status_code == 422
        assert "metadata" in response.json()["detail"]
