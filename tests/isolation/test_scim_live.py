"""SCIM provisioning against the real application and a real Postgres.

Maturity: the evidence that takes **SCIM 2.0, white-label, usage
metering** to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

Why the offline suite is not enough
------------------------------------
`services/api/tests/test_scim_provisioning.py` is 40 good tests and two
things about its harness make it unable to certify this capability:

**It runs on `sqlite+aiosqlite:///:memory:` with `@compiles` shims** that
translate `JSONB`, `UUID`, `INET` and `ARRAY` into something SQLite will
accept. Those four types are where Postgres and SQLite disagree most, and
a shim that makes a column *accept* a value is not evidence the real
column stores or queries it. This repository has already shipped one
defect of exactly that shape — a query naming two columns the table does
not have, green across thirty tests against a fake.

**It builds its own `FastAPI()` and mounts the router alone.** So the
production middleware stack, the exception handlers and the real
dependency overrides are not what the assertions run through. A 401 that
the app's own handler would turn into a SCIM-shaped error body is not
exercised.

This suite uses `app.main:create_application` and real Postgres, so the
types, the constraints, the middleware and the auth are the ones a
deployment runs.

The negative control
--------------------
`test_an_unauthenticated_request_is_refused` and
`test_another_tenants_token_cannot_read_these_users` are what stop the
positive assertions passing for the wrong reason: a surface that returned
everything to everyone would satisfy "the user I created is listed".
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

# One event loop for the whole module, and the application built once in
# it.
#
# `create_application()` opens engines bound to the loop that built it.
# With a loop per test, the second test closes the first loop while the
# first app's pool still holds connections, and every subsequent test
# dies with "Event loop is closed" — a message about the harness that
# says nothing about the code. Each test still gets its own tenants, so
# they remain independent of one another.
# Skip as a *module*, not only in the fixture.
#
# The offline isolation job collects this directory with no stores
# running. With the skip only in the fixture, any test that does not take
# it ran anyway and failed there — which is a failure about the harness,
# reported against a capability.
pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_SCIM_DSN", "").strip(),
        reason="ISOLATION_SCIM_DSN is not set; this suite needs live infrastructure",
    ),
]

SCIM_CONTENT_TYPE = "application/scim+json"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_SCIM_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_SCIM_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client():
    """The real application, against real Postgres.

    `create_application()` rather than a bare `FastAPI()` with the router
    mounted: the middleware, the exception handlers and the dependency
    graph are part of what a SCIM client talks to, and a harness that
    skips them is testing a different surface.
    """
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    os.environ.setdefault("ENVIRONMENT", "development")

    import httpx
    from app.main import create_application

    application = create_application()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def db():
    """One SQLAlchemy engine for setup and for verification.

    An asyncpg pool beside a SQLAlchemy engine looks tidier and is not:
    under pytest-asyncio the two end up bound to different event loops,
    and the teardown of one fails with "Event loop is closed" while
    telling you nothing about the code under test.
    """
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_dsn(), future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _tenant(session) -> str:  # noqa: ANN001
    import sqlalchemy

    tenant_id = uuid.uuid4()
    await session.execute(
        sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s) ON CONFLICT DO NOTHING"),
        {"i": tenant_id, "n": f"scim-{tenant_id.hex[:8]}", "s": f"scim-{tenant_id.hex[:8]}"},
    )
    await session.commit()
    return str(tenant_id)


@pytest_asyncio.fixture(loop_scope="module")
async def tenants(db):  # noqa: ANN001
    """Two tenants, each with a real SCIM token minted by production code."""
    from app.services.scim import tokens

    a, b = await _tenant(db), await _tenant(db)
    minted: dict[str, str] = {}
    for name, tenant_id in (("a", a), ("b", b)):
        # `mint_token` returns `(token, raw)` and the raw secret is the
        # only time it exists outside an IdP's configuration.
        _token, raw = await tokens.mint_token(
            db,
            tenant_id=uuid.UUID(tenant_id),
            org_id=None,
            name=f"ci-{name}",
            created_by=None,
        )
        minted[name] = raw
    await db.commit()

    yield {"a": a, "b": b, "token_a": minted["a"], "token_b": minted["b"]}

    # Deliberately does not delete the tenants.
    #
    # `audit_log` rows are immutable by design — a trigger raises on
    # DELETE — and deleting a tenant cascades into them. That is correct
    # product behaviour and this suite found it by trying: an audit trail
    # a test can erase is not an audit trail.
    #
    # Every identifier here is unique per run, and CI gets a fresh
    # container, so leaving the rows costs nothing. Users are removed
    # because they are what the assertions count.
    import sqlalchemy

    for tenant_id in (a, b):
        try:
            await db.execute(
                sqlalchemy.text("DELETE FROM users WHERE tenant_id = CAST(:t AS uuid)"),
                {"t": tenant_id},
            )
            await db.commit()
        except Exception:  # noqa: BLE001, S110 — teardown is best effort
            await db.rollback()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": SCIM_CONTENT_TYPE}


class TestTheNegativeControls:
    async def test_an_unauthenticated_request_is_refused(self, app_client, tenants) -> None:  # noqa: ANN001
        """Without this, every assertion below could pass on a surface
        that serves everyone."""
        response = await app_client.get("/scim/v2/Users")
        assert response.status_code in (401, 403), f"SCIM served an uncredentialed caller with {response.status_code}"

    async def test_a_garbage_token_is_refused(self, app_client, tenants) -> None:  # noqa: ANN001
        response = await app_client.get("/scim/v2/Users", headers=_auth("aisoc_scim_not_a_real_token"))
        assert response.status_code in (401, 403)


class TestProvisioningAgainstRealTypes:
    async def test_a_user_created_over_scim_is_a_row(self, app_client, db, tenants) -> None:  # noqa: ANN001
        """The round trip the SQLite harness cannot certify.

        `users` carries UUID and JSONB columns that the offline suite
        compiles away; here they are the real types.
        """
        email = f"ci-{uuid.uuid4().hex[:8]}@example.com"
        response = await app_client.post(
            "/scim/v2/Users",
            headers=_auth(tenants["token_a"]),
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": email,
                "name": {"givenName": "Ada", "familyName": "Lovelace"},
                "emails": [{"value": email, "primary": True}],
                "active": True,
            },
        )
        assert response.status_code == 201, f"{response.status_code}: {response.text[:300]}"

        import sqlalchemy

        result = await db.execute(
            sqlalchemy.text("SELECT email, tenant_id FROM users WHERE email = :e"),
            {"e": email},
        )
        row = result.first()
        assert row is not None, "SCIM answered 201 and wrote no row"
        assert str(row.tenant_id) == tenants["a"], "the user was created against a tenant other than the token's"

    async def test_the_created_user_is_listed(self, app_client, tenants) -> None:  # noqa: ANN001
        email = f"ci-{uuid.uuid4().hex[:8]}@example.com"
        await app_client.post(
            "/scim/v2/Users",
            headers=_auth(tenants["token_a"]),
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": email,
                "active": True,
            },
        )
        listed = await app_client.get("/scim/v2/Users", headers=_auth(tenants["token_a"]))
        assert listed.status_code == 200
        assert email in listed.text


class TestTenantIsolation:
    async def test_another_tenants_token_cannot_read_these_users(self, app_client, tenants) -> None:  # noqa: ANN001
        """The isolation claim, through the real auth stack.

        Tenant A provisions a user; tenant B's token must not see it. A
        surface that returned everything would have passed the listing
        test above.
        """
        email = f"ci-{uuid.uuid4().hex[:8]}@example.com"
        created = await app_client.post(
            "/scim/v2/Users",
            headers=_auth(tenants["token_a"]),
            json={
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                "userName": email,
                "active": True,
            },
        )
        assert created.status_code == 201

        theirs = await app_client.get("/scim/v2/Users", headers=_auth(tenants["token_b"]))
        assert theirs.status_code == 200
        assert email not in theirs.text, "tenant B's SCIM token listed a user provisioned by tenant A"


class TestTheDiscoveryEndpoints:
    async def test_service_provider_config_is_served(self, app_client, tenants) -> None:  # noqa: ANN001
        """An IdP reads this first. If it 404s, nothing else is reached."""
        response = await app_client.get("/scim/v2/ServiceProviderConfig", headers=_auth(tenants["token_a"]))
        assert response.status_code == 200
        assert "schemas" in response.json()

    async def test_the_user_schema_is_served(self, app_client, tenants) -> None:  # noqa: ANN001
        response = await app_client.get("/scim/v2/Schemas", headers=_auth(tenants["token_a"]))
        assert response.status_code == 200
