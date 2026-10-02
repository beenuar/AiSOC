"""`POST /api/v1/lake/sql`, end to end, against a real ClickHouse.

Maturity: completes the **Event lake + hunting (ClickHouse)** row. The
plan asked for "one E2E that round-trips a tenant-scoped query through
`POST /lake/sql`", and `test_lake_live.py` stops one layer short — it
calls `rewrite_for_tenant` directly.

Why that layer matters
-----------------------
The route is where four things happen that the rewriter alone does not
exercise: the caller is authenticated, their tenant is taken from the
*token* rather than from an argument, the rate limiter runs, and errors
are mapped onto status codes an operator reads (400 for syntax, 403 for
forbidden, 422 for timeout, 502 for a driver fault).

A tenant id taken from an argument is the shape that has gone wrong here
before — `get_entity_neighbors` accepted one and never bound it. Driving
the route means the tenant comes from the authenticated principal, which
is the only version of the claim worth making.

The negative control
--------------------
`test_an_uncredentialed_caller_is_refused` is what stops the rest
passing vacuously: a route that served everyone would satisfy "my rows
came back" while leaking every other tenant's.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_LAKE_ROUTE_DSN", "").strip(),
        reason="ISOLATION_LAKE_ROUTE_DSN is not set; this suite needs live Postgres + ClickHouse",
    ),
]

TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")


def _dsn() -> str:
    return os.environ["ISOLATION_LAKE_ROUTE_DSN"]


def _ch():  # noqa: ANN202
    driver = pytest.importorskip("clickhouse_driver")
    return driver.Client(
        host=os.environ.get("ISOLATION_CLICKHOUSE_HOST", "localhost"),
        port=int(os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000")),
        user=os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"),
        password=os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""),
    )


@pytest.fixture(scope="module")
def lake():
    """Two tenants' rows, under the schema the product ships."""
    client = _ch()
    root = Path(os.environ.get("ISOLATION_REPO_ROOT", "."))
    ddl = (root / "services" / "api" / "clickhouse" / "001_init.sql").read_text(encoding="utf-8")
    lines = [ln for ln in ddl.splitlines() if not ln.strip().startswith("--")]
    for statement in (s.strip() for s in "\n".join(lines).split(";")):
        if statement:
            client.execute(statement)

    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")
    now = datetime.now(UTC).replace(tzinfo=None)
    client.execute(
        "INSERT INTO aisoc.raw_events "
        "(tenant_id, event_time, class_uid, category_uid, severity_id, severity, "
        "src_hostname, raw_payload) VALUES",
        [
            (TENANT_A, now, 2001, 2, 4, "high", "route-a-host-1", "{}"),
            (TENANT_A, now, 2001, 2, 4, "high", "route-a-host-2", "{}"),
            (TENANT_B, now, 2001, 2, 4, "high", "route-b-host-1", "{}"),
        ],
    )
    yield client
    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def users(lake):  # noqa: ANN001
    """One admin user per tenant, as real rows."""
    asyncpg = pytest.importorskip("asyncpg")
    dsn = _dsn().replace("postgresql+asyncpg://", "postgresql://")
    conn = await asyncpg.connect(dsn)
    created: dict[uuid.UUID, uuid.UUID] = {}
    try:
        for tenant in (TENANT_A, TENANT_B):
            slug = f"lake-{tenant.hex[:8]}"
            await conn.execute(
                "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                tenant,
                slug,
                slug,
            )
            user_id = uuid.uuid4()
            await conn.execute(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                "VALUES ($1, $2, $3, $4, $5, 'admin', true) ON CONFLICT DO NOTHING",
                user_id,
                tenant,
                f"lake-{user_id.hex[:8]}@example.com",
                f"lake-{user_id.hex[:8]}",
                "x",
            )
            created[tenant] = user_id
    finally:
        await conn.close()
    yield created


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client(lake, users):  # noqa: ANN001
    """The real application, as `create_application()` builds it."""
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    os.environ.setdefault("ENVIRONMENT", "development")
    os.environ.setdefault("CLICKHOUSE_HOST", os.environ.get("ISOLATION_CLICKHOUSE_HOST", "localhost"))
    os.environ.setdefault("CLICKHOUSE_PORT", os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000"))
    os.environ.setdefault("CLICKHOUSE_USER", os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"))
    os.environ.setdefault("CLICKHOUSE_PASSWORD", os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""))
    os.environ.setdefault("CLICKHOUSE_DATABASE", "aisoc")

    import httpx
    from app.main import create_application

    app = create_application()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


def _auth(users: dict, tenant: uuid.UUID) -> dict[str, str]:  # noqa: ANN001
    """A real signed token for a real user row.

    `get_current_user` resolves `sub` against the `users` table and 401s
    on "User not found", so a synthetic subject would be refused. That
    is the behaviour worth keeping: the tenant comes from the
    credential's *user*, never from an argument or a header — which is
    the shape that has gone wrong here before, when `get_entity_neighbors`
    accepted a tenant_id and never bound it.
    """
    from app.core.security import create_access_token

    token = create_access_token({"sub": str(users[tenant]), "type": "access"})
    return {"Authorization": f"Bearer {token}"}


class TestTheNegativeControl:
    async def test_an_uncredentialed_caller_is_refused(self, client) -> None:  # noqa: ANN001
        """Without this, every assertion below could pass on a route that
        serves everyone."""
        response = await client.post("/api/v1/lake/sql", json={"sql": "SELECT 1"})
        assert response.status_code in (401, 403), f"the lake route served an uncredentialed caller with {response.status_code}"


class TestTheRoundTrip:
    async def test_a_tenant_reads_its_own_rows(self, client, users) -> None:  # noqa: ANN001
        response = await client.post(
            "/api/v1/lake/sql",
            headers=_auth(users, TENANT_A),
            json={"sql": "SELECT src_hostname FROM aisoc.raw_events"},
        )
        assert response.status_code == 200, f"{response.status_code}: {response.text[:300]}"
        blob = response.text
        assert "route-a-host-1" in blob and "route-a-host-2" in blob, blob[:300]

    async def test_it_does_not_read_another_tenants(self, client, users) -> None:  # noqa: ANN001
        """The claim the whole lake row rests on, made at the layer where
        the tenant comes from the token."""
        response = await client.post(
            "/api/v1/lake/sql",
            headers=_auth(users, TENANT_A),
            json={"sql": "SELECT src_hostname FROM aisoc.raw_events"},
        )
        assert response.status_code == 200
        assert "route-b-host-1" not in response.text, "tenant A read tenant B's rows through POST /lake/sql"

    async def test_the_other_tenant_sees_its_own(self, client, users) -> None:  # noqa: ANN001
        """So the exclusion above is isolation, not an empty table."""
        response = await client.post(
            "/api/v1/lake/sql",
            headers=_auth(users, TENANT_B),
            json={"sql": "SELECT src_hostname FROM aisoc.raw_events"},
        )
        assert response.status_code == 200
        assert "route-b-host-1" in response.text

    async def test_naming_another_tenant_in_the_sql_does_not_widen_it(self, client, users) -> None:  # noqa: ANN001
        """An operator writing their own `tenant_id =` must not be able to
        escape the predicate the route injects."""
        response = await client.post(
            "/api/v1/lake/sql",
            headers=_auth(users, TENANT_A),
            json={"sql": f"SELECT src_hostname FROM aisoc.raw_events WHERE tenant_id = '{TENANT_B}'"},
        )
        assert response.status_code == 200
        assert "route-b-host-1" not in response.text


class TestErrorsAreOperatorReadable:
    async def test_unparseable_sql_is_a_client_error(self, client, users) -> None:  # noqa: ANN001
        """400 rather than 500: the caller's SQL is the caller's problem,
        and a 500 sends an operator to read server logs for a typo."""
        response = await client.post("/api/v1/lake/sql", headers=_auth(users, TENANT_A), json={"sql": "this is not sql )("})
        assert 400 <= response.status_code < 500, (
            f"bad SQL answered {response.status_code}; an unhandled 500 here is the shape "
            "that sends an operator to debug the server for their own typo"
        )

    async def test_a_write_is_refused(self, client, users) -> None:  # noqa: ANN001
        """The lake API is read-only by contract. A DELETE that reached
        ClickHouse would be a cross-tenant data-loss primitive."""
        response = await client.post(
            "/api/v1/lake/sql",
            headers=_auth(users, TENANT_A),
            json={"sql": "ALTER TABLE aisoc.raw_events DELETE WHERE 1=1"},
        )
        assert response.status_code != 200, "the lake route accepted a write"

        remaining = _ch().execute("SELECT count() FROM aisoc.raw_events")[0][0]
        assert remaining == 3, (
            f"the table has {remaining} rows, not 3 — a refused write still reached ClickHouse, which is worse than accepting it openly"
        )
