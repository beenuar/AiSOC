"""The agents service reaches the API as a service, for one named tenant.

Fix pass item 1.1. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
Three agent tool modules authenticated with `AISOC_AGENTS_API_KEY`
(`app/tools/customer_tools.py`, `app/hunt/agent.py`, `app/tools/sandbox.py`),
and **no compose file, `.env.example` or Helm value delivered that key**. On a
default `make up` every one of them answered "could not check", which a model
reads as a gap in visibility and an operator never sees.

Setting the key would not have fixed it. One key belongs to one tenant, so
every tenant's investigation would read that tenant's estate. And the routes
these tools call require `actions:read`, `lake:query` and `hunts:read`, none of
which is in `VALID_SCOPES`, so only a `*` key could reach them at all.

Why the offline suites did not catch it
---------------------------------------
They stub `_call`, or they drive the route with a `CurrentUser` built in the
test. Neither reaches the question this file asks, which is whether the
credential the deployment actually hands the agents container is one the API
will accept, and whether it confines the answer to one tenant.

What this file asserts
----------------------
The real `create_application()` against real Postgres with every migration
applied, driven over a real `httpx` client, using exactly the credential
`docker-compose.yml` gives the agents container:

* a service token plus `X-AiSOC-Tenant-ID` is accepted, and
* it returns that tenant's connectors and never the other tenant's.

The negative controls are what stop those passing for the wrong reason: a
surface that answered everything to everyone, or one that answered an empty
list to everyone, would satisfy a naive "B is present" assertion. So this also
asserts that no credential is refused, that a service token with **no** tenant
header is refused rather than widened, and that a tenant header naming a
tenant that does not exist is refused.

Against the pre-fix tree every positive assertion here fails with 401, because
the API had no service-caller path at all.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

# Skip as a module, not only in the fixture. The offline isolation job
# collects this directory with no Postgres running, and a test that does not
# take the fixture would otherwise run and fail there, reporting a harness
# problem against a capability.
pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_AGENT_AUTH_DSN", "").strip(),
        reason="ISOLATION_AGENT_AUTH_DSN is not set; this suite needs a live Postgres",
    ),
]

#: The token the deployment hands the agents container. `docker-compose.yml`
#: sets `AISOC_SERVICE_TOKEN` on the agents service already; what was missing
#: was any code path that presented it to the API.
SERVICE_TOKEN = "fixpass-service-token-not-a-real-secret"

TENANT_HEADER = "X-AiSOC-Tenant-ID"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_AGENT_AUTH_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_AGENT_AUTH_DSN is not set")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client():
    """The real application, with the real auth dependency graph.

    `create_application()` rather than a bare `FastAPI()` with one router
    mounted: the middleware, the exception handlers and the dependencies are
    part of what the agents service talks to.
    """
    pytest.importorskip("httpx")
    os.environ["DATABASE_URL"] = _dsn()
    os.environ["AISOC_SERVICE_TOKEN"] = SERVICE_TOKEN
    # Production posture. Without this the dev-mode shim answers every
    # uncredentialed request with a demo principal and the negative controls
    # below pass for the wrong reason.
    os.environ["ENVIRONMENT"] = "production"
    os.environ.pop("AISOC_DEV_MODE", None)
    os.environ.pop("AISOC_DEV_AUTH_BYPASS", None)
    # A real signing secret, so the console branch is configured and the
    # service branch is not reached merely because nothing else was.
    os.environ.setdefault("SECRET_KEY", "fixpass-console-secret-at-least-32-chars-long")

    import httpx
    from app.main import create_application

    application = create_application()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def db():
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_dsn(), future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _tenant_with_connector(session, label: str) -> tuple[str, str]:
    """A tenant and one enabled, federated-capable connector of its own."""
    from sqlalchemy import text

    tenant_id = str(uuid.uuid4())
    slug = f"fixpass-{label}-{tenant_id[:8]}"
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:tid AS uuid), :name, :slug)"),
        {"tid": tenant_id, "name": f"Fix pass {label}", "slug": slug},
    )
    connector_name = f"{label}-splunk"
    await session.execute(
        text(
            "INSERT INTO connectors (id, tenant_id, name, connector_type, category, is_enabled) "
            "VALUES (CAST(:cid AS uuid), CAST(:tid AS uuid), :name, 'splunk', 'siem', TRUE)"
        ),
        {"cid": str(uuid.uuid4()), "tid": tenant_id, "name": connector_name},
    )
    await session.commit()
    return tenant_id, connector_name


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def two_tenants(db):
    """Two tenants, each with a connector only it should see."""
    a = await _tenant_with_connector(db, "alpha")
    b = await _tenant_with_connector(db, "bravo")
    return {"a": a, "b": b}


def _service_headers(tenant_id: str | None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {SERVICE_TOKEN}"}
    if tenant_id is not None:
        headers[TENANT_HEADER] = tenant_id
    return headers


def _connector_names(payload: dict) -> set[str]:
    return {entry.get("name", "") for entry in payload.get("siem_search", {}).get("backends", [])}


class TestTheServiceCredentialIsAccepted:
    async def test_a_service_token_with_a_tenant_reaches_the_agent_tool_surface(
        self, app_client, two_tenants
    ) -> None:
        """The credential compose actually delivers is one the API accepts.

        Against the pre-fix tree this is 401: the API resolved a bearer token
        as a JWT or an `aisoc_` API key and had no service path, so the
        agents container could not authenticate at all without a hand-minted
        wildcard key that no deployment creates.
        """
        tenant_b, _ = two_tenants["b"]
        response = await app_client.get("/api/v1/agent-tools/backends", headers=_service_headers(tenant_b))

        assert response.status_code == 200, (
            f"the agents service could not authenticate to the API: {response.status_code} {response.text[:300]}"
        )

    async def test_the_answer_is_scoped_to_the_tenant_the_service_named(self, app_client, two_tenants) -> None:
        """One token, two tenants, two different answers.

        This is the half a single shared API key could never satisfy: the key
        belongs to one tenant, so every investigation would have read that
        tenant's estate whatever alert it was working on.
        """
        tenant_a, connector_a = two_tenants["a"]
        tenant_b, connector_b = two_tenants["b"]

        got_a = _connector_names((await app_client.get(
            "/api/v1/agent-tools/backends", headers=_service_headers(tenant_a)
        )).json())
        got_b = _connector_names((await app_client.get(
            "/api/v1/agent-tools/backends", headers=_service_headers(tenant_b)
        )).json())

        assert connector_a in got_a, f"tenant A did not see its own connector: {sorted(got_a)}"
        assert connector_b in got_b, f"tenant B did not see its own connector: {sorted(got_b)}"
        assert connector_b not in got_a, "tenant A was shown tenant B's connector"
        assert connector_a not in got_b, "tenant B was shown tenant A's connector"


class TestTheNegativeControls:
    """What stops the assertions above passing over a surface that leaks."""

    async def test_no_credential_is_refused(self, app_client, two_tenants) -> None:
        tenant_b, _ = two_tenants["b"]
        response = await app_client.get("/api/v1/agent-tools/backends", headers={TENANT_HEADER: tenant_b})
        assert response.status_code in (401, 403), (
            f"an uncredentialed caller was served: {response.status_code}"
        )

    async def test_a_service_token_without_a_tenant_is_refused_rather_than_widened(self, app_client) -> None:
        """An absent scope is an empty scope, never every scope.

        Every cross-tenant leak this codebase has had took the other shape: a
        scope that was absent rather than narrow, and a read that treated
        absent as "no filter".
        """
        response = await app_client.get("/api/v1/agent-tools/backends", headers=_service_headers(None))
        assert response.status_code in (401, 403), (
            f"a service token with no tenant header was served: {response.status_code}"
        )

    async def test_a_tenant_that_does_not_exist_is_refused(self, app_client) -> None:
        """The header is caller-supplied, so it is checked against the table.

        `POST /v1/ingest/batch` once trusted a caller-supplied tenant header
        that nothing checked against `tenants`. A service token is trusted;
        the tenant it names is not.
        """
        response = await app_client.get(
            "/api/v1/agent-tools/backends", headers=_service_headers(str(uuid.uuid4()))
        )
        assert response.status_code in (401, 403, 404), (
            f"a service token naming an unknown tenant was served: {response.status_code}"
        )

    async def test_a_wrong_service_token_is_refused(self, app_client, two_tenants) -> None:
        tenant_b, _ = two_tenants["b"]
        response = await app_client.get(
            "/api/v1/agent-tools/backends",
            headers={"Authorization": "Bearer not-the-service-token", TENANT_HEADER: tenant_b},
        )
        assert response.status_code in (401, 403), (
            f"a forged service token was served: {response.status_code}"
        )
