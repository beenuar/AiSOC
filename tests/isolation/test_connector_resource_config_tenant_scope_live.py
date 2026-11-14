"""``GET /connectors/instances/{id}/resource-config`` may only reach the caller's own tenant.

What was wrong
--------------
The handler took ``(instance_id, resource_id, ts)`` and **no principal**. The
router authenticates (``dependencies=[Depends(require_console_or_service_auth)]``
in ``services/connectors/app/api/router.py``), but a dependency that is never
declared as a handler parameter hands its result nowhere, so the resolved
``TenantPrincipal`` was discarded and nothing downstream knew who was asking.

The lookup underneath was global as well: ``fetch_enabled_connectors`` is
``select(...).where(is_enabled)`` with no tenant predicate, and the handler then
picked its row out of every tenant's instances with
``next(i for i in instances if str(i.id) == instance_id)``. Ownership was never
compared. The connectors engine binds no ``app.current_tenant_id``, so the
``connectors`` RLS policy's ``OR current_tenant_id() IS NULL`` arm fails open and
the predicate is the only control there is.

The consequence is worse than reading a row. ``router.py`` decrypts that row's
``auth_config`` with the platform vault, constructs the vendor client and makes
an authenticated call — so the platform spent **the victim's** cloud credential
on the attacker's behalf and returned the vendor's answer, with the vendor-side
audit trail naming the victim.

What this asserts
-----------------
Both halves, because either alone leaves the hole open:

* the row is selected **by (id, tenant)**, so another tenant's instance is not
  found at all rather than found and then filtered; and
* the tenant comes from the **authenticated principal** — a console token's
  verified claim, or the header a service token must declare — never from
  anything else the caller sends.

Non-ownership resolves as **404, not 403**. A 403 would still answer "this id
exists somewhere", which turns the route into an existence oracle over every
tenant's connector ids; the miss and the cross-tenant hit are required to be
byte-identical.

The positive controls are as load-bearing as the refusals. A route that
refuses everything passes every negative assertion while being broken, and
"stuck closed" reads as working caution — so each tenant must still reach its
*own* instance and the vendor must still see that tenant's own credential.

Why live
--------
The vendor is a real socket rather than a patched method, so the decrypt →
construct → authenticate path runs and the test can ask the vendor *which
credential it was paid with*. That question is the whole finding, and a mock
that answers whatever it is asked cannot be asked it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
import pytest_asyncio

# Skipped as a *module*, not only in the fixture: the offline isolation job
# collects this directory with no stores running, and a test that does not take
# the fixture would otherwise run and fail there — a failure about the harness,
# reported against a capability.
pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip(),
        reason="ISOLATION_CONNECTOR_DSN is not set; this suite needs live infrastructure",
    ),
]

SECRET = "isolation-console-secret-at-least-32-characters"
SERVICE_TOKEN = "isolation-shared-service-token"

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")

#: Okta ids are prefix-typed; ``00u`` is a user, which is the branch
#: ``OktaConnector.get_resource_config`` takes.
RESOURCE_ID = "00uRESOURCE0001"

TOKEN_A = "tenant-a-own-okta-token"
TOKEN_B = "tenant-b-victim-okta-token"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_CONNECTOR_DSN is not set; this suite needs a live Postgres")
    return value


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def console_token(tenant: uuid.UUID, *, role: str = "viewer") -> str:
    """A console access token, signed the way ``services/api`` signs one.

    Minted here rather than by importing the API, because both services name
    their top-level package ``app`` and importing one shadows the other. The
    construction is byte-compatible with ``create_access_token`` and the
    *verifier* on the path is the real one, which is the half that matters:
    ``require_console_or_service_auth`` -> ``verify_console_token``.
    """
    header = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    claims = {
        "sub": f"user-{tenant}",
        "tenant_id": str(tenant),
        "role": role,
        "type": "access",
        "exp": int(time.time()) + 600,
    }
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    sig = _b64(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


class _Vendor(BaseHTTPRequestHandler):
    """A real HTTP server standing in for Okta, recording what it was paid with."""

    seen: list[dict[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802
        auth = self.headers.get("Authorization", "")
        presented = auth[len("SSWS ") :] if auth.startswith("SSWS ") else auth
        _Vendor.seen.append({"path": self.path, "credential": presented})
        body = json.dumps(
            {
                "id": self.path.rsplit("/", 1)[-1],
                "status": "ACTIVE",
                "profile": {"login": "someone@example.com"},
                "_authenticated_with": presented,
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Quiet: the default handler prints to stderr on every request."""


@pytest.fixture(scope="module")
def vendor():
    server = HTTPServer(("127.0.0.1", 0), _Vendor)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module", autouse=True)
def _env():
    """Production posture, and the credentials both auth shapes need.

    ``ENVIRONMENT=production`` deliberately: ``development`` is in
    ``AUTH_BYPASS_ENVIRONMENTS`` and would resolve a demo principal inside the
    one suite whose whole subject is that the tenant comes from the credential.
    """
    previous = {
        k: os.environ.get(k)
        for k in (
            "ENVIRONMENT",
            "SECRET_KEY",
            "AISOC_SERVICE_TOKEN",
            "AISOC_DEV_MODE",
            "AISOC_DEV_AUTH_BYPASS",
            "AISOC_CONNECTORS_DISABLE_SCHEDULER",
        )
    }
    os.environ["ENVIRONMENT"] = "production"
    os.environ["SECRET_KEY"] = SECRET
    os.environ["AISOC_SERVICE_TOKEN"] = SERVICE_TOKEN
    os.environ["AISOC_CONNECTORS_DISABLE_SCHEDULER"] = "1"
    os.environ.pop("AISOC_DEV_MODE", None)
    os.environ.pop("AISOC_DEV_AUTH_BYPASS", None)
    yield
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    pytest.importorskip("asyncpg")
    from sqlalchemy.ext.asyncio import create_async_engine

    created = create_async_engine(_dsn(), future=True)
    yield created
    await created.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def instances(engine, vendor):  # noqa: ANN001
    """One enabled Okta instance per tenant, written the way the console writes one.

    Both point at the same stub vendor and differ only in their credential, so
    "whose secret was spent" is answerable from the vendor's own log rather
    than inferred from which row came back.
    """
    import sqlalchemy
    from app.security.credential_vault import get_vault

    vault = get_vault()
    ids = {TENANT_A: uuid.uuid4(), TENANT_B: uuid.uuid4()}
    async with engine.begin() as conn:
        for tenant, token in ((TENANT_A, TOKEN_A), (TENANT_B, TOKEN_B)):
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO tenants (id, name, slug, is_active) VALUES (CAST(:i AS uuid), :n, :s, true) ON CONFLICT (id) DO NOTHING"
                ),
                {"i": str(tenant), "n": f"T-{tenant}", "s": f"t-{tenant}"},
            )
            auth = vault.encrypt_dict({"domain": vendor, "api_token": token})
            assert str(auth["api_token"]).startswith("vault:v1:"), "the credential must be ciphertext at rest"
            await conn.execute(
                sqlalchemy.text(
                    "INSERT INTO connectors (id, tenant_id, name, connector_type, category, is_enabled, "
                    "auth_config, connector_config, health_status, tags, events_ingested, events_dropped, error_count) "
                    "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :n, 'okta', 'iam', true, "
                    "CAST(:a AS jsonb), CAST('{}' AS jsonb), 'healthy', CAST('[]' AS jsonb), 0, 0, 0) "
                    "ON CONFLICT (id) DO NOTHING"
                ),
                {"i": str(ids[tenant]), "t": str(tenant), "n": f"okta-{tenant}", "a": json.dumps(auth)},
            )
    yield ids
    async with engine.begin() as conn:
        for value in ids.values():
            await conn.execute(
                sqlalchemy.text("DELETE FROM connectors WHERE id = CAST(:i AS uuid)"),
                {"i": str(value)},
            )


@pytest_asyncio.fixture(loop_scope="module")
async def client(engine):  # noqa: ANN001
    """The real connectors ASGI application, over the real request pipeline."""
    from app.db.engine import set_engine
    from app.main import app as application

    set_engine(engine)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://connectors") as http:
        yield http
    set_engine(None)


def _url(instance_id: uuid.UUID) -> str:
    return f"/api/v1/connectors/instances/{instance_id}/resource-config?resource_id={RESOURCE_ID}"


# ---------------------------------------------------------------------------
# The finding
# ---------------------------------------------------------------------------


async def test_a_console_token_cannot_read_another_tenants_instance(client, instances):  # noqa: ANN001
    """The reported defect: a tenant-A viewer read tenant B's instance and got 200."""
    _Vendor.seen.clear()

    response = await client.get(
        _url(instances[TENANT_B]),
        headers={"Authorization": f"Bearer {console_token(TENANT_A)}"},
    )

    assert response.status_code == 404, f"tenant A reached tenant B's instance: {response.status_code} {response.text[:300]}"


async def test_the_victims_credential_is_never_decrypted_or_spent(client, instances):  # noqa: ANN001
    """Not merely "no row returned": the victim's secret must not be used at all.

    Asserted against the vendor's own record of the credential presented to it,
    because the sink is an authenticated vendor call made with a decrypted
    ``auth_config`` — a refusal that still spent the secret would be no fix.
    """
    _Vendor.seen.clear()

    await client.get(
        _url(instances[TENANT_B]),
        headers={"Authorization": f"Bearer {console_token(TENANT_A)}"},
    )

    spent = [call["credential"] for call in _Vendor.seen]
    assert TOKEN_B not in spent, f"the platform spent tenant B's credential for tenant A: {spent}"
    assert spent == [], f"the refused request reached the vendor at all: {spent}"


async def test_a_service_token_cannot_name_one_tenant_and_read_another(client, instances):  # noqa: ANN001
    """The declared tenant must bound the read, not merely accompany it."""
    _Vendor.seen.clear()

    response = await client.get(
        _url(instances[TENANT_B]),
        headers={
            "Authorization": f"Bearer {SERVICE_TOKEN}",
            "X-AiSOC-Tenant-ID": str(TENANT_A),
        },
    )

    assert response.status_code == 404, f"a service token declaring tenant A read tenant B: {response.status_code}"
    assert TOKEN_B not in [c["credential"] for c in _Vendor.seen]


async def test_a_foreign_instance_is_indistinguishable_from_one_that_does_not_exist(client, instances):  # noqa: ANN001
    """404 rather than 403, so the route stops being an existence oracle.

    A 403 on a real id and a 404 on an invented one lets an unauthorised caller
    enumerate which connector ids exist across every tenant. The two answers
    must be the same answer.
    """
    headers = {"Authorization": f"Bearer {console_token(TENANT_A)}"}

    foreign = await client.get(_url(instances[TENANT_B]), headers=headers)
    absent = await client.get(_url(uuid.uuid4()), headers=headers)

    assert foreign.status_code == absent.status_code == 404
    assert foreign.json() == absent.json(), f"a foreign instance is distinguishable from an absent one: {foreign.json()} vs {absent.json()}"


# ---------------------------------------------------------------------------
# Positive controls — the route must still work, or "fixed" means "broken"
# ---------------------------------------------------------------------------


async def test_each_tenant_still_reaches_its_own_instance_with_its_own_credential(client, instances):  # noqa: ANN001
    """Stuck-closed reads as working caution, so this is the half that catches it."""
    for tenant, token in ((TENANT_A, TOKEN_A), (TENANT_B, TOKEN_B)):
        _Vendor.seen.clear()

        response = await client.get(
            _url(instances[tenant]),
            headers={"Authorization": f"Bearer {console_token(tenant)}"},
        )

        assert response.status_code == 200, f"tenant {tenant} lost access to its own instance: {response.text[:300]}"
        assert response.json()["resource_id"] == RESOURCE_ID
        assert [c["credential"] for c in _Vendor.seen] == [token], (
            f"tenant {tenant}'s own read was made with the wrong credential: {_Vendor.seen}"
        )


async def test_a_service_token_still_acts_for_the_tenant_it_declares(client, instances):  # noqa: ANN001
    """Delegation is the mechanism the scheduler and the API both rely on."""
    _Vendor.seen.clear()

    response = await client.get(
        _url(instances[TENANT_B]),
        headers={
            "Authorization": f"Bearer {SERVICE_TOKEN}",
            "X-AiSOC-Tenant-ID": str(TENANT_B),
        },
    )

    assert response.status_code == 200, f"a correctly-scoped service call was refused: {response.text[:300]}"
    assert [c["credential"] for c in _Vendor.seen] == [TOKEN_B]


async def test_an_unauthenticated_caller_is_refused_before_any_lookup(client, instances):  # noqa: ANN001
    """The router-level guard still applies; this pins it from the route's side."""
    _Vendor.seen.clear()

    response = await client.get(_url(instances[TENANT_B]))

    assert response.status_code == 401
    assert _Vendor.seen == []
