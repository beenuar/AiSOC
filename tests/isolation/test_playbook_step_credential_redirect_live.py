"""The reported chain, end to end: console session -> API -> actions -> vendor.

What was wrong
--------------
``POST /api/v1/playbook-steps/dispatch`` takes a free-form ``params`` dict from
any session holding ``actions:execute`` — which ``ROLE_PERMISSIONS`` grants to
``soc_analyst`` — and forwards it verbatim to ``services/actions``. There,
``resolve_params`` merged it **on top of** the fields translated from the
connector's decrypted ``auth_config``, so ``params["cs_base_url"]`` replaced
the stored CrowdStrike URL and the platform authenticated against a host the
caller named, using the tenant's own client id and secret
(GHSA-78jg-x2ch-638f). ``get_host`` is ``READ_ONLY``/``AUTOMATIC``/``MINIMAL``,
so it auto-executes at the default ``L1_NOTIFY`` tier and no approval was
involved.

Why this suite exists alongside the actions-side one
----------------------------------------------------
``services/actions/tests/test_param_override_credential_redirect.py`` drives
``dispatch()`` directly and is the regression gate. This one reproduces the
reporter's proof of concept as written: a real console JWT, the real API
application, a real Postgres holding a real vault-encrypted connector row, the
real actions service over a real socket, and a real HTTP server standing in for
CrowdStrike. It is the artefact that answers "could a customer's analyst
actually do this", which no amount of unit testing answers.

The actions service runs as a **subprocess**: ``services/api`` and
``services/actions`` both name their top-level package ``app``, so importing
one in-process shadows the other.

``ENVIRONMENT=production`` deliberately — ``development`` is in
``AUTH_BYPASS_ENVIRONMENTS`` and would resolve an uncredentialed request to a
demo admin, which makes an authorization test pass for the worst reason.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_STEP_DISPATCH_DSN", "").strip() or not os.environ.get("ISOLATION_ACTIONS_PYTHON", "").strip(),
        reason="ISOLATION_STEP_DISPATCH_DSN and ISOLATION_ACTIONS_PYTHON are not both set; this suite needs live infrastructure",
    ),
]

SECRET = "isolation-step-dispatch-secret-at-least-32-characters"
AGENTS_TOKEN = "isolation-step-dispatch-agents-token"
ACTIONS_TOKEN = "isolation-step-dispatch-actions-token"

TENANT = uuid.UUID("78a9a9a9-0000-0000-0000-000000000078")
ANALYST = uuid.UUID("78a9a9a9-0000-0000-0000-0000000000b8")

CLIENT_ID = "MARKER_CLIENT_ID_live78"
#: A marker, not a credential: it authenticates to nothing and exists so the
#: stub vendor's request log can be searched for it. The whole point of this
#: suite is asserting where this string does and does not travel, so it has to
#: be a literal.
CLIENT_SECRET = "MARKER_SECRET_live78_xyz789"  # gitleaks:allow

URL = "/api/v1/playbook-steps/dispatch"


class _Vendor(BaseHTTPRequestHandler):
    """Stands in for CrowdStrike, recording what it was paid with."""

    seen: list[dict[str, str]] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8", "replace")
        _Vendor.seen.append({"path": self.path, "body": body})
        self._reply(b'{"access_token":"tok","expires_in":1799}')

    def do_GET(self) -> None:  # noqa: N802
        _Vendor.seen.append({"path": self.path, "body": ""})
        self._reply(b'{"resources":[]}')

    def _reply(self, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args) -> None:  # noqa: ANN002
        """Quiet: the default handler prints every request to stderr."""


@pytest.fixture(scope="module")
def vendor():
    server = HTTPServer(("127.0.0.1", 0), _Vendor)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(scope="module")
def actions_service():
    """The real actions service, on a real socket, in its own interpreter."""
    repo = pathlib.Path(__file__).resolve().parents[2]
    python = os.environ["ISOLATION_ACTIONS_PYTHON"].strip()

    sock = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    port = sock.server_port
    sock.server_close()

    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo / "services" / "actions")
    env["AISOC_ACTIONS_SERVICE_TOKEN"] = ACTIONS_TOKEN
    env["ENVIRONMENT"] = "production"
    proc = subprocess.Popen(
        [python, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
        cwd=str(repo / "services" / "actions"),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    for _ in range(80):
        if proc.poll() is not None:
            pytest.fail(f"the actions service exited during startup:\n{proc.stdout.read().decode()[-3000:]}")
        try:
            if httpx.get(f"{base}/health", timeout=2).status_code < 500:
                break
        except httpx.HTTPError:
            # Expected while the server is still binding its socket: a
            # connection refused here means "not up yet", which is what the
            # loop is waiting for. A startup that genuinely failed is caught
            # by the `proc.poll()` check above, which reports the child's
            # output, and one that never comes up falls through to the
            # `else:` below — so there is nothing to handle at this point
            # beyond trying again.
            pass
        time.sleep(0.5)
    else:
        proc.terminate()
        pytest.fail("the actions service never became reachable")

    yield base
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()


@pytest.fixture(scope="module", autouse=True)
def _env(actions_service):  # noqa: ANN001
    keys = (
        "ENVIRONMENT",
        "SECRET_KEY",
        "AISOC_AGENTS_SERVICE_TOKEN",
        "AISOC_ACTIONS_SERVICE_TOKEN",
        "AISOC_ACTIONS_BASE_URL",
        "AISOC_CREDENTIAL_KEY",
        "DATABASE_URL",
        "AISOC_DEV_MODE",
        "AISOC_DEV_AUTH_BYPASS",
    )
    previous = {k: os.environ.get(k) for k in keys}
    os.environ["ENVIRONMENT"] = "production"
    os.environ["SECRET_KEY"] = SECRET
    os.environ["AISOC_AGENTS_SERVICE_TOKEN"] = AGENTS_TOKEN
    os.environ["AISOC_ACTIONS_SERVICE_TOKEN"] = ACTIONS_TOKEN
    os.environ["AISOC_ACTIONS_BASE_URL"] = actions_service
    os.environ["DATABASE_URL"] = os.environ["ISOLATION_STEP_DISPATCH_DSN"].strip()
    os.environ.pop("AISOC_DEV_MODE", None)
    os.environ.pop("AISOC_DEV_AUTH_BYPASS", None)

    # The environment alone is not enough, and the failure it produces points
    # at the wrong thing. `Settings` reads the environment once, at import of
    # `app.core.config`, and another live module in the same pytest process
    # may already have imported it — after which setting these variables here
    # changes nothing. `actions_client` then presents an empty token, the
    # actions service answers 401, and the dispatch report reads "Could not
    # reach the action registry", which sends a reader to debug a service that
    # is running perfectly. Both are read off the settings object per call, so
    # assigning them is what actually takes effect.
    from app.core.config import settings

    settings_previous = {
        "AISOC_ACTIONS_SERVICE_TOKEN": settings.AISOC_ACTIONS_SERVICE_TOKEN,
        "AISOC_ACTIONS_BASE_URL": settings.AISOC_ACTIONS_BASE_URL,
    }
    settings.AISOC_ACTIONS_SERVICE_TOKEN = ACTIONS_TOKEN
    settings.AISOC_ACTIONS_BASE_URL = actions_service

    yield

    for name, value in settings_previous.items():
        setattr(settings, name, value)
    for key, value in previous.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


@pytest_asyncio.fixture(scope="module", loop_scope="module", autouse=True)
async def _release_engine(_env):  # noqa: ANN001
    """Hand the shared engine's pool back when this module's loop ends.

    ``app.db.database.engine`` is a module global whose pool binds to whichever
    event loop first used it. Two module-scoped live suites in one pytest
    process therefore leave the second holding connections from a loop that has
    closed, which surfaces as ``RuntimeError: Event loop is closed`` and reads
    like a database fault rather than the harness artefact it is.
    """
    yield
    # Imported here, not at module scope: the engine is constructed from
    # ``settings.DATABASE_URL`` at import time, and ``_env`` above is what sets
    # it. A top-level import would bind the engine to whatever DSN the
    # environment happened to carry.
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture(loop_scope="module")
async def connector(_env, vendor):  # noqa: ANN001
    """An enabled CrowdStrike connector whose stored URL is the test's vendor.

    The stored URL points at the same server the attacker would name, so "whose
    URL was used" is answered by the *path* the vendor saw rather than by which
    host it was, and the positive control can assert the legitimate call still
    lands. The credential is asserted to be ciphertext at rest so the decrypt
    path is genuinely exercised.
    """
    import sqlalchemy
    from app.db.database import AsyncSessionLocal
    from app.security.credential_vault import get_vault

    auth = get_vault().encrypt_dict({"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "base_url": vendor})
    assert str(auth["client_secret"]).startswith("vault:v1:"), "the fixture must store ciphertext"

    async with AsyncSessionLocal() as session:
        await session.execute(
            sqlalchemy.text(
                "INSERT INTO tenants (id, name, slug, is_active) VALUES (CAST(:i AS uuid), :n, :s, true) ON CONFLICT (id) DO NOTHING"
            ),
            {"i": str(TENANT), "n": "step-dispatch-isolation", "s": f"stepdisp-{TENANT}"},
        )
        await session.execute(
            sqlalchemy.text(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active, is_verified) "
                "VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :e, :u, 'unused', 'soc_analyst', true, true) "
                "ON CONFLICT (id) DO NOTHING"
            ),
            {"i": str(ANALYST), "t": str(TENANT), "e": f"analyst-{ANALYST}@example.com", "u": f"analyst-{ANALYST}"},
        )
        await session.execute(sqlalchemy.text("DELETE FROM connectors WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
        await session.execute(sqlalchemy.text("SELECT set_config('app.current_tenant_id', :t, TRUE)"), {"t": str(TENANT)})
        await session.execute(
            sqlalchemy.text(
                "INSERT INTO connectors (id, tenant_id, name, connector_type, category, is_enabled, auth_config, "
                "connector_config, health_status, tags, events_ingested, events_dropped, error_count) "
                "VALUES (gen_random_uuid(), CAST(:t AS uuid), :n, 'crowdstrike', 'edr', true, CAST(:a AS jsonb), "
                "CAST(:c AS jsonb), 'healthy', CAST('[]' AS jsonb), 0, 0, 0)"
            ),
            {"t": str(TENANT), "n": "cs-isolation", "a": json.dumps(auth), "c": json.dumps({"base_url": vendor})},
        )
        await session.commit()

    yield

    async with AsyncSessionLocal() as session:
        await session.execute(sqlalchemy.text("DELETE FROM connectors WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
        await session.execute(sqlalchemy.text("DELETE FROM users WHERE id = CAST(:i AS uuid)"), {"i": str(ANALYST)})
        await session.commit()


@pytest_asyncio.fixture(loop_scope="module")
async def client(_env):  # noqa: ANN001
    from app.main import app as application

    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://api", timeout=30) as http:
        yield http


def analyst_token() -> str:
    from app.core.security import create_access_token

    return create_access_token({"sub": str(ANALYST), "tenant_id": str(TENANT), "role": "soc_analyst"})


async def _dispatch(client, params: dict) -> httpx.Response:  # noqa: ANN001
    return await client.post(
        URL,
        json={
            "capability": "get_host",
            "vendor_id": "crowdstrike",
            "target": "anyhost",
            "params": params,
            "dry_run": False,
        },
        headers={"Authorization": f"Bearer {analyst_token()}"},
    )


# ---------------------------------------------------------------------------
# The finding
# ---------------------------------------------------------------------------


async def test_an_analyst_cannot_point_a_stored_credential_at_a_host_it_names(client, connector, vendor):  # noqa: ANN001
    """The reporter's proof of concept, verbatim, against the shipped code.

    The marker path is what makes this unambiguous: the caller names a URL
    carrying ``/redirected``, so a request arriving under that prefix can only
    have come from the caller's value and not from the stored one.
    """
    _Vendor.seen.clear()

    response = await _dispatch(client, {"cs_base_url": f"{vendor}/redirected"})

    redirected = [call for call in _Vendor.seen if call["path"].startswith("/redirected")]
    assert redirected == [], f"the caller's URL was used: {redirected}"
    paid = " ".join(call["body"] for call in redirected)
    assert CLIENT_SECRET not in paid, "the tenant's stored CrowdStrike secret was sent to a caller-named path"
    body = response.json()
    assert body["executed"] is False, f"a refused step reported as executed: {body}"
    assert body["status"] == "failed", body


async def test_the_refusal_carries_no_secret_and_no_attacker_value(client, connector, vendor):  # noqa: ANN001
    """The console reads this body back, so it must reflect neither side."""
    _Vendor.seen.clear()

    response = await _dispatch(client, {"cs_base_url": f"{vendor}/redirected"})

    assert CLIENT_SECRET not in response.text, "the dispatch report carried the stored secret"
    assert CLIENT_ID not in response.text, "the dispatch report carried the stored client id"
    assert "/redirected" not in response.text, "the dispatch report echoed the caller's URL"
    assert "cs_base_url" in response.text, f"the refusal does not name the parameter: {response.text[:400]}"


# ---------------------------------------------------------------------------
# Positive control — the legitimate step must still reach the tenant's vendor
# ---------------------------------------------------------------------------


async def test_a_step_with_no_override_still_reaches_the_tenants_own_vendor(client, connector, vendor):  # noqa: ANN001
    """Stuck-closed reads as working caution, so this is the half that catches it.

    A dispatch carrying no connection override must still authenticate against
    the *stored* URL with the tenant's own credential — which is the product
    doing its job, and the reason the merge exists at all.
    """
    _Vendor.seen.clear()

    response = await _dispatch(client, {})

    bodies = " ".join(call["body"] for call in _Vendor.seen)
    assert f"client_secret={CLIENT_SECRET}" in bodies, f"the tenant's own CrowdStrike integration stopped working: {_Vendor.seen}"
    assert response.json()["status"] != "failed", response.text[:400]
