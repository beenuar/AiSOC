"""Every API-to-connectors call carries the service token and the tenant.

Fix pass item 1.2. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
`services/connectors/app/api/router.py` mounts its whole router behind
`Depends(require_console_or_service_auth)`. A bearer credential is mandatory,
and a *service* token must additionally declare the tenant it acts for,
because an absent scope there is an empty scope rather than every scope.

Two callers in `services/api` sent neither:

* `federated.py` posted the unified query with `client.post(url, json=payload)`,
  so federated search, the agent's federated tool and the retro-hunt SIEM sweep
  were answered **401 by every SIEM**.
* `case_fanout.py` pushed cases and polled their status the same way.

The catalog proxy twenty lines away in `connectors.py` already did it
correctly, which is the shape worth noting: one call site was fixed when this
was last found, and its siblings kept shipping.

Why the offline suites did not catch it
---------------------------------------
They mock the connectors service with a transport that answers whatever it is
asked. A fake that never authenticates cannot notice a caller that never
authenticates.

Why this lives here and not in `services/api/tests/`
-----------------------------------------------------
It needs **both** services installed: the API's `_query_one_backend` on one
side and the connectors application on the other. `ci.yml`'s API job installs
only the API's lockfile, so the first home for this file errored there with
`ModuleNotFoundError: apscheduler`. `tests/isolation/` is where a test that
spans two services belongs, and `agent-auth-live.yml` installs both.

Why this runs the far side in a subprocess
------------------------------------------
Both services name their top-level package `app`. Importing the connectors
router into this suite shadows the API's own package, and the first attempt at
this file resolved `app.api.v1` inside the connectors tree, where it does not
exist. Making the test skip around that would have been worse than not writing
it: a skipping test reports the same word as a passing one.

So the real connectors application is started as its own process on a loopback
socket, and the request crosses a real one. That is also closer to the
deployment, where these are two containers.

What this file asserts
----------------------
A request built by the API's own `_catalog_headers` helper is **accepted** by
the real `require_console_or_service_auth` dependency; the same request with
the credential or the tenant removed is **refused**.

Against the pre-fix tree the first assertion fails with 401, which is what
every federated search returned on every deployment.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

pytestmark = pytest.mark.anyio

SERVICE_TOKEN = "fixpass-connectors-token-not-a-real-secret"
TENANT = str(uuid.uuid4())

_REPO = Path(__file__).resolve().parents[2]
_CONNECTORS = _REPO / "services" / "connectors"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def connectors_base_url():  # noqa: C901
    """The real connectors service, on a loopback socket, with real auth.

    Not a stand-in and not an in-process mount. The question is whether the
    headers the API sends satisfy that service's own dependency, and only that
    dependency can answer it.
    """
    if not (_CONNECTORS / "app" / "main.py").is_file():
        pytest.fail(f"the connectors service is not at {_CONNECTORS}; this test cannot be skipped into passing")

    port = _free_port()
    env = {
        **os.environ,
        "AISOC_SERVICE_TOKEN": SERVICE_TOKEN,
        "AISOC_CONNECTORS_SERVICE_TOKEN": SERVICE_TOKEN,
        "AISOC_CONNECTORS_DISABLE_SCHEDULER": "1",
        "OTEL_SDK_DISABLED": "true",
        "PYTHONPATH": str(_CONNECTORS),
    }
    # Production posture: the anonymous shim must be off, or every negative
    # control below passes for the wrong reason.
    env.pop("AISOC_DEV_MODE", None)
    env.pop("AISOC_DEV_AUTH_BYPASS", None)

    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            # `app.main:app`, not a router re-mounted here. Re-mounting it
            # dropped the `/api/v1` prefix the real service uses, so the
            # first run of this test got 404 where the deployment gets 401:
            # a harness artefact that reads exactly like a passing test.
            "import uvicorn\n"
            "from app.main import app as connectors_app\n"
            f"uvicorn.run(connectors_app, host='127.0.0.1', port={port}, log_level='error')\n",
        ],
        cwd=str(_CONNECTORS),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    while time.time() < deadline:
        if proc.poll() is not None:
            output = (proc.stdout.read() or b"").decode()[-2000:]
            pytest.fail(f"the connectors service exited before serving:\n{output}")
        try:
            httpx.get(f"{base}/openapi.json", timeout=1.0)
            break
        except httpx.HTTPError:
            time.sleep(0.2)
    else:
        proc.terminate()
        pytest.fail("the connectors service did not start within 30s")

    yield base

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:  # pragma: no cover - teardown guard
        proc.kill()


async def _post(base: str, headers: dict[str, str]) -> int:
    async with httpx.AsyncClient(base_url=base, timeout=10.0) as client:
        response = await client.post(
            f"/api/v1/connectors/{uuid.uuid4()}/query",
            json={"auth_config": {}, "connector_config": {}, "query": {}},
            headers=headers,
        )
    return response.status_code


@pytest.fixture(autouse=True)
def _api_side_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """The token the API presents, in the process that builds the headers.

    `_catalog_headers` reads it here, not in the subprocess, so without this
    the helper would send an empty bearer and the positive assertion would
    fail for a harness reason that looks exactly like the defect.
    """
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("AISOC_CONNECTORS_SERVICE_TOKEN", SERVICE_TOKEN)


class TestTheProductionCallPath:
    """`federated.py`'s own request, not a hand-written stand-in for it.

    The helper has worked since the catalog proxy was fixed. What shipped
    broken is that federated search never called it, so a test that exercised
    the helper would have passed on the defective tree.
    """

    async def test_the_federated_backend_query_is_accepted(self, connectors_base_url, monkeypatch: pytest.MonkeyPatch) -> None:
        # Imported here rather than at module scope: the offline isolation job
        # collects this directory with no service installed, and a module-level
        # service import errors collection for the whole directory.
        federated_mod = pytest.importorskip(
            "app.api.v1.endpoints.federated",
            reason="services/api is not installed in this job",
        )
        monkeypatch.setattr(federated_mod.settings, "CONNECTORS_SERVICE_URL", connectors_base_url, raising=False)

        connector = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=uuid.UUID(TENANT),
            name="prod-splunk",
            connector_type="splunk",
            connector_config={},
            auth_config={},
        )
        monkeypatch.setattr(federated_mod, "decrypt_dict", lambda value: dict(value or {}), raising=False)

        verdict, _rows = await federated_mod._query_one_backend(
            # A stand-in for the ORM row, carrying only the five attributes
            # this function reads. Constructing a real `Connector` would need
            # a session and a tenant, neither of which this test is about: the
            # question is which headers leave the process.
            connector,  # type: ignore[arg-type]
            {"query": {}},
            httpx.Timeout(10.0, connect=5.0),
        )

        status = getattr(verdict, "status", "") or getattr(verdict, "state", "")
        error = str(getattr(verdict, "error", "") or getattr(verdict, "detail", "") or "")
        assert "401" not in error and "unauthor" not in error.lower(), (
            f"federated search was refused by the connectors service: status={status!r} error={error!r}"
        )

    async def test_the_api_helper_produces_headers_the_connectors_service_accepts(self, connectors_base_url) -> None:
        """The credential itself is good; this pins that separately."""
        connectors_mod = pytest.importorskip(
            "app.api.v1.endpoints.connectors",
            reason="services/api is not installed in this job",
        )
        status = await _post(connectors_base_url, connectors_mod._catalog_headers(TENANT))

        assert status not in (401, 403), f"the connectors service refused the credential the API sends: HTTP {status}"


class TestTheNegativeControls:
    async def test_no_credential_is_refused(self, connectors_base_url) -> None:
        """The pre-fix call, exactly: a body and nothing else."""
        assert await _post(connectors_base_url, {}) in (401, 403)

    async def test_a_service_token_without_a_tenant_is_refused(self, connectors_base_url) -> None:
        """An absent scope is an empty scope, never every scope."""
        status = await _post(connectors_base_url, {"Authorization": f"Bearer {SERVICE_TOKEN}"})
        assert status in (401, 403), f"a service token with no tenant was served: HTTP {status}"

    async def test_a_forged_token_is_refused(self, connectors_base_url) -> None:
        status = await _post(
            connectors_base_url,
            {"Authorization": "Bearer not-the-token", "X-AiSOC-Tenant-ID": TENANT},
        )
        assert status in (401, 403), f"a forged token was served: HTTP {status}"


# The "every caller uses it" half is deliberately **not** re-implemented here.
#
# `scripts/check_service_token_wiring.py` already walks every service-to-service
# request in the tree and resolves each URL through its helper, its settings
# attribute and its intermediate variable. A second AST walk in this file was
# written first and was worse at it: it matched any call in a module whose text
# mentioned "connectors", so it named five call sites that reach the agents
# service and a vendor instead. Two walkers over one tree that disagree about
# what they are looking at is a defect this repository has already shipped.
#
# So the gate owns the property, and this file owns the question the gate
# cannot answer: whether the headers the API builds actually satisfy the
# dependency on the far side.
