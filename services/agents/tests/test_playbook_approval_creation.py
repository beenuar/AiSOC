"""A playbook ``approval`` step must open an approval, or refuse to pause.

The README lists "a durable approval pause ... resumes after the approval" as
Stable. The resume half could not occur, for three independent reasons that all
had to be fixed together:

1. ``_create_approval`` presented ``AISOC_AGENTS_SERVICE_TOKEN`` — the token the
   *agents* service accepts — to an API that validates
   ``AISOC_API_SERVICE_TOKEN``. Measured: 401.
2. It declared the tenant on ``X-Tenant-ID``. The API's service auth reads
   ``X-AiSOC-Tenant-ID``, and a service token that names no tenant resolves to
   an empty scope. Measured with the right token: 403.
3. The service principal's permissions did not include the one
   ``POST /api/v1/approvals`` demands. Measured with the right token and the
   right header: 403 ``Permission denied``.

And the failure mode was the worst available: ``_create_approval`` returns
``None``, and the run **still** called ``playbook_pause.suspend(approval_id=None)``
— a pause with nothing for any human to decide against, under a docstring on
``_suspend_for_approval`` that already said "if the approval cannot be created
the pause is not written either". The code did not do what its own docstring
claimed, so a reader checking this property found it documented and absent.

The run reaches a real socket here rather than a mocked client, because two of
the three defects are in the *request* — a test that asserts on a parsed result
cannot see a missing header.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import httpx
import pytest
from app.playbook import engine as engine_module
from app.playbook import pause as playbook_pause
from app.playbook.engine import PlaybookRun
from app.playbook.models import Playbook, PlaybookStep, StepType

API_SECRET = "api-accepts-this-one-0000000000000000000000"
AGENTS_SECRET = "agents-accepts-this-one-00000000000000000000"
SHARED_SECRET = "the-shared-platform-token-000000000000000000"

TENANT = "aaaaaaaa-0000-0000-0000-0000000000de"
SERVICE_TENANT_HEADER = "X-AiSOC-Tenant-ID"

#: What the service principal must hold for ``POST /api/v1/approvals``.
#: Spelled as a literal because the API service's package is also called
#: ``app`` and cannot be imported into this process; the API half is asserted
#: against the real route in ``services/api/tests/test_service_approval_permission.py``.
APPROVAL_PERMISSION = "approvals:write"


class _ApiStub(BaseHTTPRequestHandler):
    """``POST /api/v1/approvals`` with the API's three refusals, in its order.

    401 on a credential it does not hold, then 403 for a service caller that
    names no tenant, then 403 for a principal without the permission. Ordered
    the way the real API orders them so a fix for one does not accidentally
    read as a fix for another.
    """

    received: list[dict[str, Any]] = []
    granted: set[str] = set()

    def do_POST(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's spelling
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        headers = {k.lower(): v for k, v in self.headers.items()}
        type(self).received.append({"headers": headers, "body": body})

        presented = headers.get("authorization", "").removeprefix("Bearer ").strip()
        if presented != API_SECRET:
            self._json(401, {"detail": "Not authenticated"})
            return
        if not headers.get(SERVICE_TENANT_HEADER.lower()):
            self._json(403, {"detail": f"service token must declare the tenant it acts for on {SERVICE_TENANT_HEADER}"})
            return
        if APPROVAL_PERMISSION not in type(self).granted:
            self._json(403, {"detail": f"Permission denied: {APPROVAL_PERMISSION}"})
            return
        self._json(201, {"id": "approval-0001"})

    def _json(self, status: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args: Any) -> None:
        """Silence the handler's stderr access log."""


@pytest.fixture()
def api_stub(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[_ApiStub]]:
    _ApiStub.received = []
    _ApiStub.granted = {APPROVAL_PERMISSION}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ApiStub)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    monkeypatch.setenv("AISOC_API_URL", f"http://127.0.0.1:{server.server_address[1]}")
    monkeypatch.setenv("AISOC_API_SERVICE_TOKEN", API_SECRET)
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", AGENTS_SECRET)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SHARED_SECRET)
    try:
        yield _ApiStub
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def suspensions(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Every ``playbook_pause.suspend`` call, so "did it pause" is observable.

    The durable row needs Postgres; what this file is about is whether the
    engine decides to write one at all, and with what approval id.
    """
    calls: list[dict[str, Any]] = []

    async def _suspend(**kwargs: Any) -> str:
        calls.append(kwargs)
        return "pause-0001"

    monkeypatch.setattr(playbook_pause, "suspend", _suspend)
    return calls


def _run() -> tuple[PlaybookRun, PlaybookStep]:
    step = PlaybookStep(id="s1", name="Approve containment", type=StepType.APPROVAL, params={})
    playbook = Playbook(id="pb1", name="Contain host", steps=[step])
    pr = PlaybookRun(playbook, {"tenant_id": TENANT})
    return pr, step


@pytest.mark.asyncio
async def test_the_approval_is_created(api_stub: type[_ApiStub], suspensions: list[dict[str, Any]]) -> None:
    """The whole point of the step. Fails on the pre-fix tree with 401."""
    pr, step = _run()
    async with httpx.AsyncClient() as http:
        await engine_module._suspend_for_approval(pr, step, 0, http)

    assert api_stub.received, "the engine never dialled the API"
    assert suspensions and suspensions[0]["approval_id"] == "approval-0001"


@pytest.mark.asyncio
async def test_it_presents_the_token_the_api_accepts(api_stub: type[_ApiStub], suspensions: list[dict[str, Any]]) -> None:
    pr, step = _run()
    async with httpx.AsyncClient() as http:
        await engine_module._suspend_for_approval(pr, step, 0, http)

    presented = api_stub.received[-1]["headers"].get("authorization", "").removeprefix("Bearer ").strip()
    assert presented != AGENTS_SECRET, "AISOC_AGENTS_SERVICE_TOKEN is the token this service accepts, not the API's"
    assert presented == API_SECRET


@pytest.mark.asyncio
async def test_it_declares_the_tenant_on_the_header_the_api_reads(api_stub: type[_ApiStub], suspensions: list[dict[str, Any]]) -> None:
    pr, step = _run()
    async with httpx.AsyncClient() as http:
        await engine_module._suspend_for_approval(pr, step, 0, http)

    headers = api_stub.received[-1]["headers"]
    assert headers.get(SERVICE_TENANT_HEADER.lower()) == TENANT
    assert "x-tenant-id" not in headers, "the header the API's service auth never reads must be gone"


@pytest.mark.asyncio
async def test_a_failed_approval_refuses_to_suspend(api_stub: type[_ApiStub], suspensions: list[dict[str, Any]]) -> None:
    """The docstring's own claim, which the code did not keep.

    A pause carrying ``approval_id=None`` is a run halted forever with nothing
    for anyone to decide against — strictly worse than failing the step, which
    at least surfaces.
    """
    api_stub.granted = set()  # the API refuses the permission

    pr, step = _run()
    async with httpx.AsyncClient() as http:
        result = await engine_module._suspend_for_approval(pr, step, 0, http)

    assert result is None, "the step must fail closed when no approval exists"
    assert suspensions == [], "suspended with no approval for anyone to act on"


@pytest.mark.asyncio
async def test_the_stub_refuses_a_credential_it_does_not_hold(api_stub: type[_ApiStub]) -> None:
    """Control for the harness.

    A peer that accepts anything would pass every assertion above with all
    three defects present, so it is shown issuing each refusal before any of
    them is believed.
    """
    url = f"{os.environ['AISOC_API_URL']}/api/v1/approvals"
    async with httpx.AsyncClient() as client:
        wrong_token = await client.post(
            url,
            headers={"Authorization": f"Bearer {AGENTS_SECRET}", SERVICE_TENANT_HEADER: TENANT},
            json={},
        )
        no_tenant = await client.post(url, headers={"Authorization": f"Bearer {API_SECRET}"}, json={})
        api_stub.granted = set()
        no_permission = await client.post(
            url,
            headers={"Authorization": f"Bearer {API_SECRET}", SERVICE_TENANT_HEADER: TENANT},
            json={},
        )

    assert (wrong_token.status_code, no_tenant.status_code, no_permission.status_code) == (401, 403, 403)
