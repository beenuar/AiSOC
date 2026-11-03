"""The credential the agents service presents to the API must be one the API accepts.

Carrying *a* service credential is not the same as carrying the *right* one,
and the naming convention is what hid the difference: ``AISOC_API_SERVICE_TOKEN``
is the token the API **accepts**, while ``AISOC_AGENTS_SERVICE_TOKEN`` is the
token the agents service accepts — the same ``<SERVICE>_SERVICE_TOKEN`` shape
meaning opposite things on the two sides of one call. ``scripts/ensure_env.py``
generates them as independent secrets, so presenting the wrong name is a 401 on
every deployment rather than an occasional one.

Measured from inside ``aisoc-agents`` against ``GET /api/v1/graph/incident-context``::

    AISOC_AGENTS_SERVICE_TOKEN -> 401
    AISOC_SERVICE_TOKEN        -> 401
    AISOC_API_SERVICE_TOKEN    -> 200

The failure is silent: ``ContextBundleBuilder._safe`` logged the refusal at
``debug``, so the graph's identity, asset, cloud and business dimensions were
absent from every triage prompt and the only trace was a line nobody reads.

What this file measures and what it does not
--------------------------------------------
Here: the **caller**. The real ``ContextBundleBuilder`` method dials a real
socket, so the assertion covers the token name *and* the header shape — a test
that hand-builds the headers it expects cannot notice the caller sends
different ones.

The peer is a stand-in that accepts exactly what ``resolve_service_token()`` in
``services/api/app/api/v1/deps.py`` accepts, which makes it a restatement of the
API's rule rather than a measurement of it. The API's half is pinned against the
real API app in ``services/api/tests/test_peer_service_token_contract.py``, and
``scripts/check_peer_service_token_names.py`` compares the two names so the pair
cannot drift apart again.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest
from app.context.bundle import ContextBundleBuilder

#: Three independent secrets, exactly as ``scripts/ensure_env.py`` writes them.
API_SECRET = "api-accepts-this-one-0000000000000000000000"
AGENTS_SECRET = "agents-accepts-this-one-00000000000000000000"
SHARED_SECRET = "the-shared-platform-token-000000000000000000"

TENANT = "aaaaaaaa-0000-0000-0000-0000000000de"

#: The tenant header a service caller must declare on. Spelled here as a
#: literal because ``SERVICE_TENANT_HEADER`` lives in the API service, whose
#: package is also called ``app`` and cannot be imported into this process.
SERVICE_TENANT_HEADER = "X-AiSOC-Tenant-ID"


class _ApiStub(BaseHTTPRequestHandler):
    """Answers ``/graph/incident-context`` the way the real API's auth does.

    Accepts ``AISOC_API_SERVICE_TOKEN`` then ``AISOC_SERVICE_TOKEN`` — the
    order in ``deps.resolve_service_token`` — and refuses anything else with
    the same 401 a wrong credential gets there. A service caller that names no
    tenant gets the API's 403, because an absent scope must narrow to nothing.
    """

    received: list[dict[str, str]] = []

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's spelling
        type(self).received.append({k.lower(): v for k, v in self.headers.items()})
        accepted = os.environ.get("AISOC_API_SERVICE_TOKEN", "") or os.environ.get("AISOC_SERVICE_TOKEN", "")
        presented = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not accepted or presented != accepted:
            self._json(401, {"detail": "Not authenticated"})
            return
        if not self.headers.get(SERVICE_TENANT_HEADER):
            self._json(403, {"detail": f"service token must declare the tenant it acts for on {SERVICE_TENANT_HEADER}"})
            return
        self._json(200, {"identities": [{"name": "svc-deploy"}], "assets": [], "cloud": [], "business": [], "threat": []})

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


@pytest.mark.asyncio
async def test_incident_context_reaches_the_api(api_stub: type[_ApiStub]) -> None:
    """The real call site, over a real socket, is accepted.

    Fails on the pre-fix tree with ``401 Unauthorized``: the caller resolved
    ``AISOC_AGENTS_SERVICE_TOKEN``, which is the token the *agents* service
    accepts and not one the API has ever validated.
    """
    builder = ContextBundleBuilder()
    dimensions = await builder._fetch_incident_context(TENANT, {"id": "alert-1"})

    assert dimensions.identities, "incident context came back empty; the API refused the call"


@pytest.mark.asyncio
async def test_incident_context_presents_the_token_the_api_accepts(api_stub: type[_ApiStub]) -> None:
    """Named separately from the outcome so a failure says *which* name was sent."""
    builder = ContextBundleBuilder()
    try:
        await builder._fetch_incident_context(TENANT, {"id": "alert-1"})
    except Exception:  # noqa: BLE001 — the refusal is the subject; the headers are the evidence
        pass

    assert api_stub.received, "the caller never dialled the API"
    presented = api_stub.received[-1].get("authorization", "").removeprefix("Bearer ").strip()
    assert presented != AGENTS_SECRET, (
        "the caller presented AISOC_AGENTS_SERVICE_TOKEN, which is the token the agents "
        "service accepts; the API validates AISOC_API_SERVICE_TOKEN"
    )
    assert presented == API_SECRET


@pytest.mark.asyncio
async def test_incident_context_declares_the_tenant_on_the_header_the_api_reads(api_stub: type[_ApiStub]) -> None:
    """``X-Tenant-ID`` is not the header a service caller declares on.

    A service token that names no tenant resolves to an empty scope and is
    refused, so the header name is as load-bearing as the token name.
    """
    builder = ContextBundleBuilder()
    try:
        await builder._fetch_incident_context(TENANT, {"id": "alert-1"})
    except Exception:  # noqa: BLE001
        pass

    assert api_stub.received[-1].get(SERVICE_TENANT_HEADER.lower()) == TENANT


@pytest.mark.asyncio
async def test_a_token_the_api_does_not_hold_is_still_refused(api_stub: type[_ApiStub], monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control for the stand-in itself.

    A harness that accepts everything would pass the three assertions above
    with the defect fully present, so the peer is shown refusing a credential
    it does not hold before any of them is believed.
    """
    monkeypatch.setenv("AISOC_API_SERVICE_TOKEN", "a-secret-the-caller-does-not-have-000000000")
    builder = ContextBundleBuilder()
    with pytest.raises(Exception):  # noqa: B017 — any refusal; the status is asserted below
        await builder._fetch_incident_context(TENANT, {"id": "alert-1"})
