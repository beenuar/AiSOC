"""An investigation run is readable only by the tenant that launched it.

What was wrong (GHSA-mpxh-f6q6-6w8g)
------------------------------------
``services/agents/app/api/investigate.py`` launched a run, resolved the
caller's tenant with ``scoped_tenant_or_403`` — and then stored the run in
the process-wide ``_runs`` dict without it. Every read route (the status
poll, ``report.md``, ``report.html``, ``report.pdf`` and the WebSocket
stream) authenticated the caller, bound a principal, and looked the run up
by ``run_id`` alone. ``app/api/router.py`` did the same on its own ``_runs``
for ``GET /agent-runs/{run_id}``.

So a signed-in user of any tenant who learned another tenant's ``run_id``
was answered with that tenant's run: status, case id, audit log, recon,
forensic and responder output, and the full incident report once complete.
The sibling that had the comparison — the triage poll in
``app/api/triage.py`` — is what the fix mirrors.

What this asserts
-----------------
* Launch records the owner: the entry carries the tenant resolved from the
  credential, on both launch surfaces.
* Every HTTP read route answers a foreign caller **404, byte-identical** to
  the unknown-id 404 — a 403 on a real id and a 404 on an invented one would
  let a caller enumerate which run ids exist across tenants.
* The WebSocket stream treats another tenant's run exactly like no run at
  all: the caller falls through to the ad-hoc branch under their *own*
  tenant, so the socket is not an existence oracle either.
* ``router.py``'s completion/failure writes replace the entry wholesale, so
  they must carry the owner through — otherwise the owner's own completed
  run would start answering 404.
* Positive controls throughout: the owner still reads everything. A route
  that refuses everyone passes every negative assertion while broken.

Why this is a unit test rather than a live one
----------------------------------------------
Nothing on this path touches a database: the run store is a dict and the
credential is a JWT the guard verifies in process. The suite drives the
**real** routers with **real** signed tokens and nothing overridden except
the investigation engine itself, so it runs on every pull request.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

SECRET = "investigation-tenant-scope-secret-at-least-32-chars"
SERVICE_TOKEN = "investigation-tenant-scope-service-token"

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def console_token(tenant: uuid.UUID, *, role: str = "tenant_admin") -> str:
    """A console access token, signed the way ``services/api`` signs one.

    Minted here rather than by importing the API, because both services name
    their top-level package ``app`` and importing one shadows the other. The
    verifier on the path is the real one, which is the half that matters.
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


def auth(tenant: uuid.UUID) -> dict[str, str]:
    return {"Authorization": f"Bearer {console_token(tenant)}"}


@pytest.fixture(autouse=True)
def _env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Production posture: no dev bypass may resolve a demo principal here."""
    monkeypatch.setenv("ENVIRONMENT", "test")
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.delenv("AISOC_DEV_MODE", raising=False)
    monkeypatch.delenv("AISOC_DEV_AUTH_BYPASS", raising=False)
    yield


def _completed_run(run_id: str, tenant: uuid.UUID) -> dict[str, Any]:
    """A finished entry shaped like ``_run_and_store``'s ``done`` update."""
    return {
        "run_id": run_id,
        "case_id": "case-1",
        "tenant_id": str(tenant),
        "status": "completed",
        "report_md": "# Incident report\nsensitive",
        "report_html": "<html><body>sensitive</body></html>",
        "audit_log": [{"agent": "recon", "action": "ran"}],
        "recon": {"finding": "sensitive"},
        "forensic": {},
        "responder": {},
        "started_at": "2026-11-20T00:00:00",
        "completed_at": "2026-11-20T00:05:00",
        "error": None,
    }


@pytest.fixture()
def investigate_client(_env: None) -> Iterator[tuple[TestClient, Any]]:
    """The real investigate router, with the real guard, store cleared."""
    from app.api import investigate as investigate_api

    investigate_api._runs.clear()
    app = FastAPI()
    app.include_router(investigate_api.router)
    with TestClient(app) as test_client:
        yield test_client, investigate_api
    investigate_api._runs.clear()


@pytest.fixture()
def agent_runs_client(_env: None) -> Iterator[tuple[TestClient, Any]]:
    """The real ``router.py`` router (``/agent-runs``), store cleared."""
    from app.api import router as agent_router_api

    agent_router_api._runs.clear()
    app = FastAPI()
    app.include_router(agent_router_api.router)
    with TestClient(app) as test_client:
        yield test_client, agent_router_api
    agent_router_api._runs.clear()


# ---------------------------------------------------------------------------
# Launch records the owner
# ---------------------------------------------------------------------------


def test_launch_stores_the_credential_tenant_on_the_run(investigate_client, monkeypatch):
    client, investigate_api = investigate_client
    monkeypatch.setattr(investigate_api, "_run_and_store", _noop_run_and_store)

    resp = client.post(
        "/api/v1/cases/case-7/investigate",
        json={"alert_summary": "suspicious login", "tenant_id": str(TENANT_A)},
        headers=auth(TENANT_A),
    )
    assert resp.status_code == 200
    run_id = resp.json()["run_id"]
    assert investigate_api._runs[run_id]["tenant_id"] == str(TENANT_A)


async def _noop_run_and_store(run_id: str, case_id: str, req: Any) -> None:
    return None


def test_agent_runs_launch_stores_the_credential_tenant(agent_runs_client, monkeypatch):
    client, agent_router_api = agent_runs_client

    async def _noop(run_id: str, state: Any) -> None:
        return None

    monkeypatch.setattr(agent_router_api, "_run_investigation", _noop)
    resp = client.post(
        "/agent-runs",
        json={
            "incident_id": str(uuid.uuid4()),
            "tenant_id": str(TENANT_A),
            "alert_summary": "suspicious login",
        },
        headers=auth(TENANT_A),
    )
    assert resp.status_code == 200
    run_id = resp.json()["run_id"]
    assert agent_router_api._runs[run_id]["tenant_id"] == str(TENANT_A)


def test_agent_runs_failure_write_keeps_the_owner(agent_runs_client, monkeypatch):
    """``_run_investigation`` replaces the entry; the owner must survive."""
    import asyncio

    client, agent_router_api = agent_runs_client

    async def _boom(state: Any) -> Any:
        raise RuntimeError("engine down")

    monkeypatch.setattr(agent_router_api, "run_full_investigation", _boom)
    run_id = str(uuid.uuid4())
    agent_router_api._runs[run_id] = {"tenant_id": str(TENANT_A), "status": "running"}

    state = _minimal_state(agent_router_api, run_id)
    asyncio.run(agent_router_api._run_investigation(run_id, state))
    entry = agent_router_api._runs[run_id]
    assert entry["status"] == "failed"
    assert entry["tenant_id"] == str(TENANT_A)

    # And the owner can still read the failed run while a stranger cannot.
    assert client.get(f"/agent-runs/{run_id}", headers=auth(TENANT_A)).status_code == 200
    assert client.get(f"/agent-runs/{run_id}", headers=auth(TENANT_B)).status_code == 404


def _minimal_state(agent_router_api: Any, run_id: str) -> Any:
    from app.models.state import InvestigationState

    return InvestigationState(
        run_id=uuid.UUID(run_id),
        incident_id=uuid.uuid4(),
        tenant_id=TENANT_A,
        alert_summary="",
        raw_alert={},
    )


# ---------------------------------------------------------------------------
# HTTP read routes: foreign caller gets the unknown-id answer, owner reads
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path_tmpl",
    [
        "/api/v1/investigations/{run_id}",
        "/api/v1/investigations/{run_id}/report.md",
        "/api/v1/investigations/{run_id}/report.html",
        "/api/v1/investigations/{run_id}/report.pdf",
    ],
)
def test_foreign_tenant_gets_the_unknown_id_answer(investigate_client, path_tmpl):
    client, investigate_api = investigate_client
    run_id = str(uuid.uuid4())
    investigate_api._runs[run_id] = _completed_run(run_id, TENANT_A)

    foreign = client.get(path_tmpl.format(run_id=run_id), headers=auth(TENANT_B))
    unknown = client.get(path_tmpl.format(run_id=str(uuid.uuid4())), headers=auth(TENANT_B))

    assert foreign.status_code == 404
    # Byte-identical to the unknown-id refusal: a different body or status
    # would make the route an existence oracle across tenants.
    assert unknown.status_code == 404
    assert foreign.content == unknown.content


def test_owner_still_reads_status_and_reports(investigate_client):
    client, investigate_api = investigate_client
    run_id = str(uuid.uuid4())
    investigate_api._runs[run_id] = _completed_run(run_id, TENANT_A)

    poll = client.get(f"/api/v1/investigations/{run_id}", headers=auth(TENANT_A))
    assert poll.status_code == 200
    assert poll.json()["tenant_id"] == str(TENANT_A)

    md = client.get(f"/api/v1/investigations/{run_id}/report.md", headers=auth(TENANT_A))
    assert md.status_code == 200
    assert "sensitive" in md.text

    html = client.get(f"/api/v1/investigations/{run_id}/report.html", headers=auth(TENANT_A))
    assert html.status_code == 200

    # 200 with weasyprint installed, 501 without — never the foreign 404.
    pdf = client.get(f"/api/v1/investigations/{run_id}/report.pdf", headers=auth(TENANT_A))
    assert pdf.status_code in (200, 501)


def test_agent_runs_read_is_tenant_scoped(agent_runs_client):
    client, agent_router_api = agent_runs_client
    run_id = str(uuid.uuid4())
    agent_router_api._runs[run_id] = {
        "tenant_id": str(TENANT_A),
        "status": "completed",
        "result": {"verdict": "sensitive"},
    }

    owner = client.get(f"/agent-runs/{run_id}", headers=auth(TENANT_A))
    assert owner.status_code == 200
    assert owner.json()["result"]["verdict"] == "sensitive"

    foreign = client.get(f"/agent-runs/{run_id}", headers=auth(TENANT_B))
    unknown = client.get(f"/agent-runs/{uuid.uuid4()}", headers=auth(TENANT_B))
    assert foreign.status_code == 404
    assert foreign.content == unknown.content


# ---------------------------------------------------------------------------
# WebSocket stream: a foreign run behaves exactly like no run at all
# ---------------------------------------------------------------------------


def test_ws_owner_tails_the_run(investigate_client):
    client, investigate_api = investigate_client
    run_id = str(uuid.uuid4())
    investigate_api._runs[run_id] = _completed_run(run_id, TENANT_A)

    with client.websocket_connect(f"/api/v1/investigations/{run_id}/stream", headers=auth(TENANT_A)) as ws:
        first = json.loads(ws.receive_text())
        assert first["type"] == "step"  # the replayed audit entry
        done = json.loads(ws.receive_text())
        assert done["type"] == "done"
        assert done["status"] == "completed"


def test_ws_foreign_tenant_falls_through_to_adhoc_under_own_tenant(investigate_client, monkeypatch):
    """B connecting with A's run_id must not tail A's audit log.

    The indistinguishability requirement: the socket behaves exactly as it
    would for an unknown run_id — the ad-hoc branch, under B's own tenant.
    """
    client, investigate_api = investigate_client
    run_id = str(uuid.uuid4())
    investigate_api._runs[run_id] = _completed_run(run_id, TENANT_A)

    seen_tenants: list[str] = []

    def _fake_stream(**kwargs: Any) -> AsyncIterator[dict[str, Any]]:
        seen_tenants.append(kwargs["tenant_id"])

        async def _gen() -> AsyncIterator[dict[str, Any]]:
            yield {"type": "adhoc-sentinel"}

        return _gen()

    monkeypatch.setattr(investigate_api, "_investigate_stream", _fake_stream)

    with client.websocket_connect(f"/api/v1/investigations/{run_id}/stream", headers=auth(TENANT_B)) as ws:
        first = json.loads(ws.receive_text())

    assert first["type"] == "adhoc-sentinel"
    assert seen_tenants == [str(TENANT_B)]
