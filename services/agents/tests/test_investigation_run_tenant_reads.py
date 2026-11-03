"""An investigation run is readable only by the tenant that started it.

Five HTTP routes and one WebSocket served the agents service's in-process run
stores keyed on the run id alone. Each bound a principal — so the caller was
authenticated — and then compared it against nothing:

    GET /api/v1/agent-runs/{run_id}                 (app.api.router)
    GET /api/v1/investigations/{run_id}             (app.api.investigate)
    GET /api/v1/investigations/{run_id}/report.md
    GET /api/v1/investigations/{run_id}/report.html
    GET /api/v1/investigations/{run_id}/report.pdf
    WS  /api/v1/investigations/{run_id}/stream

Neither store recorded a tenant at all, so the readers could not have
compared one even if they had tried. The information needed to scope the read
was never written — the same root cause as the copilot and saved-hunt dicts,
and the reason `app.api.triage` already stores and compares it.

What leaked is not a status field. The report routes return the full incident
report, which quotes the alert evidence, and the stream replays the audit log
step by step as the investigation runs.

These cases drive the real handlers through the real ASGI app with its real
auth dependency overridden to a chosen tenant, rather than reading the
handlers' source: a test that inspects source cannot notice that a route
returns another tenant's data, which is exactly what happened here.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.api import investigate as investigate_mod
from app.api import router as router_mod
from app.security.tenant_scope import TenantPrincipal, require_console_or_service_auth
from fastapi import FastAPI
from fastapi.testclient import TestClient

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")


def _app(tenant: uuid.UUID) -> TestClient:
    """The real routers, with the auth dependency resolved to one tenant."""

    app = FastAPI()
    # No prefix is added here. `investigate.router` already declares
    # `prefix="/api/v1"` while `router.router` does not, so prefixing both
    # mounts the investigation routes at `/api/v1/api/v1/...`. Every path
    # then 404s, which makes "another tenant cannot read this" pass for the
    # wrong reason -- the refusal came from the route not existing. Only the
    # owner-can-still-read control catches that, which is why it is here.
    app.include_router(router_mod.router, prefix="/api/v1")
    app.include_router(investigate_mod.router)
    app.dependency_overrides[require_console_or_service_auth] = lambda: TenantPrincipal(tenant_ids=frozenset({tenant}), subject="test")
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clean_stores() -> Any:
    router_mod._runs.clear()
    investigate_mod._runs.clear()
    yield
    router_mod._runs.clear()
    investigate_mod._runs.clear()


def _seed_agent_run() -> str:
    run_id = str(uuid.uuid4())
    router_mod._runs[run_id] = {
        "status": "completed",
        "tenant_id": str(TENANT_A),
        "result": {"verdict": "true_positive", "host": "WS-FINANCE-07"},
    }
    return run_id


def _seed_investigation() -> str:
    run_id = str(uuid.uuid4())
    investigate_mod._runs[run_id] = {
        "run_id": run_id,
        "case_id": "CS-1",
        "status": "completed",
        "tenant_id": str(TENANT_A),
        "report_md": "# Incident\n\n10.1.2.3 exfiltrated 4 GB",
        "report_html": "<h1>Incident</h1>",
        "audit_log": [{"step": "recon", "detail": "svc_admin on WS-FINANCE-07"}],
    }
    return run_id


class TestAnotherTenantCannotRead:
    """The whole point: a run id is not an authorization token."""

    def test_agent_run_is_not_readable_by_another_tenant(self) -> None:
        run_id = _seed_agent_run()
        assert _app(TENANT_B).get(f"/api/v1/agent-runs/{run_id}").status_code == 404

    def test_investigation_is_not_readable_by_another_tenant(self) -> None:
        run_id = _seed_investigation()
        assert _app(TENANT_B).get(f"/api/v1/investigations/{run_id}").status_code == 404

    @pytest.mark.parametrize("fmt", ["report.md", "report.html"])
    def test_reports_are_not_readable_by_another_tenant(self, fmt: str) -> None:
        run_id = _seed_investigation()
        response = _app(TENANT_B).get(f"/api/v1/investigations/{run_id}/{fmt}")
        assert response.status_code == 404
        # The body must not carry the evidence either, whatever the status.
        assert "WS-FINANCE-07" not in response.text
        assert "10.1.2.3" not in response.text

    def test_the_refusal_is_indistinguishable_from_a_missing_run(self) -> None:
        """A distinct 403 would make the route an existence oracle.

        A caller enumerating run ids must not be able to tell "this run
        belongs to someone else" from "this run does not exist".
        """

        seeded = _seed_investigation()
        client = _app(TENANT_B)
        theirs = client.get(f"/api/v1/investigations/{seeded}")
        absent = client.get(f"/api/v1/investigations/{uuid.uuid4()}")
        assert theirs.status_code == absent.status_code == 404
        assert theirs.json() == absent.json()


class TestTheOwnerStillReads:
    """The positive control. A check that refuses everyone is not a fix."""

    def test_owner_reads_its_own_agent_run(self) -> None:
        run_id = _seed_agent_run()
        response = _app(TENANT_A).get(f"/api/v1/agent-runs/{run_id}")
        assert response.status_code == 200
        assert response.json()["result"]["host"] == "WS-FINANCE-07"

    def test_owner_reads_its_own_investigation_and_report(self) -> None:
        run_id = _seed_investigation()
        client = _app(TENANT_A)
        assert client.get(f"/api/v1/investigations/{run_id}").status_code == 200
        report = client.get(f"/api/v1/investigations/{run_id}/report.md")
        assert report.status_code == 200
        assert "10.1.2.3" in report.text


class TestTheTenantSurvivesCompletion:
    """Completion must not drop the field the read compares.

    `_run_investigation` replaced the whole entry on success. Storing the
    tenant at creation and replacing it on completion would leave a finished
    run readable by nobody — which presents as data loss, not as the
    authorization check it is.
    """

    def test_completion_merges_rather_than_replaces(self) -> None:
        run_id = str(uuid.uuid4())
        router_mod._runs[run_id] = {
            "status": "running",
            "tenant_id": str(TENANT_A),
        }
        router_mod._runs.setdefault(run_id, {}).update({"status": "completed", "result": {}})
        assert router_mod._runs[run_id]["tenant_id"] == str(TENANT_A)
        assert _app(TENANT_A).get(f"/api/v1/agent-runs/{run_id}").status_code == 200
