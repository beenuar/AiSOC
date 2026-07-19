"""Tests for the demo-mode middleware.

These verify the gate behaves correctly in both modes:

- When `AISOC_DEMO_MODE=False`, the middleware is transparent — every request
  flows through and responses do **not** carry demo headers.
- When `AISOC_DEMO_MODE=True`, GET requests succeed and pick up the banner
  headers, allowlisted writes (kickoff against the showcase `INC-RT-001`
  ransomware case or any stock `INC-NNN` catalogue case, plus alert ack)
  succeed, and arbitrary mutating writes return 403 with the
  `demo_mode_read_only` error code.

The middleware is the *only* thing under test; we mount it on a stub Starlette
app so the test doesn't pull in the real DB / auth stack.
"""

from __future__ import annotations

from typing import Any

import pytest
from app.core.config import settings
from app.middleware.demo_mode import DemoModeMiddleware
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """Build a stub app with the middleware wired up."""
    monkeypatch.setattr(settings, "AISOC_DEMO_MODE", True)
    monkeypatch.setattr(settings, "AISOC_DEMO_TENANT", "demo")
    app = FastAPI()
    app.add_middleware(DemoModeMiddleware)

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True}

    @app.get("/api/v1/cases")
    def list_cases() -> dict[str, Any]:
        return {"cases": []}

    @app.post("/api/v1/cases")
    def create_case() -> dict[str, Any]:
        # Real handler would write to DB; in demo mode we should never reach it.
        return {"created": True}

    @app.delete("/api/v1/cases/{case_id}")
    def delete_case(case_id: str) -> dict[str, Any]:
        return {"deleted": case_id}

    @app.post("/api/v1/cases/{case_number}/investigate")
    def investigate(case_number: str) -> dict[str, Any]:
        return {"run_id": "demo-run-123", "case_number": case_number}

    @app.post("/api/v1/alerts/{alert_id}/ack")
    def ack(alert_id: str) -> dict[str, Any]:
        return {"acked": alert_id}

    @app.post("/api/v1/auth/login")
    def login() -> dict[str, Any]:
        return {"token": "fake"}

    @app.post("/api/v1/waitlist/signup")
    def waitlist_signup() -> dict[str, Any]:
        return {"ok": True}

    return app


def test_demo_mode_off_is_transparent(monkeypatch: pytest.MonkeyPatch) -> None:
    """With demo mode off the middleware is a passthrough — no headers, no gates."""
    monkeypatch.setattr(settings, "AISOC_DEMO_MODE", False)
    app = FastAPI()
    app.add_middleware(DemoModeMiddleware)

    @app.post("/api/v1/cases")
    def create_case() -> dict[str, Any]:
        return {"created": True}

    client = TestClient(app)
    r = client.post("/api/v1/cases")
    assert r.status_code == 200
    assert r.json() == {"created": True}
    assert "X-AiSOC-Demo" not in r.headers


def test_get_request_succeeds_with_banner_headers(app: FastAPI) -> None:
    client = TestClient(app)
    r = client.get("/api/v1/cases")
    assert r.status_code == 200
    assert r.headers["X-AiSOC-Demo"] == "true"
    assert r.headers["X-AiSOC-Demo-Tenant"] == "demo"
    assert "resets daily" in r.headers["X-AiSOC-Demo-Banner"].lower()


def test_health_endpoint_is_always_allowed(app: FastAPI) -> None:
    """`/health` must answer 200 even in demo mode so Fly.io health checks pass."""
    client = TestClient(app)
    r = client.get("/health")
    assert r.status_code == 200


def test_arbitrary_post_is_blocked_with_403(app: FastAPI) -> None:
    client = TestClient(app)
    r = client.post("/api/v1/cases", json={"title": "evil"})
    assert r.status_code == 403
    body = r.json()
    assert body["error"] == "demo_mode_read_only"
    assert body["blocked_method"] == "POST"
    assert body["blocked_path"] == "/api/v1/cases"
    assert "self_host_url" in body
    # 403 still gets banner headers so the UI can render the banner over the error.
    assert r.headers["X-AiSOC-Demo"] == "true"


def test_arbitrary_delete_is_blocked_with_403(app: FastAPI) -> None:
    client = TestClient(app)
    r = client.delete("/api/v1/cases/INC-007")
    assert r.status_code == 403
    assert r.json()["error"] == "demo_mode_read_only"


def test_canonical_investigation_kickoff_is_allowed(app: FastAPI) -> None:
    """The canned demo flow must work end-to-end against the showcase case.

    The README "Try Demo" CTA deeplinks to ``/cases/INC-RT-001?tab=ledger`` —
    the in-flight LockBit 3.0 ransomware investigation — so kicking off a
    fresh agent run there must succeed under the demo-mode gate.
    """
    client = TestClient(app)
    r = client.post("/api/v1/cases/INC-RT-001/investigate")
    assert r.status_code == 200
    body = r.json()
    assert body["run_id"] == "demo-run-123"
    assert body["case_number"] == "INC-RT-001"
    assert r.headers["X-AiSOC-Demo"] == "true"


def test_stock_catalogue_investigation_kickoff_is_allowed(app: FastAPI) -> None:
    """Stock catalogue cases (INC-001 … INC-014) must also be investigatable.

    Visitors who navigate the case list will click into other seeded
    incidents; the demo-mode gate must let them kick off agent runs there
    without a 403.
    """
    client = TestClient(app)
    r = client.post("/api/v1/cases/INC-007/investigate")
    assert r.status_code == 200
    assert r.json()["case_number"] == "INC-007"


def test_unseeded_case_kickoff_is_blocked(app: FastAPI) -> None:
    """A made-up case ID must NOT bypass the gate — only seeded shapes do."""
    client = TestClient(app)
    r = client.post("/api/v1/cases/EVIL-CASE/investigate")
    assert r.status_code == 403
    assert r.json()["error"] == "demo_mode_read_only"


def test_alert_acknowledge_is_allowed(app: FastAPI) -> None:
    client = TestClient(app)
    r = client.post("/api/v1/alerts/abc-123/ack")
    assert r.status_code == 200
    assert r.json() == {"acked": "abc-123"}


def test_auth_login_is_allowed(app: FastAPI) -> None:
    """Auth endpoints must work in demo mode so visitors can be issued a session."""
    client = TestClient(app)
    r = client.post("/api/v1/auth/login", json={"username": "demo", "password": "demo"})
    assert r.status_code == 200
    assert r.json() == {"token": "fake"}


def test_waitlist_signup_is_allowed(app: FastAPI) -> None:
    """Managed-instance waitlist must accept signups on the public demo host.

    ``/waitlist`` is the conversion funnel for tryaisoc.com. Demo-mode must
    not 403 the POST — waitlist rows are not part of the shared demo SOC
    dataset, so allowing the write does not let visitors mutate the canned
    alerts/cases every other visitor sees.
    """
    client = TestClient(app)
    r = client.post(
        "/api/v1/waitlist/signup",
        json={
            "email": "champ@acme.com",
            "company": "Acme",
            "role": "SOC Manager",
            "soc_stack": ["Splunk"],
            "motivation": "Alert volume is drowning the team.",
        },
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}
    assert r.headers["X-AiSOC-Demo"] == "true"


def test_options_preflight_is_allowed(app: FastAPI) -> None:
    """CORS preflight (OPTIONS) is a safe method; gate must let it through."""
    client = TestClient(app)
    r = client.options(
        "/api/v1/cases",
        headers={"Origin": "https://tryaisoc.com", "Access-Control-Request-Method": "GET"},
    )
    # FastAPI's TestClient + CORSMiddleware would normally answer this; without
    # CORSMiddleware it 405s, but the demo-mode middleware itself never blocks
    # the OPTIONS verb. So we accept either 200 or 405 — the assertion is only
    # that the demo-mode 403 path was *not* taken.
    assert r.status_code != 403
