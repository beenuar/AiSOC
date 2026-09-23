"""The signed email-approval link must resolve, and must carry an identity.

`app/services/email_approval.py` shipped a complete issuer and verifier whose
URLs pointed at ``/v1/actions/email-decide`` — a path that appeared nowhere
else in the tree. Every approve and deny button in a rendered approval email
linked to a 404, so the documented fallback for "Slack and Teams are
unreachable" failed exactly when it was needed.

The token also signed only decision, action and case. A link with no recipient
in it is a bearer credential: whoever holds it approves, and the approval
reaches the actions service with no principal, so the permission tier and
separation of duties are skipped — the same hole the ChatOps path had.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from app.api.v1.endpoints import email_approval as endpoint
from app.services.email_approval import EmailApprovalError, approval_url, issue_token, verify_token
from fastapi import FastAPI
from fastapi.testclient import TestClient

SECRET = "test-signing-secret"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AISOC_EMAIL_APPROVAL_SECRET", SECRET)
    app = FastAPI()
    app.include_router(endpoint.router, prefix="/api/v1")
    return TestClient(app)


def _token(**kwargs) -> str:
    params = {
        "decision": "approved",
        "action_id": "act-1",
        "case_id": "case-1",
        "secret": SECRET,
        "approver": "dana@example.com",
    }
    params.update(kwargs)
    return issue_token(**params)


class _StubResponse:
    def __init__(self, status_code: int, payload: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}

    def json(self) -> dict:
        return self._payload


def _stub_post(monkeypatch: pytest.MonkeyPatch, response: _StubResponse, recorder: list | None = None):
    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, url, json=None, headers=None):
            if recorder is not None:
                recorder.append({"url": url, "json": json, "headers": headers})
            return response

    monkeypatch.setattr(endpoint.httpx, "AsyncClient", lambda **_: _Client())


# ── the route exists at the path the emails link to ────────────────────────


def test_the_url_the_issuer_mints_is_the_url_the_router_serves(client: TestClient) -> None:
    """The regression. The default used to be /v1/actions/email-decide, a path
    no router served, so every button in a rendered email 404'd."""
    url = approval_url(
        base_url="https://console.example",
        decision="approved",
        action_id="act-1",
        case_id="case-1",
        secret=SECRET,
        approver="dana@example.com",
    )
    path = url.split("https://console.example", 1)[1].split("?", 1)[0]
    assert path == "/api/v1/actions/email-decide"

    # Asserted by requesting it rather than by inspecting `app.routes`: a
    # route table can list a path that the mounted prefix does not actually
    # serve, and a 404 here is precisely the bug. Any status other than 404
    # means the path resolves — the token is deliberately absent, so a 422
    # for the missing required query parameter is the expected answer.
    assert client.get(path).status_code != 404


# ── the approver is signed in ──────────────────────────────────────────────


def test_the_recipient_is_signed_into_the_token() -> None:
    parsed = verify_token(_token(), secret=SECRET)
    assert parsed.approver == "dana@example.com"


def test_swapping_the_recipient_breaks_the_signature() -> None:
    """Otherwise a forwarded link could be re-pointed at the forwarder."""
    raw = json.loads(base64.urlsafe_b64decode(_token() + "=="))
    raw["p"] = "attacker@example.test"
    tampered = base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
    with pytest.raises(EmailApprovalError, match="signature mismatch"):
        verify_token(tampered, secret=SECRET)


def test_the_decision_forwards_the_recipient_as_the_approver(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []
    _stub_post(monkeypatch, _StubResponse(200, {"status": "approved"}), calls)

    res = client.get("/api/v1/actions/email-decide", params={"token": _token()})

    assert res.status_code == 200
    assert len(calls) == 1
    assert calls[0]["url"].endswith("/api/v1/actions/act-1/approve")
    assert calls[0]["json"] == {"chatops_approver": {"platform": "email", "platform_user_id": "dana@example.com"}}


def test_a_reject_token_routes_to_the_reject_verb(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []
    _stub_post(monkeypatch, _StubResponse(200, {"status": "rejected"}), calls)

    res = client.get("/api/v1/actions/email-decide", params={"token": _token(decision="rejected")})

    assert res.status_code == 200
    assert calls[0]["url"].endswith("/api/v1/actions/act-1/reject")


def test_a_token_without_a_recipient_is_refused_not_forwarded(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Forwarding it would make the actions service authorize nobody."""
    calls: list[dict] = []
    _stub_post(monkeypatch, _StubResponse(200), calls)

    res = client.get("/api/v1/actions/email-decide", params={"token": _token(approver="")})

    assert res.status_code == 400
    assert calls == []
    assert "missing its recipient" in res.text


# ── failures name the right failure ────────────────────────────────────────


def test_an_expired_link_says_expired(client: TestClient) -> None:
    stale = issue_token(
        decision="approved",
        action_id="act-1",
        case_id="case-1",
        secret=SECRET,
        approver="dana@example.com",
        ttl_seconds=60,
        now=0,
    )
    res = client.get("/api/v1/actions/email-decide", params={"token": stale})
    assert res.status_code == 410
    assert "expired" in res.text.lower()


def test_a_tampered_link_is_rejected(client: TestClient) -> None:
    res = client.get("/api/v1/actions/email-decide", params={"token": "not-a-token"})
    assert res.status_code == 400


def test_an_already_decided_action_says_so_rather_than_failing_opaquely(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Single-use falls out of the action's own state machine: the actions
    service only accepts an approval while the action awaits one, so a
    replayed link gets a 400 upstream."""
    _stub_post(monkeypatch, _StubResponse(400, {"detail": "Action is not awaiting approval"}))
    res = client.get("/api/v1/actions/email-decide", params={"token": _token()})
    assert res.status_code == 409
    assert "already" in res.text.lower()


def test_an_unauthorized_approver_is_told_why(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_post(monkeypatch, _StubResponse(403, {"detail": "email user is not mapped to an AiSOC approver."}))
    res = client.get("/api/v1/actions/email-decide", params={"token": _token()})
    assert res.status_code == 403
    assert "AISOC_CHATOPS_APPROVERS" in res.text


def test_an_unset_secret_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifying against an empty secret would accept every token."""
    monkeypatch.setenv("AISOC_EMAIL_APPROVAL_SECRET", "")
    app = FastAPI()
    app.include_router(endpoint.router, prefix="/api/v1")
    res = TestClient(app).get("/api/v1/actions/email-decide", params={"token": _token()})
    assert res.status_code == 503


def test_an_unreachable_actions_service_does_not_claim_success(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def post(self, *a, **k):
            raise httpx.ConnectError("refused")

    monkeypatch.setattr(endpoint.httpx, "AsyncClient", lambda **_: _Client())
    res = client.get("/api/v1/actions/email-decide", params={"token": _token()})
    assert res.status_code == 502
    assert "not recorded" in res.text
