"""The route that lets this bot start a conversation.

Reproduce: before this, every route here was inbound. Teams posted an
``invoke`` activity, the bot verified the signed card payload and answered —
so it could answer a question and could not ask one, and the documented
"an agent stops and asks Teams for approval" flow could only begin with a
person typing first. The card builder and the signed callback handler were
both written and both reachable only from a conversation a human started.
"""

from __future__ import annotations

import httpx
import pytest
from app import notify
from app.main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AISOC_INTERNAL_TOKEN", "tok")
    monkeypatch.setenv("AISOC_TEAMS_CALLBACK_SECRET", "signing-secret")
    monkeypatch.setenv("AISOC_WEB_BASE_URL", "https://console.example.com")
    # The destination is deployment configuration, not a request field. It
    # used to arrive in the body, which made this route a full SSRF.
    monkeypatch.setenv("TEAMS_APPROVALS_WEBHOOK_URL", "https://teams.example/hook")
    return TestClient(app)


_ACTION = {"id": "act-1", "action_type": "isolate_host", "target": "web-prod-04", "rationale": "credential access"}


def test_the_route_exists_and_refuses_an_unauthenticated_caller(client: TestClient) -> None:
    assert client.post("/internal/approval-card", json={"action": _ACTION}).status_code == 401


def test_an_unset_internal_token_refuses_everything(monkeypatch: pytest.MonkeyPatch) -> None:
    """Failing closed, with no dev-mode exemption.

    That exemption existed on the Slack bot and it was the state a stock
    install ran in, so a route that posts into a workspace channel was open
    to anything that could reach the pod.
    """
    monkeypatch.delenv("AISOC_INTERNAL_TOKEN", raising=False)
    response = TestClient(app).post("/internal/approval-card", json={"action": _ACTION}, headers={"X-AiSOC-Internal-Token": "anything"})
    assert response.status_code == 401


def test_no_configured_webhook_is_reported_not_failed(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """202 with ``posted: false``.

    The approval is already durable in Postgres and the console and the
    responder app can both act on it; Teams is one delivery route, not the
    record. The caller reads ``posted`` rather than the status code, which
    is what stops a skipped post being recorded as a delivery.
    """
    monkeypatch.delenv("TEAMS_APPROVALS_WEBHOOK_URL", raising=False)
    response = client.post("/internal/approval-card", json={"action": _ACTION}, headers={"X-AiSOC-Internal-Token": "tok"})
    assert response.status_code == 202
    assert response.json() == {"posted": False, "reason": "no approvals webhook configured"}


def test_an_unsigned_card_is_refused(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """A card whose Approve button the callback handler will reject looks
    actionable and is not, which is worse than no card."""
    monkeypatch.setenv("AISOC_TEAMS_CALLBACK_SECRET", "")
    response = client.post(
        "/internal/approval-card",
        json={"action": _ACTION},
        headers={"X-AiSOC-Internal-Token": "tok"},
    )
    assert response.json()["posted"] is False
    assert "AISOC_TEAMS_CALLBACK_SECRET" in response.json()["reason"]


def test_a_posted_card_is_an_adaptive_card_envelope(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[httpx.Request] = []

    def _transport(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(202)

    real = httpx.AsyncClient
    monkeypatch.setattr(
        notify.httpx,
        "AsyncClient",
        lambda *args, **kwargs: real(*args, **{**kwargs, "transport": httpx.MockTransport(_transport)}),
    )
    response = client.post(
        "/internal/approval-card",
        json={"action": _ACTION, "case": {"id": "c-1", "severity": "high"}},
        headers={"X-AiSOC-Internal-Token": "tok"},
    )
    assert response.json() == {"posted": True}
    body = sent[0].read().decode()
    assert "AdaptiveCard" in body
    assert "web-prod-04" in body


def test_a_rejected_post_is_not_reported_as_delivered(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    real = httpx.AsyncClient
    monkeypatch.setattr(
        notify.httpx,
        "AsyncClient",
        lambda *args, **kwargs: real(*args, **{**kwargs, "transport": httpx.MockTransport(lambda r: httpx.Response(400, text="bad"))}),
    )
    response = client.post(
        "/internal/approval-card",
        json={"action": _ACTION},
        headers={"X-AiSOC-Internal-Token": "tok"},
    )
    assert response.json()["posted"] is False
    assert "400" in response.json()["reason"]


def test_a_caller_cannot_choose_the_destination(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """The request body must not be able to redirect the post.

    `webhook_url` was accepted here as a per-tenant routing override and
    posted to directly, so anything that could reach this pod chose where an
    internal service sent an authenticated-looking request — CodeQL's
    `py/full-ssrf`, at critical. The field is gone rather than validated,
    because the only production caller never set it.

    Pydantic ignores an unknown field by default, so the attacker-supplied
    URL is simply never read; this asserts the post still goes to the
    configured host, which is the property that matters.
    """
    seen: dict[str, str] = {}

    class _Response:
        status_code = 200

    class _Client:
        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_: object) -> None:
            return None

        async def post(self, url: str, **_: object) -> _Response:
            seen["url"] = url
            return _Response()

    monkeypatch.setattr(notify.httpx, "AsyncClient", lambda *a, **k: _Client())

    response = client.post(
        "/internal/approval-card",
        json={"action": _ACTION, "webhook_url": "http://169.254.169.254/latest/meta-data/"},
        headers={"X-AiSOC-Internal-Token": "tok"},
    )

    assert response.json()["posted"] is True
    assert seen["url"] == "https://teams.example/hook"
