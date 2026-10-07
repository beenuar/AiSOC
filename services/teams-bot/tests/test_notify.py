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


@pytest.mark.parametrize("supplied", ["", "   ", "wrong", "tok-with-suffix"])
def test_a_token_that_is_not_the_configured_one_is_refused(client: TestClient, supplied: str) -> None:
    """Pins each branch of the comparison, including the empty header.

    `_authorized` reached these cases through `bool(supplied) and ...`,
    which does not narrow `str | None` for a type checker. Rewriting it as
    an early return does, and these are the inputs that would show a
    behaviour change if the rewrite had introduced one -- an empty or
    whitespace header in particular, which the truthiness test rejected
    before reaching the compare and the early return rejects at the same
    point.
    """
    response = client.post(
        "/internal/approval-card",
        json={"action": _ACTION},
        headers={"X-AiSOC-Internal-Token": supplied},
    )
    assert response.status_code == 401, f"{supplied!r} was accepted as the internal token"


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
        json={"action": _ACTION, "webhook_url": "https://teams.example/hook"},
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
        json={"action": _ACTION, "case": {"id": "c-1", "severity": "high"}, "webhook_url": "https://teams.example/hook"},
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
        json={"action": _ACTION, "webhook_url": "https://teams.example/hook"},
        headers={"X-AiSOC-Internal-Token": "tok"},
    )
    assert response.json()["posted"] is False
    assert "400" in response.json()["reason"]
