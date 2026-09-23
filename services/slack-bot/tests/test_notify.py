"""The bot has to be able to start a conversation.

Every route this service had was inbound. Replies go through Bolt's
``respond()``, which writes to the ``response_url`` that arrives with an
interaction — so the bot could answer a question and could not ask one. The
documented flow where an agent stops and Slack asks an analyst for approval
could only begin with a human typing a slash command first.

``rich_approval_card_blocks`` had **no production caller at all** before this;
the renderer and the button handlers both existed, with nothing between them.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from app import notify
from app.core.config import get_settings
from fastapi import FastAPI
from fastapi.testclient import TestClient

TOKEN = "internal-secret"

ACTION = {
    "id": "act-1",
    "action_type": "isolate_host",
    "target": "WKSTN-01",
    "risk_level": "high",
    "rationale": "Confirmed C2 beacon.",
}


class _Client:
    """Stands in for Bolt's Slack web client."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[dict] = []
        self._fail = fail

    async def chat_postMessage(self, **kwargs):
        if self._fail:
            raise RuntimeError("channel_not_found")
        self.calls.append(kwargs)
        return {"ts": "1700000000.000100"}


@pytest.fixture
def slack():
    return _Client()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, slack: _Client) -> TestClient:
    monkeypatch.setenv("AISOC_INTERNAL_TOKEN", TOKEN)
    monkeypatch.setenv("SLACK_APPROVALS_CHANNEL", "#soc-approvals")
    get_settings.cache_clear()

    app = FastAPI()
    app.include_router(notify.router)
    app.state.bolt_app = SimpleNamespace(client=slack)
    yield TestClient(app)
    get_settings.cache_clear()


def _post(client: TestClient, *, token: str | None = TOKEN, **body):
    headers = {"X-AiSOC-Internal-Token": token} if token is not None else {}
    payload = {"action": ACTION, "case": {"title": "Beaconing on WKSTN-01"}}
    payload.update(body)
    return client.post("/internal/approval-card", json=payload, headers=headers)


class TestItActuallyPosts:
    def test_a_card_reaches_the_configured_channel(self, client: TestClient, slack: _Client):
        response = _post(client)

        assert response.status_code == 202
        assert response.json()["posted"] is True
        assert len(slack.calls) == 1
        assert slack.calls[0]["channel"] == "#soc-approvals"

    def test_the_card_is_block_kit_not_a_plain_string(self, client: TestClient, slack: _Client):
        _post(client)

        blocks = slack.calls[0]["blocks"]
        assert isinstance(blocks, list) and blocks
        assert all("type" in block for block in blocks)

    def test_fallback_text_names_the_action_and_target(self, client: TestClient, slack: _Client):
        """Often all an approver sees is the mobile push preview."""
        _post(client)

        text = slack.calls[0]["text"]
        assert "isolate_host" in text
        assert "WKSTN-01" in text

    def test_a_caller_can_override_the_channel(self, client: TestClient, slack: _Client):
        _post(client, channel="#ir-warroom")

        assert slack.calls[0]["channel"] == "#ir-warroom"


class TestAuthentication:
    def test_an_unauthenticated_call_is_refused(self, client: TestClient, slack: _Client):
        """This route can post into a workspace channel. It carries no Slack
        signature because Slack is not the caller."""
        assert _post(client, token=None).status_code == 401
        assert slack.calls == []

    def test_a_wrong_token_is_refused(self, client: TestClient, slack: _Client):
        assert _post(client, token="not-it").status_code == 401
        assert slack.calls == []

    def test_an_unset_token_fails_closed_outside_dev_mode(self, monkeypatch: pytest.MonkeyPatch, slack: _Client):
        """Treating 'no token configured' as 'no auth needed' would open this
        to anything that can reach the pod."""
        monkeypatch.setenv("AISOC_INTERNAL_TOKEN", "")
        monkeypatch.delenv("AISOC_DEV_MODE", raising=False)
        get_settings.cache_clear()

        app = FastAPI()
        app.include_router(notify.router)
        app.state.bolt_app = SimpleNamespace(client=slack)

        response = TestClient(app).post("/internal/approval-card", json={"action": ACTION})
        assert response.status_code == 401
        get_settings.cache_clear()


class TestDegradation:
    def test_no_configured_channel_is_reported_not_crashed(self, monkeypatch: pytest.MonkeyPatch, slack: _Client):
        """An approval is durable in Postgres by the time this runs. Slack is
        one delivery route, not the record."""
        monkeypatch.setenv("AISOC_INTERNAL_TOKEN", TOKEN)
        monkeypatch.setenv("SLACK_APPROVALS_CHANNEL", "")
        get_settings.cache_clear()

        app = FastAPI()
        app.include_router(notify.router)
        app.state.bolt_app = SimpleNamespace(client=slack)

        response = TestClient(app).post(
            "/internal/approval-card",
            json={"action": ACTION},
            headers={"X-AiSOC-Internal-Token": TOKEN},
        )
        assert response.status_code == 202
        assert response.json()["posted"] is False
        assert slack.calls == []
        get_settings.cache_clear()

    def test_slack_rejecting_the_message_does_not_500(self, monkeypatch: pytest.MonkeyPatch):
        """A failed card must not fail the agent run that raised it."""
        monkeypatch.setenv("AISOC_INTERNAL_TOKEN", TOKEN)
        monkeypatch.setenv("SLACK_APPROVALS_CHANNEL", "#soc-approvals")
        get_settings.cache_clear()

        app = FastAPI()
        app.include_router(notify.router)
        app.state.bolt_app = SimpleNamespace(client=_Client(fail=True))

        response = TestClient(app).post(
            "/internal/approval-card",
            json={"action": ACTION},
            headers={"X-AiSOC-Internal-Token": TOKEN},
        )
        assert response.status_code == 202
        assert response.json()["posted"] is False
        get_settings.cache_clear()

    def test_no_slack_client_is_reported_not_crashed(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AISOC_INTERNAL_TOKEN", TOKEN)
        monkeypatch.setenv("SLACK_APPROVALS_CHANNEL", "#soc-approvals")
        get_settings.cache_clear()

        app = FastAPI()
        app.include_router(notify.router)

        response = TestClient(app).post(
            "/internal/approval-card",
            json={"action": ACTION},
            headers={"X-AiSOC-Internal-Token": TOKEN},
        )
        assert response.status_code == 202
        assert response.json()["posted"] is False
        get_settings.cache_clear()
