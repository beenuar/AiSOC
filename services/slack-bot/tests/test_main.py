"""
Tests for ``app.main`` — the FastAPI + Bolt entrypoint.

What we cover here
==================

* ``GET /health`` returns 200 and the expected service identifier so
  docker-compose / Fly.io can rely on it for liveness.
* The FastAPI app exposes the single Slack webhook endpoint
  (``POST /slack/events``).
* The lifespan hook builds and tears down the upstream HTTP clients —
  if it didn't, every Slack request would leak a connection.
* :func:`app.main._route_action_decision` correctly extracts the
  ``user.id`` and ``actions[0].value`` shape Slack actually delivers
  and converts last-resort exceptions into ephemeral errors instead of
  raising back into Bolt.

What we deliberately don't cover
================================

We don't fire real Slack-shaped slash command requests through Bolt's
verifier (that would force us to mint signed payloads with a fake
secret). The slash command logic is already fully tested in
``tests/test_commands.py``; here we just verify the Bolt → handler
wiring (decorator registration, request unpacking).
"""

from __future__ import annotations

from typing import Any

import pytest
from app import main as main_module
from app.interactions import APPROVE_ACTION_ID, DENY_ACTION_ID
from app.services.aisoc_clients import AisocClientError
from fastapi.testclient import TestClient


class _StubActionsClient:
    """Mock for :class:`AisocActionsClient` — only methods used by interactions."""

    def __init__(self, *, raise_on: str | None = None) -> None:
        self._raise_on = raise_on
        self.approve_calls: list[str] = []
        self.reject_calls: list[str] = []

    async def approve_action(self, action_id: str) -> dict[str, Any]:
        if self._raise_on == "approve":
            raise AisocClientError("upstream boom", status_code=502)
        self.approve_calls.append(action_id)
        return {"id": action_id, "status": "approved", "action_type": "isolate_host"}

    async def reject_action(self, action_id: str) -> dict[str, Any]:
        if self._raise_on == "reject":
            raise AisocClientError("upstream boom", status_code=502)
        self.reject_calls.append(action_id)
        return {"id": action_id, "status": "rejected", "action_type": "isolate_host"}


# ────────────────────────────────────────────────────────────────────────────
# Health + route registration
# ────────────────────────────────────────────────────────────────────────────


def test_health_endpoint_returns_expected_payload():
    """
    ``/health`` is the contract docker-compose and Fly.io check. If the
    JSON shape changes, both deployments need to update simultaneously
    — keep this assertion strict so we don't drift accidentally.
    """
    with TestClient(main_module.app) as client:
        res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "healthy", "service": "aisoc-slack-bot"}


def test_slack_events_route_is_registered():
    """The single Slack webhook endpoint must exist at ``/slack/events``."""
    paths = {getattr(route, "path", None) for route in main_module.app.routes}
    assert "/slack/events" in paths


def test_health_route_is_registered():
    paths = {getattr(route, "path", None) for route in main_module.app.routes}
    assert "/health" in paths


# ────────────────────────────────────────────────────────────────────────────
# Lifespan: clients are built on startup and closed on shutdown
# ────────────────────────────────────────────────────────────────────────────


def test_lifespan_builds_and_closes_clients(monkeypatch):
    """
    The lifespan must build singleton AisocApiClient + AisocActionsClient on
    startup and call ``aclose()`` on both during shutdown. Without this we'd
    leak an httpx pool on every reload.
    """
    closed: list[str] = []
    built: list[str] = []

    class _RecordingApiClient:
        base_url = "http://test-api"

        @classmethod
        def from_settings(cls):
            built.append("api")
            return cls()

        async def aclose(self) -> None:
            closed.append("api")

    class _RecordingActionsClient:
        base_url = "http://test-actions"

        @classmethod
        def from_settings(cls):
            built.append("actions")
            return cls()

        async def aclose(self) -> None:
            closed.append("actions")

        # The lifespan handler now hands these two coroutines to the
        # ``ApprovalTimeoutScheduler`` at startup (T3.6 ChatOps timeout
        # path), so the mock has to expose them — no actual call is
        # made during the lifespan, but ``getattr`` is.
        async def approve_action(self, action_id: str) -> dict[str, Any]:
            return {"id": action_id, "status": "approved"}

        async def reject_action(self, action_id: str) -> dict[str, Any]:
            return {"id": action_id, "status": "rejected"}

    monkeypatch.setattr(main_module, "AisocApiClient", _RecordingApiClient)
    monkeypatch.setattr(main_module, "AisocActionsClient", _RecordingActionsClient)

    with TestClient(main_module.app) as client:
        # Trigger startup.
        client.get("/health")
        assert built == ["api", "actions"]
        # The bolt app + handler are stashed on app.state for /slack/events.
        assert client.app.state.api_client is not None
        assert client.app.state.actions_client is not None
        assert client.app.state.bolt_app is not None
        assert client.app.state.bolt_handler is not None

    # Both clients must be closed on shutdown.
    assert sorted(closed) == ["actions", "api"]


# ────────────────────────────────────────────────────────────────────────────
# _route_action_decision: payload extraction + exception containment
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_route_action_decision_extracts_user_and_value_and_calls_approve():
    """
    Verify the Slack ``block_actions`` payload shape is parsed into the
    fields :func:`handle_action_decision` expects, and that approve
    routing reaches the actions client.
    """
    actions = _StubActionsClient()
    captured: list[dict] = []

    async def respond(payload: dict) -> None:
        captured.append(payload)

    body = {
        "user": {"id": "U99", "username": "soc-analyst"},
        "actions": [{"action_id": APPROVE_ACTION_ID, "value": "act-7|case-3"}],
    }
    await main_module._route_action_decision(
        event_action_id=APPROVE_ACTION_ID,
        body=body,
        respond=respond,
        actions_client=actions,
    )
    assert actions.approve_calls == ["act-7"]
    assert len(captured) == 1
    # On a successful decision we replace the original card so analysts
    # can't double-click.
    assert captured[0].get("replace_original") is True


@pytest.mark.asyncio
async def test_route_action_decision_routes_deny_branch():
    actions = _StubActionsClient()
    captured: list[dict] = []

    async def respond(payload: dict) -> None:
        captured.append(payload)

    body = {
        "user": {"id": "U99"},
        "actions": [{"action_id": DENY_ACTION_ID, "value": "act-9|case-3"}],
    }
    await main_module._route_action_decision(
        event_action_id=DENY_ACTION_ID,
        body=body,
        respond=respond,
        actions_client=actions,
    )
    assert actions.reject_calls == ["act-9"]
    assert actions.approve_calls == []
    assert captured[0].get("replace_original") is True


@pytest.mark.asyncio
async def test_route_action_decision_handles_missing_user_field_gracefully():
    """A malformed payload missing ``user`` should not raise back into Bolt."""
    actions = _StubActionsClient()
    captured: list[dict] = []

    async def respond(payload: dict) -> None:
        captured.append(payload)

    body = {"actions": [{"value": "act-1|case-1"}]}  # no user
    await main_module._route_action_decision(
        event_action_id=APPROVE_ACTION_ID,
        body=body,
        respond=respond,
        actions_client=actions,
    )
    # We default user_id to "unknown" so the audit-trail line still
    # renders something deterministic.
    assert actions.approve_calls == ["act-1"]
    assert captured[0].get("replace_original") is True


@pytest.mark.asyncio
async def test_route_action_decision_handles_empty_actions_list():
    """
    No actions at all should produce an ephemeral error, not a crash.
    The interactions module returns the error block; we just verify the
    main wrapper doesn't lose it.
    """
    actions = _StubActionsClient()
    captured: list[dict] = []

    async def respond(payload: dict) -> None:
        captured.append(payload)

    body = {"user": {"id": "U99"}, "actions": []}
    await main_module._route_action_decision(
        event_action_id=APPROVE_ACTION_ID,
        body=body,
        respond=respond,
        actions_client=actions,
    )
    assert actions.approve_calls == []
    assert captured[0]["response_type"] == "ephemeral"


@pytest.mark.asyncio
async def test_route_action_decision_converts_unhandled_exception_to_ephemeral(
    monkeypatch,
):
    """
    The wrapper has a last-resort ``except Exception`` so an unforeseen
    bug in :func:`handle_action_decision` lands in Slack as an
    ephemeral error rather than as a 500 to Slack (which would then
    retry the click and double-fire the approval).
    """

    async def boom(**kwargs):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(main_module, "handle_action_decision", boom)

    captured: list[dict] = []

    async def respond(payload: dict) -> None:
        captured.append(payload)

    body = {
        "user": {"id": "U99"},
        "actions": [{"value": "act-1|case-1"}],
    }
    await main_module._route_action_decision(
        event_action_id=APPROVE_ACTION_ID,
        body=body,
        respond=respond,
        actions_client=_StubActionsClient(),
    )
    assert captured[0]["response_type"] == "ephemeral"
    assert "Internal error" in captured[0]["text"]
