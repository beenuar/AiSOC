"""
FastAPI + Slack Bolt entrypoint for the AiSOC Slack bot.

Architecture (one diagram, then code)::

    Slack ──HTTP──► FastAPI ──► SlackRequestHandler ──► Bolt AsyncApp ──► Python handlers
                                                                              │
                                                                              ▼
                                                                  app.commands.handle_aisoc_command
                                                                  app.interactions.handle_action_decision
                                                                              │
                                                                              ▼
                                                              services/api  ·  services/actions

Design choices
--------------

* **Bolt is mounted under FastAPI** rather than running standalone so we
  keep one ASGI app per service (matches every other AiSOC service) and
  one health-check endpoint for compose / Fly.io.
* **All Slack-side logic lives behind an async-friendly Bolt app**; the
  actual command/interaction logic stays in :mod:`app.commands` and
  :mod:`app.interactions` so it can be tested without touching Bolt.
* **Per-process singleton clients** (`AisocApiClient`,
  `AisocActionsClient`). Each holds an ``httpx.AsyncClient`` with
  connection pooling — building one per request would defeat the pool.
* **Signing-secret-aware bootstrap**: Bolt requires a signing secret in
  production. For local pytest / docker-without-secrets we set the Bolt
  request-verification flag off and log a loud warning so we can never
  ship a misconfigured production build by accident.
* **No state on disk**: every command result is rendered into Slack
  blocks and discarded. The case timeline in ``services/api`` is the
  source of truth for audit.

Endpoints
---------

* ``GET /health`` — liveness probe used by docker-compose / Fly.io.
* ``POST /slack/events`` — single Slack request endpoint. Slack posts
  slash commands and interactive payloads here; Bolt routes internally.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from slack_bolt.adapter.fastapi.async_handler import AsyncSlackRequestHandler
from slack_bolt.async_app import AsyncApp

from app._health import install_health_routes
from app.commands import handle_aisoc_command
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.interactions import (
    APPROVE_ACTION_ID,
    DENY_ACTION_ID,
    NEED_INFO_ACTION_ID,
    handle_action_decision,
)
from app.services.aisoc_clients import AisocActionsClient, AisocApiClient
from app.services.approval_audit import StructlogAuditSink
from app.services.approval_timeout import ApprovalTimeoutScheduler

# Configure structlog before anything else so module-level loggers
# (httpx, slack_bolt, …) inherit the JSON renderer.
configure_logging()
logger = structlog.get_logger("aisoc.slack_bot")


def _build_bolt_app(api_client: AisocApiClient, actions_client: AisocActionsClient) -> AsyncApp:
    """
    Construct the Bolt :class:`AsyncApp` and register every Slack handler.

    The clients are injected so the same builder can be reused from tests
    with mock clients (or with respx-routed real clients) without
    spinning up the FastAPI app.
    """
    settings = get_settings()

    # ``request_verification_enabled`` defaults to True; we explicitly
    # disable it when no signing secret is set so docker-without-secrets
    # bring-up doesn't 401 every Slack request. Production manifests must
    # supply ``SLACK_SIGNING_SECRET``.
    #
    # ``token`` defaults to a placeholder when missing so Bolt doesn't
    # reject the constructor; outbound API calls obviously won't succeed
    # without a real token, but startup still works for local dev / tests.
    bolt = AsyncApp(
        signing_secret=settings.SLACK_SIGNING_SECRET or None,
        token=settings.SLACK_BOT_TOKEN or "xoxb-not-configured",
        request_verification_enabled=settings.signature_verification_enabled,
        ignoring_self_events_enabled=True,
    )

    if not settings.signature_verification_enabled:
        logger.warning(
            "slack_signing_secret_missing",
            note=(
                "Bolt request-signature verification disabled — acceptable for local dev only. Set SLACK_SIGNING_SECRET before shipping."
            ),
        )
    if not settings.SLACK_BOT_TOKEN:
        logger.warning(
            "slack_bot_token_missing",
            note=("SLACK_BOT_TOKEN is empty — outbound Slack API calls will fail. Required before submitting the Slack app for review."),
        )

    web_base = settings.AISOC_WEB_BASE_URL

    # ── Slash command: /aisoc -------------------------------------------------
    @bolt.command("/aisoc")
    async def _on_slash_aisoc(ack, command, respond):
        # Slack requires an ack within 3 seconds. We ack immediately so
        # the slow path (HTTP calls into AiSOC services) doesn't blow the
        # 3s budget on a cold cache.
        await ack()
        text = command.get("text") or ""
        user_id = command.get("user_id") or "unknown"
        try:
            payload = await handle_aisoc_command(
                text=text,
                user_id=user_id,
                api_client=api_client,
                actions_client=actions_client,
                web_base=web_base,
            )
        except Exception as exc:  # noqa: BLE001 — last-resort guard
            # Defensive: handle_aisoc_command swallows AisocClientError but a
            # programming bug could still raise. We never want a stack
            # trace to land in Slack.
            logger.error("slash_command_unhandled_exception", error=str(exc))
            payload = {
                "response_type": "ephemeral",
                "text": f"⚠️ Internal error: {exc}",
            }
        await respond(payload)

    # ── Interactive: approve --------------------------------------------------
    @bolt.action(APPROVE_ACTION_ID)
    async def _on_approve(ack, body, respond):
        await ack()
        await _route_action_decision(
            event_action_id=APPROVE_ACTION_ID,
            body=body,
            respond=respond,
            actions_client=actions_client,
        )

    # ── Interactive: deny -----------------------------------------------------
    @bolt.action(DENY_ACTION_ID)
    async def _on_deny(ack, body, respond):
        await ack()
        await _route_action_decision(
            event_action_id=DENY_ACTION_ID,
            body=body,
            respond=respond,
            actions_client=actions_client,
        )

    # ── Interactive: need-info -----------------------------------------------
    @bolt.action(NEED_INFO_ACTION_ID)
    async def _on_need_info(ack, body, respond):
        await ack()
        await _route_action_decision(
            event_action_id=NEED_INFO_ACTION_ID,
            body=body,
            respond=respond,
            actions_client=actions_client,
        )

    # ── Interactive: open-case link ------------------------------------------
    # Pure URL buttons still emit a block_actions payload that Bolt would
    # otherwise log a "no listener" warning for. Acking quietly keeps
    # logs clean without coupling the URL button to any business logic.
    @bolt.action("aisoc_action_open_case")
    async def _on_open_case(ack):
        await ack()

    @bolt.action("case_open_link")
    async def _on_case_open_link(ack):
        await ack()

    return bolt


async def _route_action_decision(
    *,
    event_action_id: str,
    body: dict,
    respond,
    actions_client: AisocActionsClient,
) -> None:
    """
    Pull the routing value out of the Slack ``block_actions`` payload and
    delegate to :func:`app.interactions.handle_action_decision`.

    Slack's payload shape for buttons is:

        body["user"]["id"] -> str
        body["actions"][0]["value"] -> str ("<action_id>|<case_id>")

    We tolerate missing fields gracefully (eg. a malformed test
    payload) so handlers can never raise back into Bolt.
    """
    user_id = (body.get("user") or {}).get("id") or "unknown"
    channel_id = (body.get("channel") or {}).get("id") or None
    actions = body.get("actions") or []
    button_value = ""
    if actions and isinstance(actions, list):
        first = actions[0] or {}
        button_value = first.get("value") or ""

    try:
        payload = await handle_action_decision(
            action_id_event=event_action_id,
            button_value=button_value,
            user_id=user_id,
            actions_client=actions_client,
            audit_sink=StructlogAuditSink(),
            channel_id=channel_id,
            actor_ip=None,
        )
    except Exception as exc:  # noqa: BLE001 — last-resort guard
        logger.error("action_decision_unhandled_exception", error=str(exc))
        payload = {
            "response_type": "ephemeral",
            "text": f"⚠️ Internal error: {exc}",
        }
    await respond(payload)


# ────────────────────────────────────────────────────────────────────────────
# FastAPI wiring
# ────────────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Build the AiSOC HTTP clients on startup, tear them down on shutdown.

    The clients each own an ``httpx.AsyncClient`` with a connection pool
    — sharing them across requests is a 10× win versus building a fresh
    client per Slack event.
    """
    api_client = AisocApiClient.from_settings()
    actions_client = AisocActionsClient.from_settings()
    bolt_app = _build_bolt_app(api_client, actions_client)

    # The timeout scheduler is shared across the process — one task per
    # pending approval so a forgotten Approve/Deny can't leave the action
    # in awaiting_approval forever. See app/services/approval_timeout.py.
    timeout_scheduler = ApprovalTimeoutScheduler(
        approve_fn=actions_client.approve_action,
        reject_fn=actions_client.reject_action,
        audit_sink=StructlogAuditSink(),
    )

    app.state.api_client = api_client
    app.state.actions_client = actions_client
    app.state.bolt_app = bolt_app
    app.state.bolt_handler = AsyncSlackRequestHandler(bolt_app)
    app.state.timeout_scheduler = timeout_scheduler

    logger.info(
        "slack_bot_started",
        api_base=api_client.base_url,
        actions_base=actions_client.base_url,
    )
    # Phase 2.6 — flip /readyz to 200 once Bolt + the HTTP clients
    # are wired. We deliberately don't probe Slack itself — the
    # upstream sign-in is checked the first time Slack posts here.
    app.state.mark_ready()
    try:
        yield
    finally:
        # Phase 2.6 — start draining before tearing down clients.
        app.state.mark_not_ready()
        await timeout_scheduler.aclose()
        await api_client.aclose()
        await actions_client.aclose()
        logger.info("slack_bot_stopped")


app = FastAPI(
    title="AiSOC Slack Bot",
    description=(
        "ChatOps adapter for AiSOC. Forwards `/aisoc …` slash commands and "
        "approval-card button clicks to services/api and services/actions. "
        "Holds no state of its own."
    ),
    version="0.1.0",
    lifespan=_lifespan,
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-slack-bot")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready


@app.get("/health")
async def health() -> dict[str, str]:
    """
    Liveness probe used by docker-compose and Fly.io.

    Intentionally does NOT exercise the upstream services — that would
    couple liveness to an availability concern that is better tracked
    via a separate readiness probe.
    """
    return {"status": "healthy", "service": "aisoc-slack-bot"}


@app.post("/slack/events")
async def slack_events(req: Request):
    """
    Single endpoint Slack posts to for slash commands and interactive
    payloads. Bolt routes internally based on the payload shape.
    """
    handler: AsyncSlackRequestHandler = req.app.state.bolt_handler
    return await handler.handle(req)
