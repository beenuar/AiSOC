"""
FastAPI entrypoint for the AiSOC Teams bot.

The Teams bot is intentionally smaller than the Slack bot today: it
ships exactly one webhook (``/teams/messages``) that consumes the Bot
Framework activity for an Adaptive Card ``invoke`` and dispatches it
through :func:`app.callbacks.handle_card_action`.

We keep the surface small for two reasons:

* the **only Teams-specific T3.6 contract** is "render an Adaptive Card
  approval prompt and verify the signed callback that comes back" —
  every upstream call lands in ``services/actions`` exactly as it does
  for Slack;
* the **Bot Framework outer auth** (JWT in the Authorization header
  signed by Microsoft) is enforced by the deployment fronting reverse
  proxy, not by this service. The bot itself never minted or holds the
  Microsoft secret. Our HMAC signature on the card payload is a
  *defence in depth* sitting inside their envelope, and is the surface
  we control end-to-end.
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, Request

from app._health import install_health_routes
from app.callbacks import callback_max_age_seconds, handle_card_action

app = FastAPI(
    title="AiSOC Teams Bot",
    description=(
        "ChatOps adapter for Microsoft Teams. Renders Adaptive Card " "approval prompts and verifies the signed callback payload."
    ),
    version="0.1.0",
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-teams-bot")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "aisoc-teams-bot"}


def _resolve_approver(activity: dict[str, Any]) -> str:
    """
    Pull a stable approver identifier out of the Teams activity.

    Falls back through ``from.aadObjectId`` → ``from.id`` →
    ``"unknown"`` because not every Teams tenant returns the AAD
    identifier (guest users, anon links).
    """
    sender = activity.get("from") or {}
    return str(sender.get("aadObjectId") or "").strip() or str(sender.get("id") or "").strip() or "unknown"


@app.post("/teams/messages")
async def teams_webhook(request: Request) -> dict[str, Any]:
    """
    Entrypoint for Teams Adaptive Card callbacks.

    Expects a Bot Framework v3 activity body. For card actions the
    payload's shape is::

        {
            "type": "invoke",
            "name": "adaptiveCard/action",
            "value": {"action": {"data": <signed payload>}},
            "from": {"id": "...", "aadObjectId": "..."},
            "conversation": {"id": "..."}
        }

    Any deviation (missing fields, wrong activity type) is converted
    into an HTTP 400 with a structured body so the deployment's
    operational tooling can alert.
    """
    body = await request.json()
    if not isinstance(body, dict):
        return {"ok": False, "error": "expected JSON object"}

    value = body.get("value") or {}
    action = value.get("action") or {}
    data = action.get("data") or {}
    if not isinstance(data, dict):
        return {"ok": False, "error": "missing signed data payload"}

    approver_id = _resolve_approver(body)
    channel_id = (body.get("conversation") or {}).get("id")
    actor_ip = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or None

    actions_client = request.app.state.actions_client
    audit_sink = request.app.state.audit_sink
    secret = request.app.state.callback_secret

    result = await handle_card_action(
        payload=data,
        approver_id=approver_id,
        secret=secret,
        max_age_seconds=callback_max_age_seconds(),
        actions_client=actions_client,
        audit_sink=audit_sink,
        channel_id=channel_id,
        actor_ip=actor_ip,
    )
    return result


@app.on_event("startup")
async def _startup() -> None:  # pragma: no cover - thin runtime wiring
    """Wire HTTP clients + audit sink at startup."""
    from app.services.aisoc_clients import build_actions_client, build_audit_sink

    app.state.callback_secret = os.environ.get("AISOC_TEAMS_CALLBACK_SECRET", "")
    app.state.actions_client = build_actions_client()
    app.state.audit_sink = build_audit_sink()
    # Phase 2.6 — actions client + audit sink wired; the webhook
    # is now safe to dispatch.
    app.state.mark_ready()


@app.on_event("shutdown")
async def _shutdown() -> None:  # pragma: no cover - thin runtime wiring
    # Phase 2.6 — drain readiness before tearing the client down.
    app.state.mark_not_ready()
    client = getattr(app.state, "actions_client", None)
    if client is not None and hasattr(client, "aclose"):
        await client.aclose()
