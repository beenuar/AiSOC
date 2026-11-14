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
  signed by Microsoft) is terminated by the deployment fronting reverse
  proxy. The bot never minted or holds the Microsoft secret. Our HMAC
  signature on the card payload is a *defence in depth* sitting inside
  their envelope, and is the surface we control end-to-end.

The second bullet used to end there, and read as though the proxy made this
route safe. It did not: the route had **no inbound authentication of any
kind**, while ``_resolve_approver`` takes the deciding identity from
``from.aadObjectId`` — an envelope field our HMAC does not cover, since that
signs ``value.action.data``. Anyone who could reach the port could approve a
governed response action under any identity they chose
(GHSA-vf98-8367-45mp, F03).

A control this repository cannot observe cannot be the only one. The proxy
still terminates Bot Framework auth; ``AISOC_TEAMS_INBOUND_TOKEN`` is the leg
that proves a request arrived through it, and an unset token in production is
a refusal rather than an open door. See :func:`_require_inbound_auth`.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

from fastapi import FastAPI, HTTPException, Request

from app._health import install_health_routes
from app.callbacks import callback_max_age_seconds, handle_card_action
from app.notify import router as notify_router
from app.war_room import router as war_room_router

app = FastAPI(
    title="AiSOC Teams Bot",
    description=("ChatOps adapter for Microsoft Teams. Renders Adaptive Card approval prompts and verifies the signed callback payload."),
    version="0.1.0",
)

# Phase 2.6 — k8s liveness + readiness probes (see app/_health.py).
app.include_router(notify_router)
# Depth 9.4. Creating a Teams channel needs Microsoft Graph, not the
# incoming webhook this service posts cards through — so the route
# refuses with the specific missing settings named rather than falling
# back to one shared channel, which would put the next incident's
# traffic in the last one's thread.
app.include_router(war_room_router)

_mark_ready, _mark_not_ready = install_health_routes(app, service_name="aisoc-teams-bot")
app.state.mark_ready = _mark_ready
app.state.mark_not_ready = _mark_not_ready


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy", "service": "aisoc-teams-bot"}


def _is_production() -> bool:
    """Anything not explicitly a development or test environment.

    The unset case is production on purpose: "unconfigured means relaxed" is
    how a stock install once resolved an uncredentialed caller to a demo
    admin.
    """
    return os.environ.get("ENVIRONMENT", "production").strip().lower() not in {
        "development",
        "dev",
        "test",
        "testing",
        "local",
    }


def _require_inbound_auth(request: Request) -> None:
    """Authenticate the caller before any identity is read out of the body.

    GHSA-vf98-8367-45mp, F03. This route had **no inbound authentication of
    any kind**, and `_resolve_approver` takes the deciding identity from
    ``from.aadObjectId`` -- a field of the Bot Framework envelope, which our
    HMAC does not cover (that signs ``value.action.data``, the card payload we
    issued). So anyone who could reach the port could post a card callback and
    name themselves as the approver of a governed response action.

    The module docstring argued the Bot Framework JWT "is enforced by the
    deployment fronting reverse proxy, not by this service". That is a real
    deployment pattern and it is not a control this repository can observe, so
    it cannot be the only one -- an operator who exposes the container
    directly, or whose proxy rule is scoped to a different path, gets no
    authentication at all and nothing says so.

    ``AISOC_TEAMS_INBOUND_TOKEN`` is the shared secret the proxy (or the
    channel's outgoing-webhook configuration) presents. Unset in production is
    a refusal, matching `require_service_auth` in ``services/actions``: a bot
    that starts and silently accepts forged approvals looks healthier than one
    that refuses, which is exactly why it is worse.

    Deliberately *not* a Bot Framework JWT validation: that needs Microsoft's
    JWKS fetched at request time, and this service already refuses to put a
    network round trip on the approval path (see `chatops_identity`, which
    maps approvers from operator configuration for the same reason). An
    operator who terminates Bot Framework auth at the proxy keeps doing so;
    this is the leg that proves the request came through it.
    """
    expected = os.environ.get("AISOC_TEAMS_INBOUND_TOKEN", "").strip()
    if not expected:
        if not _is_production():
            return
        raise HTTPException(
            status_code=503,
            detail=(
                "AISOC_TEAMS_INBOUND_TOKEN is not set, so this callback cannot be authenticated "
                "and the approver named in the activity cannot be trusted. Set it here and on "
                "the proxy or channel configuration that forwards Bot Framework activities, or "
                "set ENVIRONMENT=development if this is a local run."
            ),
        )

    presented = request.headers.get("authorization", "")
    prefix = "bearer "
    token = presented[len(prefix) :] if presented.lower().startswith(prefix) else presented
    # Constant time: the comparison is against a shared secret, and a timing
    # oracle on it is a way to learn it one byte at a time.
    if not token or not hmac.compare_digest(token, expected):
        raise HTTPException(
            status_code=401,
            detail="invalid or missing inbound token",
            headers={"WWW-Authenticate": "Bearer"},
        )


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
    _require_inbound_auth(request)

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
