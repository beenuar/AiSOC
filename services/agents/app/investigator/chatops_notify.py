"""Tell a human an approval is waiting.

An approval row in Postgres is durable and useless until somebody looks at
it. The console shows it and the responder app pushes it, but the path the
documentation describes — an agent stops, Slack asks, an analyst taps — could
not start: the bot had no way to originate a message, only to reply inside an
inbound interaction.

Now that ``services/slack-bot`` exposes ``POST /internal/approval-card``,
this is the caller. It is deliberately best-effort and deliberately quiet
when unconfigured: an approval is already recorded by the time this runs, and
a deployment with no Slack should not log a warning per alert forever.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_TIMEOUT_SECONDS = 5.0


def _bot_url() -> str:
    return os.getenv("AISOC_SLACK_BOT_URL", "").strip().rstrip("/")


def _internal_token() -> str:
    return os.getenv("AISOC_INTERNAL_TOKEN", "").strip()


async def notify_chatops(
    approval_id: uuid.UUID,
    *,
    title: str,
    summary: str,
    risk_level: str,
    action: dict[str, Any],
) -> bool:
    """Post an approval card to ChatOps. Returns whether it was delivered.

    Unconfigured is not an error and not a warning: it is the default, and the
    approval is reachable in the console and the responder app regardless.
    """
    base = _bot_url()
    if not base:
        return False

    payload = {
        "action": {
            "id": str(approval_id),
            "action_type": action.get("action_type"),
            "target": action.get("target"),
            "risk_level": risk_level,
            "rationale": summary,
            "title": title,
        },
        "case": {"title": title, "description": summary},
    }
    headers = {"Accept": "application/json"}
    token = _internal_token()
    if token:
        headers["X-AiSOC-Internal-Token"] = token

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(f"{base}/internal/approval-card", json=payload, headers=headers)
    except httpx.HTTPError as exc:
        logger.warning("chatops_notify.unreachable", approval_id=str(approval_id), error=str(exc))
        return False

    if response.status_code >= 400:
        logger.warning(
            "chatops_notify.refused",
            approval_id=str(approval_id),
            status=response.status_code,
        )
        return False

    logger.info("chatops_notify.posted", approval_id=str(approval_id))
    return True
