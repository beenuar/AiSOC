"""Let the bot start a conversation.

Every route this service had was inbound: Slack posts an interaction, the bot
replies through Bolt's ``respond()``, which writes to the ``response_url``
that came with the request. That URL only exists inside an inbound
interaction, so the bot could answer a question and could not ask one.

The consequence is the shape this wave keeps finding. The cards were already
written — ``blocks.approval_card_blocks`` and the richer
``rich_approval_card_blocks``, the latter with no production caller at all —
and the button handlers that receive Approve and Deny were already wired.
What was missing between them was the ability to put a card in front of
somebody who had not just typed a slash command. So the documented "an agent
stops and asks Slack for approval" flow could only ever start with a human
asking first.

This is one route and one Slack API call. It is deliberately internal:
callers are AiSOC services, not Slack, so the request carries no Slack
signature and is authenticated with a shared token instead.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

import structlog
from fastapi import APIRouter, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.blocks import rich_approval_card_blocks
from app.core.config import get_settings

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])


class ApprovalCardRequest(BaseModel):
    """An approval an agent wants a human to decide."""

    action: dict[str, Any] = Field(
        ...,
        description="The action record: id, action_type, target, risk_level, rationale.",
    )
    case: dict[str, Any] = Field(default_factory=dict, description="Case context rendered into the card.")
    channel: str | None = Field(
        default=None,
        description="Override the configured approvals channel. Useful for per-tenant routing.",
    )
    requested_by_slack_id: str = Field(
        default="",
        description=(
            "Slack id of the requester, when there is one. An agent-raised "
            "approval has none, and the card says so rather than attributing "
            "it to whoever happens to be on call."
        ),
    )
    related_alerts: list[dict[str, Any]] | None = None
    timeout_seconds: int | None = None


def _authorized(supplied: str | None) -> bool:
    """Compare the internal token in constant time, failing closed.

    An unset token refuses every internal call unless dev mode is on. The
    alternative — treating "no token configured" as "no auth needed" — makes
    a route that can post into a workspace channel open to anything that can
    reach the pod.
    """
    settings = get_settings()
    expected = settings.AISOC_INTERNAL_TOKEN.strip()
    if not expected:
        return os.environ.get("AISOC_DEV_MODE", "").strip().lower() in {"1", "true", "yes", "on"}
    return bool(supplied) and hmac.compare_digest(supplied.strip(), expected)


@router.post("/approval-card", status_code=status.HTTP_202_ACCEPTED)
async def post_approval_card(
    body: ApprovalCardRequest,
    request: Request,
    x_internal_token: str | None = Header(default=None, alias="X-AiSOC-Internal-Token"),
) -> dict[str, Any]:
    """Post an approval card into the approvals channel.

    Returns 202 with a ``posted`` flag rather than failing when no channel is
    configured: an approval is already durable in Postgres by the time this is
    called, and the console and responder app can both act on it. Slack is one
    delivery route, not the record.
    """
    if not _authorized(x_internal_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="internal token required")

    settings = get_settings()
    channel = (body.channel or settings.SLACK_APPROVALS_CHANNEL).strip()
    if not channel:
        logger.info(
            "slack_bot.approval_card_skipped",
            reason="SLACK_APPROVALS_CHANNEL is unset",
            action_id=body.action.get("id"),
        )
        return {"posted": False, "reason": "no approvals channel configured"}

    bolt = getattr(request.app.state, "bolt_app", None)
    if bolt is None:
        logger.error("slack_bot.no_bolt_app", action_id=body.action.get("id"))
        return {"posted": False, "reason": "slack client unavailable"}

    blocks = rich_approval_card_blocks(
        action=body.action,
        case=body.case,
        requested_by_slack_id=body.requested_by_slack_id,
        web_base=settings.AISOC_WEB_BASE_URL,
        timeout_seconds=body.timeout_seconds,
        related_alerts=body.related_alerts,
    )

    try:
        response = await bolt.client.chat_postMessage(
            channel=channel,
            blocks=blocks,
            # Notification text for clients that cannot render Block Kit, and
            # for the mobile push preview — which is often all an approver
            # sees before deciding whether to open it.
            text=f"Approval needed: {body.action.get('action_type', 'action')} on {body.action.get('target', 'a target')}",
        )
    except Exception as exc:  # noqa: BLE001 — Slack being down must not fail the agent
        logger.warning(
            "slack_bot.approval_card_failed",
            action_id=body.action.get("id"),
            channel=channel,
            error=str(exc),
        )
        return {"posted": False, "reason": f"slack rejected the message ({type(exc).__name__})"}

    logger.info(
        "slack_bot.approval_card_posted",
        action_id=body.action.get("id"),
        channel=channel,
    )
    return {"posted": True, "channel": channel, "ts": response.get("ts") if hasattr(response, "get") else None}
