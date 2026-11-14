"""Let the Teams bot start a conversation.

Exactly the gap ``services/slack-bot/app/notify.py`` closed, one service
over, and for the same reason: every route here was inbound. Teams posts an
``invoke`` activity, the bot verifies the signed card payload and answers —
so the bot could *answer* a question and could not *ask* one. The card
builder (``cards.approval_card``) and the signed callback handler were both
written and both reachable only from a conversation a human had already
started.

So the documented "an agent stops and asks Teams for approval" flow could
only ever begin with a person typing first. This is one route and one
outbound call to the Bot Framework.

Why an incoming webhook and not the Bot Framework proactive API
----------------------------------------------------------------
Posting proactively through the Bot Framework needs a stored conversation
reference per channel, a Microsoft App ID and a client secret this service
has never held — the module docstring in ``main.py`` is explicit that the
outer Bot Framework auth is terminated by the fronting proxy and that the
bot "never minted or holds the Microsoft secret". A Workflows incoming
webhook needs none of that: the URL is the credential, an operator creates
it on the channel they want, and the card payload is the same Adaptive Card
the callback handler already signs.

Authentication is the same shared internal token the Slack bot uses, for
the same reason: the caller is an AiSOC service, not Teams, so there is no
Teams signature to verify and a bearer token the operator generates is what
``scripts/ensure_env.py`` already provisions.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

import httpx
import structlog
from fastapi import APIRouter, Header, HTTPException, status
from pydantic import BaseModel, Field

from app.cards import approval_card

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/internal", tags=["internal"])

_TIMEOUT_SECONDS = 10.0


class ApprovalCardRequest(BaseModel):
    """An approval an agent wants a human in Teams to decide."""

    action: dict[str, Any] = Field(..., description="The action record: id, action_type, target, risk_level, rationale.")
    case: dict[str, Any] = Field(default_factory=dict, description="Case context rendered into the card.")
    # No `webhook_url`. It used to be accepted here as a per-tenant routing
    # override and posted to directly, which is a full server-side request
    # forgery: anything that can reach this pod chose where an internal
    # service sent an authenticated-looking POST. CodeQL flagged it
    # `py/full-ssrf` at critical.
    #
    # Removed rather than validated. The only production caller
    # (`services/agents/app/investigator/chatops_notify.py`) never set it --
    # only the tests did -- so the field was attack surface with no user,
    # and the destination belongs to the deployment's configuration the way
    # the tenant belongs to the credential. Per-tenant routing, if it is
    # wanted later, is a stored per-tenant setting this service reads, not
    # a string in a request body.
    requested_by: str = Field(
        default="",
        description=(
            "Who asked, when somebody did. An agent-raised approval has nobody, and the card says so rather than "
            "attributing it to whoever happens to be on call."
        ),
    )
    timeout_seconds: int | None = None


def _authorized(supplied: str | None) -> bool:
    """Constant-time compare, failing closed on an unset token.

    No dev-mode exemption, matching the Slack bot: that exemption used to
    exist there and it was the state a stock install ran in, so a route
    that posts into a workspace channel was open to anything that could
    reach the pod.
    """
    expected = os.environ.get("AISOC_INTERNAL_TOKEN", "").strip()
    if not expected:
        return False
    # Narrowed with a statement rather than `bool(supplied) and ...`: the
    # call form is identical at runtime, and the type checker cannot carry
    # the truthiness of a `str | None` across `and` into `.strip()`.
    if not supplied:
        return False
    return hmac.compare_digest(supplied.strip(), expected)


@router.post("/approval-card", status_code=status.HTTP_202_ACCEPTED)
async def post_approval_card(
    body: ApprovalCardRequest,
    x_internal_token: str | None = Header(default=None, alias="X-AiSOC-Internal-Token"),
) -> dict[str, Any]:
    """Post an approval card into the configured Teams channel.

    Returns 202 with ``posted: false`` rather than failing when no webhook
    is configured. The approval is already durable in Postgres by the time
    this is called and the console and responder app can both act on it;
    Teams is one delivery route, not the record. The caller reads ``posted``
    rather than the status code, so a skipped post is not recorded as a
    delivery.
    """
    if not _authorized(x_internal_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="internal token required")

    webhook_url = os.environ.get("TEAMS_APPROVALS_WEBHOOK_URL", "").strip()
    if not webhook_url:
        logger.info("teams_bot.approval_card_skipped", reason="TEAMS_APPROVALS_WEBHOOK_URL is unset", action_id=body.action.get("id"))
        return {"posted": False, "reason": "no approvals webhook configured"}

    signing_secret = os.environ.get("AISOC_TEAMS_CALLBACK_SECRET", "").strip()
    if not signing_secret:
        # Refused rather than posted unsigned. The buttons carry an
        # HMAC-signed payload that `handle_card_action` verifies, so a card
        # signed with an empty secret is one whose Approve button the
        # callback handler will reject — a card that looks actionable and
        # is not is worse than no card.
        logger.warning("teams_bot.approval_card_unsigned", action_id=body.action.get("id"))
        return {"posted": False, "reason": "AISOC_TEAMS_CALLBACK_SECRET is unset, so the card's buttons could not be signed"}

    card = approval_card(
        action=body.action,
        case=body.case,
        requested_by=body.requested_by,
        web_base=os.environ.get("AISOC_WEB_BASE_URL", ""),
        signing_secret=signing_secret,
        timeout_seconds=body.timeout_seconds,
    )

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            response = await client.post(webhook_url, json=card)
    except Exception as exc:  # noqa: BLE001 — Teams being down must not fail the agent
        logger.warning("teams_bot.approval_card_failed", action_id=body.action.get("id"), error=str(exc))
        return {"posted": False, "reason": f"Teams rejected the message ({type(exc).__name__})"}

    if not 200 <= response.status_code < 300:
        logger.warning("teams_bot.approval_card_rejected", action_id=body.action.get("id"), status_code=response.status_code)
        return {"posted": False, "reason": f"Teams returned HTTP {response.status_code}"}

    logger.info("teams_bot.approval_card_posted", action_id=body.action.get("id"))
    return {"posted": True}
