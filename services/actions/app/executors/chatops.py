"""ChatOps user-verification executor.

Wave 1 of the AiSOC v6 capability roadmap. The executor:

1. Mints three HMAC-signed callback tokens — one per choice
   (``acknowledge`` / ``deny`` / ``escalate``) — using
   :mod:`app.security.chatops_token`. Each token carries the action,
   case, tenant, user reference, and an expiry derived from
   ``AISOC_CHATOPS_TIMEOUT_SECONDS``.
2. Builds three callback URLs against ``AISOC_ACTIONS_PUBLIC_URL``.
3. Posts the interactive prompt into the configured transport
   (``slack`` via Block Kit, ``teams`` via Connector Card) using the
   credential-vault-aware helpers in :mod:`app.services.chatops_prompt`.
4. Writes a ``chatops.verify.prompted`` event onto the case timeline so
   analysts see the question was asked, and returns ``ActionStatus.RUNNING``
   to signal that the analyst is now waiting on the user.

The actual user response lands on the callback endpoint (added in
``app/api/router.py``) and produces a second timeline event; this executor
deliberately does not block the request loop on a human reply.

Failure modes:

* Feature flag off — returns ``ActionStatus.FAILED`` with a clear error
  rather than silently no-op'ing, so misconfiguration is visible in tests.
* No webhook configured — same: the action exists to ask a person a
  question, so an unreachable transport is a hard fail.
* Timeline write fails — we log and surface a non-fatal warning on the
  result, but keep the action ``RUNNING`` because the prompt was already
  delivered. Losing the timeline write is recoverable, the prompt is not.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import structlog

from app.core.config import get_settings
from app.executors.base import BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus, BlastRadius
from app.security.chatops_token import ChatOpsTokenError, mint_token
from app.services.chatops_prompt import (
    ChatOpsButton,
    ChatOpsPromptError,
    send_slack_prompt,
    send_teams_prompt,
)
from app.services.timeline_client import TimelineClientError, post_timeline_event

logger = structlog.get_logger()


# Stable button order (acknowledge, deny, escalate) — keeps the prompt
# predictable across transports and makes screenshots/tests deterministic.
_CHOICES: tuple[tuple[str, str, str], ...] = (
    ("acknowledge", "Yes, that was me", "primary"),
    ("deny", "No, that wasn't me", "danger"),
    ("escalate", "I'm not sure — escalate", "default"),
)


def _build_callback_url(
    *,
    base_url: str,
    token: str,
) -> str:
    """Compose the callback URL the user clicks in chat.

    The callback path is mounted by ``app/api/router.py`` and accepts a
    single ``token`` query parameter — see the route handler for the
    matching contract.
    """
    return f"{base_url.rstrip('/')}/api/v1/chatops/callback?token={token}"


class ChatOpsVerifyExecutor(BaseExecutor):
    """Send an interactive verification prompt to the affected user."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        settings = get_settings()

        if not settings.AISOC_FEATURE_CHATOPS_VERIFY:
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.FAILED,
                blast_radius=BlastRadius.MINIMAL,
                error="ChatOps verification is disabled (AISOC_FEATURE_CHATOPS_VERIFY=False)",
            )

        params: dict[str, Any] = request.parameters or {}
        transport = str(params.get("transport", "slack")).lower()
        webhook_url = params.get("webhook_url") or ""
        bot_token = params.get("bot_token") or None
        channel = params.get("channel") or None
        question = str(
            params.get(
                "question",
                f"AiSOC needs to confirm activity on your account ({request.target}).",
            )
        )
        context = str(
            params.get(
                "context",
                f"Incident `{request.incident_id}` — rationale: {request.rationale or 'n/a'}",
            )
        )
        user_ref = str(params.get("user_ref", request.target))

        if transport not in {"slack", "teams"}:
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.FAILED,
                blast_radius=BlastRadius.MINIMAL,
                error=f"unsupported ChatOps transport: {transport!r}",
            )
        if not webhook_url:
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.FAILED,
                blast_radius=BlastRadius.MINIMAL,
                error="parameters.webhook_url is required for ChatOps verification",
            )

        # Mint one signed callback token per choice. Failures here are
        # configuration errors (missing HMAC secret), surface them up.
        try:
            buttons = [
                ChatOpsButton(
                    label=label,
                    url=_build_callback_url(
                        base_url=settings.AISOC_ACTIONS_PUBLIC_URL,
                        token=mint_token(
                            action_id=request.id,
                            case_id=request.incident_id,
                            tenant_id=request.tenant_id,
                            choice=choice,
                            user_ref=user_ref,
                            secret=settings.AISOC_CHATOPS_RESPONSE_SECRET,
                            ttl_seconds=settings.AISOC_CHATOPS_TIMEOUT_SECONDS,
                        ),
                    ),
                    style=style,
                )
                for choice, label, style in _CHOICES
            ]
        except ChatOpsTokenError as exc:
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.FAILED,
                blast_radius=BlastRadius.MINIMAL,
                error=f"failed to mint ChatOps token: {exc}",
            )

        # Deliver the prompt. If this fails, the whole action fails — there
        # is no value in marking RUNNING when no one will ever see the
        # question.
        try:
            if transport == "slack":
                delivery = await send_slack_prompt(
                    webhook_url=webhook_url,
                    question=question,
                    context=context,
                    buttons=buttons,
                    bot_token=bot_token,
                    channel=channel,
                )
            else:
                delivery = await send_teams_prompt(
                    webhook_url=webhook_url,
                    question=question,
                    context=context,
                    buttons=buttons,
                )
        except ChatOpsPromptError as exc:
            logger.warning(
                "ChatOps prompt delivery failed",
                action_id=str(request.id),
                transport=transport,
                error=str(exc),
            )
            return ActionResult(
                action_id=request.id,
                status=ActionStatus.FAILED,
                blast_radius=BlastRadius.MINIMAL,
                error=str(exc),
            )

        # Best-effort timeline write — see module docstring for why we don't
        # fail the action when this errors.
        timeline_warning: str | None = None
        try:
            await post_timeline_event(
                case_id=request.incident_id,
                event_type="chatops.verify.prompted",
                content=(
                    f"ChatOps verification sent to {user_ref} via {transport}. "
                    f"Awaiting response (TTL {settings.AISOC_CHATOPS_TIMEOUT_SECONDS}s)."
                ),
                metadata={
                    "action_id": str(request.id),
                    "tenant_id": str(request.tenant_id),
                    "transport": transport,
                    "channel": channel,
                    "user_ref": user_ref,
                    "question": question,
                    "expires_in_seconds": settings.AISOC_CHATOPS_TIMEOUT_SECONDS,
                },
            )
        except TimelineClientError as exc:
            timeline_warning = f"timeline prompt-event write failed: {exc}"
            logger.warning(
                "ChatOps timeline write failed",
                action_id=str(request.id),
                case_id=str(request.incident_id),
                error=str(exc),
            )

        logger.info(
            "ChatOps prompt delivered",
            action_id=str(request.id),
            case_id=str(request.incident_id),
            transport=transport,
            channel=channel,
        )

        return ActionResult(
            action_id=request.id,
            status=ActionStatus.RUNNING,
            blast_radius=BlastRadius.MINIMAL,
            output={
                "transport": transport,
                "channel": channel,
                "user_ref": user_ref,
                "delivery": delivery,
                "expires_in_seconds": settings.AISOC_CHATOPS_TIMEOUT_SECONDS,
                **({"timeline_warning": timeline_warning} if timeline_warning else {}),
            },
            executed_at=datetime.now(UTC),
        )


__all__ = ["ChatOpsVerifyExecutor"]
