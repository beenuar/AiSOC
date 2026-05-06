"""Send the interactive ChatOps verification message.

Two transports today, mirroring how AiSOC connectors are wired:

* ``slack`` — POSTs an `Incoming Webhook
  <https://api.slack.com/messaging/webhooks>`_ payload with a Block Kit
  ``actions`` block. Buttons carry plain ``url`` links back to the actions
  service, so the user does not need a Slack app installed; any tenant
  with a webhook can use this on day one.
* ``teams`` — POSTs an `MessageCard
  <https://learn.microsoft.com/en-us/microsoftteams/platform/task-modules-and-cards/cards/cards-reference#office-365-connector-card>`_
  with ``OpenUri`` actions. Same property: webhook-only, no bot-app
  required for the smallest install.

Bot tokens (when present) are decrypted via the shared credential vault
so an organisation that has migrated to OAuth tokens can ship them through
the same code path without re-implementing decryption.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
import structlog

from app.security.credential_vault import CredentialVaultError, get_vault

logger = structlog.get_logger()


@dataclass(frozen=True)
class ChatOpsButton:
    label: str
    url: str
    style: str = "primary"  # one of primary | danger | default


class ChatOpsPromptError(RuntimeError):
    """Raised when the prompt can't be delivered (network / HTTP error)."""


def _maybe_decrypt(secret: str | None) -> str | None:
    """Decrypt a vault-prefixed bot token if needed.

    Plaintext webhooks pass through untouched; vault-prefixed tokens go
    through the shared Fernet keyring. Anything else surfaces a
    ``ChatOpsPromptError`` so a misconfigured tenant fails loud rather than
    silently using a corrupted credential.
    """
    if secret is None or secret == "":
        return secret
    try:
        return get_vault().decrypt(secret)
    except CredentialVaultError as exc:
        raise ChatOpsPromptError(f"failed to decrypt ChatOps credential: {exc}") from exc


async def send_slack_prompt(
    *,
    webhook_url: str,
    question: str,
    context: str,
    buttons: list[ChatOpsButton],
    bot_token: str | None = None,
    channel: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Post the interactive prompt into Slack.

    ``webhook_url`` itself may be vault-encrypted — the click-and-connect
    flow stores connector secrets that way. ``bot_token`` is accepted for
    parity with future flows that swap incoming webhooks for the Web API,
    but the default Block Kit payload below works against both.
    """
    decrypted_webhook = _maybe_decrypt(webhook_url)
    if not decrypted_webhook:
        raise ChatOpsPromptError("Slack webhook URL is empty after decryption")
    _ = _maybe_decrypt(bot_token)  # validates the token decrypts; not yet used by webhooks

    elements = [
        {
            "type": "button",
            "text": {"type": "plain_text", "text": btn.label, "emoji": True},
            "url": btn.url,
            "style": btn.style if btn.style in {"primary", "danger"} else None,
        }
        for btn in buttons
    ]
    # Slack rejects ``style: null``, so strip keys that came back as None.
    elements = [{k: v for k, v in el.items() if v is not None} for el in elements]

    payload: dict[str, Any] = {
        "text": f"AiSOC verification: {question}",
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*{question}*"}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": context}]},
            {"type": "actions", "elements": elements},
        ],
    }
    if channel:
        payload["channel"] = channel

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(decrypted_webhook, json=payload)
    if resp.status_code >= 400:
        raise ChatOpsPromptError(f"Slack webhook returned HTTP {resp.status_code}: {resp.text[:200]}")
    return {"transport": "slack", "channel": channel, "status_code": resp.status_code}


async def send_teams_prompt(
    *,
    webhook_url: str,
    question: str,
    context: str,
    buttons: list[ChatOpsButton],
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Post the interactive prompt into Microsoft Teams via Connector Card."""
    decrypted_webhook = _maybe_decrypt(webhook_url)
    if not decrypted_webhook:
        raise ChatOpsPromptError("Teams webhook URL is empty after decryption")

    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"AiSOC verification: {question}",
        "themeColor": "0078D4",
        "title": "AiSOC verification",
        "text": f"**{question}**\n\n{context}",
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": btn.label,
                "targets": [{"os": "default", "uri": btn.url}],
            }
            for btn in buttons
        ],
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(decrypted_webhook, json=payload)
    if resp.status_code >= 400:
        raise ChatOpsPromptError(f"Teams webhook returned HTTP {resp.status_code}: {resp.text[:200]}")
    return {"transport": "teams", "status_code": resp.status_code}
