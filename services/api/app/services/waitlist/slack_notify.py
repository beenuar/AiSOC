"""Slack webhook poster for waitlist signups — T6.1.

The signup endpoint fires a Block Kit message at a Slack incoming webhook
whenever a new entry lands, so the sales team gets a real-time ping
without anyone having to refresh ``/admin/waitlist``.

Design rules
------------

1. **Never raise into the caller.** A Slack outage cannot block a
   signup — that would make a working product feel broken to the
   prospect. Every error path logs and swallows.
2. **Use stdlib only.** ``urllib.request`` keeps the import graph clean
   and lets the API service avoid yet another HTTP-client dependency.
3. **Honour the air-gap setting.** If ``AISOC_AIRGAPPED=true`` the call
   is skipped without even attempting to resolve the webhook URL — a
   deliberate belt-and-suspenders against the egress gate.
4. **Make the message scannable.** Block Kit gives us a short header
   plus a fields-grid so the sales engineer reading on a phone can
   identify the prospect in two seconds.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib import error as urllib_error
from urllib import request as urllib_request

logger = logging.getLogger("aisoc.waitlist.slack")

# Environment variable holding the Slack incoming webhook URL. Operators
# rotate this through their secret store of choice; the value never
# touches the repo.
_WEBHOOK_ENV_VAR: str = "AISOC_WAITLIST_SLACK_WEBHOOK"
_AIRGAP_ENV_VAR: str = "AISOC_AIRGAPPED"
_REQUEST_TIMEOUT_SECONDS: float = 5.0


def _is_truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


def build_signup_message(
    *,
    email: str,
    company: str,
    role: str,
    soc_stack: list[str],
    motivation: str,
    entry_id: str,
) -> dict[str, Any]:
    """Construct the Block Kit payload for a new signup.

    Kept as a pure function so the test suite can assert message shape
    without mocking the HTTP layer.
    """
    stack_text = ", ".join(soc_stack) if soc_stack else "_not specified_"
    truncated_motivation = motivation if len(motivation) <= 500 else motivation[:497] + "..."

    return {
        "text": f"New AiSOC managed waitlist signup: {company} ({email})",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": "New managed waitlist signup",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Company:*\n{company}"},
                    {"type": "mrkdwn", "text": f"*Role:*\n{role}"},
                    {"type": "mrkdwn", "text": f"*Email:*\n{email}"},
                    {"type": "mrkdwn", "text": f"*SOC stack:*\n{stack_text}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Motivation:*\n>{truncated_motivation}",
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Entry id: `{entry_id}` · triage at `/admin/waitlist`",
                    }
                ],
            },
        ],
    }


class SlackNotifier:
    """Tiny wrapper around the Slack incoming-webhook contract.

    Exists as an instance class (rather than a free function) so tests
    can replace the singleton via :func:`get_slack_notifier` and assert
    against the captured calls.
    """

    def __init__(self, *, webhook_url: str | None = None, timeout_seconds: float | None = None) -> None:
        self._webhook_url: str | None = webhook_url
        self._timeout: float = timeout_seconds if timeout_seconds is not None else _REQUEST_TIMEOUT_SECONDS

    def _resolve_webhook(self) -> str | None:
        if self._webhook_url:
            return self._webhook_url
        return (os.getenv(_WEBHOOK_ENV_VAR, "") or "").strip() or None

    def post(self, payload: dict[str, Any]) -> bool:
        """Fire the webhook. Returns True on 2xx, False otherwise.

        Never raises; a False return + logged warning is the contract
        the endpoint relies on to keep signup success decoupled from
        Slack availability.
        """
        if _is_truthy(os.getenv(_AIRGAP_ENV_VAR)):
            logger.info("waitlist slack notification skipped: airgap mode")
            return False
        webhook = self._resolve_webhook()
        if not webhook:
            logger.info("waitlist slack notification skipped: %s not configured", _WEBHOOK_ENV_VAR)
            return False
        try:
            body = json.dumps(payload).encode("utf-8")
            req = urllib_request.Request(  # noqa: S310 — webhook URL is operator-supplied
                webhook,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib_request.urlopen(req, timeout=self._timeout) as resp:  # noqa: S310
                if 200 <= resp.status < 300:
                    return True
                logger.warning("waitlist slack webhook returned non-2xx: %s", resp.status)
                return False
        except urllib_error.URLError as exc:
            logger.warning("waitlist slack webhook URLError: %s", exc)
            return False
        except Exception as exc:  # noqa: BLE001 — never propagate; signup must succeed
            logger.warning("waitlist slack webhook unexpected error: %s", exc)
            return False


_slack_notifier_singleton: SlackNotifier | None = None


def get_slack_notifier() -> SlackNotifier:
    """Return the process-wide notifier singleton.

    The singleton resolves the webhook URL lazily from the environment
    on every ``post()`` so an operator can rotate the value at runtime
    (via a secret-store reload) without bouncing the API service.
    """
    global _slack_notifier_singleton
    if _slack_notifier_singleton is None:
        _slack_notifier_singleton = SlackNotifier()
    return _slack_notifier_singleton


def reset_slack_notifier_for_tests() -> None:
    """Drop the singleton. Test-only hook."""
    global _slack_notifier_singleton
    _slack_notifier_singleton = None
