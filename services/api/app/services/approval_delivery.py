"""Put a pending approval in front of a person, on the channels configured.

``POST /approvals`` persisted the row and fanned out one Web Push
notification. Everything else that was supposed to reach an approver had
been built and connected to nothing:

* ``services/api/app/services/email_approval.py`` holds the token issuer,
  the verifier, the renderer and ``send_approval_email`` — and the sender
  had **no caller anywhere in the tree**. The decide route
  (``/approvals/email/decide``) has been live the whole time waiting for a
  link nothing ever sent.
* ``services/teams-bot`` holds the Adaptive Card builder and the signed
  callback handler, and the service is not in any compose file, so nothing
  could post a card even if something tried.
* ``services/slack-bot`` grew ``POST /internal/approval-card`` for exactly
  this and is reached from here for the first time.

Why a fan-out module rather than three calls in the route
----------------------------------------------------------
Each channel has its own failure mode and none of them may fail the
request: the approval is already durable in Postgres by the time this runs,
and the console and the responder app can both act on it. A channel that is
down must leave a record saying so, not take the approval with it. That is
easier to get right — and much easier to test — in one place with one rule
than in three ``try``/``except`` blocks in a route handler.

Off by default, per channel
---------------------------
A channel delivers only when it is configured: no SMTP relay, no email; no
``AISOC_SLACK_BOT_URL``, no card; no ``AISOC_TEAMS_BOT_URL``, no Teams. An
unconfigured channel reports ``skipped`` with the setting that would turn it
on, which is the difference between "we chose not to" and "it broke".
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from app.services.email_approval import EmailApprovalError, send_approval_email
from app.services.smtp_delivery import SmtpApprovalMailer

logger = structlog.get_logger(__name__)

_TIMEOUT_SECONDS = 10.0


@dataclass
class DeliveryReport:
    """One line per channel, each naming what happened and why.

    Recorded on the approval row so an operator can answer "was anybody
    told?" from the record rather than from three services' logs.
    """

    channels: dict[str, dict[str, Any]] = field(default_factory=dict)

    def record(self, channel: str, *, delivered: bool, status: str, detail: str) -> None:
        self.channels[channel] = {"delivered": delivered, "status": status, "detail": detail[:300]}

    @property
    def delivered_to(self) -> list[str]:
        return sorted(name for name, result in self.channels.items() if result["delivered"])

    def as_dict(self) -> dict[str, Any]:
        return {"channels": self.channels, "delivered_to": self.delivered_to}


def _approval_recipients(row: Any) -> list[str]:
    """Addresses this approval should reach.

    Read from the approval's own ``action`` payload rather than from a
    tenant-wide list, because the caller that raises an approval is the one
    that knows who owns the decision — a global list would page the whole
    SOC for a single analyst's sign-off.
    """
    action = getattr(row, "action", None) or {}
    recipients = action.get("approver_emails") or action.get("recipients") or []
    if isinstance(recipients, str):
        recipients = recipients.split(",")
    return [str(r).strip() for r in recipients if str(r).strip()]


async def _deliver_email(row: Any, report: DeliveryReport) -> None:
    secret = os.getenv("AISOC_APPROVAL_TOKEN_SECRET", "").strip()
    recipients = _approval_recipients(row)
    mailer = SmtpApprovalMailer()

    if not recipients:
        report.record("email", delivered=False, status="skipped", detail="the approval names no approver_emails")
        return
    if not secret:
        # Fail closed and say so. Sending a decision link with no signing
        # secret would be a one-click approve anybody could forge, which is
        # worse than not sending it.
        report.record("email", delivered=False, status="skipped", detail="AISOC_APPROVAL_TOKEN_SECRET is unset, so no link could be signed")
        return
    if not mailer.configured:
        report.record("email", delivered=False, status="skipped", detail="no SMTP relay is configured (set SMTP_HOST and SMTP_SENDER)")
        return

    try:
        result = await send_approval_email(
            recipients=recipients,
            case={"id": str(getattr(row, "case_id", "") or ""), "title": getattr(row, "title", "")},
            action={
                "id": str(row.id),
                "action_type": (getattr(row, "action", None) or {}).get("action_type", "approval"),
                "target": (getattr(row, "action", None) or {}).get("target", ""),
                "risk_level": getattr(row, "risk_level", ""),
                "rationale": getattr(row, "summary", ""),
            },
            api_base_url=os.getenv("AISOC_API_PUBLIC_BASE_URL", os.getenv("CONSOLE_PUBLIC_BASE_URL", "")).rstrip("/"),
            web_base_url=os.getenv("CONSOLE_PUBLIC_BASE_URL", "").rstrip("/"),
            secret=secret,
            mailer=mailer,
        )
    except EmailApprovalError as exc:
        report.record("email", delivered=False, status="failed", detail=str(exc))
        return
    except Exception as exc:  # noqa: BLE001 — a mail failure must not take the approval with it
        logger.warning("approval_delivery.email_failed", approval_id=str(row.id), error=str(exc)[:300])
        report.record("email", delivered=False, status="failed", detail=str(exc))
        return

    delivered = bool(result.get("delivered"))
    report.record("email", delivered=delivered, status=str(result.get("status") or "sent"), detail=str(result.get("detail") or ""))


async def _post_card(url: str, token: str, payload: dict[str, Any]) -> tuple[bool, str]:
    headers = {"X-AiSOC-Internal-Token": token} if token else {}
    async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
        response = await client.post(url, json=payload, headers=headers)
    if not 200 <= response.status_code < 300:
        return False, f"HTTP {response.status_code}: {response.text[:200]}"
    body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    # The bot answers 202 with `posted: false` when it has no channel
    # configured, because the approval is already durable and chat is one
    # delivery route rather than the record. Reading the status code alone
    # would report that as a delivery.
    if isinstance(body, dict) and "posted" in body:
        return bool(body["posted"]), str(body.get("reason") or "posted")
    return True, "posted"


def _card_payload(row: Any) -> dict[str, Any]:
    action = getattr(row, "action", None) or {}
    return {
        "action": {
            "id": str(row.id),
            "action_type": action.get("action_type", "approval"),
            "target": action.get("target", ""),
            "risk_level": getattr(row, "risk_level", ""),
            "rationale": getattr(row, "summary", ""),
        },
        "case": {"id": str(getattr(row, "case_id", "") or ""), "title": getattr(row, "title", "")},
    }


async def _deliver_chat(row: Any, report: DeliveryReport, *, channel: str, url_env: str) -> None:
    base = os.getenv(url_env, "").strip().rstrip("/")
    if not base:
        report.record(channel, delivered=False, status="skipped", detail=f"{url_env} is unset")
        return
    token = os.getenv("AISOC_INTERNAL_TOKEN", "").strip()
    if not token:
        # Both bots compare this in constant time and refuse when unset, so
        # posting without it is a round trip to a guaranteed 401. Saying so
        # here names the missing setting instead of surfacing the 401.
        report.record(channel, delivered=False, status="skipped", detail="AISOC_INTERNAL_TOKEN is unset, so the bot would refuse the call")
        return
    try:
        posted, detail = await _post_card(f"{base}/internal/approval-card", token, _card_payload(row))
    except Exception as exc:  # noqa: BLE001 — a bot being down must not fail the approval
        logger.warning("approval_delivery.card_failed", channel=channel, approval_id=str(row.id), error=str(exc)[:300])
        report.record(channel, delivered=False, status="failed", detail=str(exc))
        return
    report.record(channel, delivered=posted, status="sent" if posted else "skipped", detail=detail)


async def deliver_approval(row: Any) -> DeliveryReport:
    """Offer one approval on every configured channel. Never raises.

    Channels run in sequence rather than concurrently on purpose: three
    channels is a handful of hundred-millisecond calls, and a gather here
    would make the failure of one harder to attribute for no gain a human
    waiting on an approval would notice.
    """
    report = DeliveryReport()
    await _deliver_email(row, report)
    await _deliver_chat(row, report, channel="slack", url_env="AISOC_SLACK_BOT_URL")
    await _deliver_chat(row, report, channel="teams", url_env="AISOC_TEAMS_BOT_URL")
    logger.info(
        "approval_delivery.fanned_out",
        approval_id=str(getattr(row, "id", "")),
        delivered_to=report.delivered_to,
    )
    return report
