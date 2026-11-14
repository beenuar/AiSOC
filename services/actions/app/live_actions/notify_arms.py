"""Where a playbook's ``notify`` step actually goes.

``notify`` has had a capability contract and one arm (``slack``, through
``NotifySlackExecutor``) since the live-action registry was built. The
playbook engine never used either: ``_handle_notify`` had a single sender,
``channel == "webhook"``, and all 63 ``notify`` steps in the shipped packs
address ``slack``, ``pagerduty`` or ``email`` by a *named destination*
(``webhook_env: "SLACK_SOC_WEBHOOK"``, ``service_key_env: "PD_SOC_KEY"``).
Every one of them answered ``{"delivered": false, "reason": "no url"}``.

Three arms are added here — Teams, PagerDuty and email. Slack keeps its
legacy adapter in ``builtins`` because ``ActionType.NOTIFY_SLACK`` is a
documented request field on the older ``POST /actions`` path, and two code
paths to one channel is how one of them comes to behave differently; its
two real defects are fixed where they were, in ``NotifySlackExecutor`` and
in the adapter's dry run.

The channel the step names picks the arm, pinned by the caller rather than
inferred, for the reason the SIEM arms pin ``alert_vendor``: otherwise
whichever destination happens to hold credentials decides where a page goes.

Vendor references, read before writing each sender
--------------------------------------------------
* Microsoft Teams, Workflows ("Post to a channel when a webhook request is
  received") —
  https://support.microsoft.com/en-us/office/create-incoming-webhooks-with-workflows-for-microsoft-teams-8ae491c7-0394-4861-ba59-055e33f75498
  The payload is a Bot Framework message carrying an Adaptive Card
  attachment. The retired Office 365 connector ``MessageCard`` format is
  deliberately not used; Microsoft stopped provisioning those endpoints.
* Adaptive Card schema 1.4 — https://adaptivecards.io/explorer/
  1.4 rather than a later version because that is the highest the Teams
  client renders on all current channels.
* PagerDuty Events API v2 — https://developer.pagerduty.com/docs/events-api-v2-overview
  Driven through the existing ``PagerDutyClient``, which already speaks it.
* SMTP — stdlib ``smtplib``/``email.message``, run off the event loop.

Credential keys match the sender exactly
----------------------------------------
``_credential_keys`` on each arm names precisely the keys that arm's sender
reads. A dry run works by stripping those keys, so a list that misses one
leaves a live credential in a preview — which is how a "dry run" called a
customer's Splunk, twice. ``test_notify_arms.py`` asserts the two agree by
reading the sender's source, so a key added to one and not the other fails.
"""

from __future__ import annotations

import asyncio
import json
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

import httpx
import structlog

from app.clients.pagerduty_client import PagerDutyClient
from app.live_actions.capability_contracts import apply_contract
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus

logger = structlog.get_logger(__name__)

_TIMEOUT_S = 10.0


def _result(
    executor: LiveActionExecutor,
    request: LiveActionRequest,
    status: LiveActionStatus,
    summary: str,
    *,
    details: dict[str, Any] | None = None,
    error: str | None = None,
) -> LiveActionResult:
    return LiveActionResult(
        request_id=request.request_id,
        status=status,
        capability=executor.capability,
        vendor_id=executor.vendor_id,
        summary=summary,
        details=details or {},
        error=error,
    )


def _message(request: LiveActionRequest) -> str:
    params = request.params or {}
    return str(params.get("message") or params.get("text") or "AiSOC playbook notification").strip()


def _missing(executor: LiveActionExecutor, request: LiveActionRequest, what: str) -> LiveActionResult:
    """No destination configured. Not a failure of the message.

    Split out because "we could not reach the destination" and "this tenant
    has not configured one" send an operator to different places, and the
    old handler collapsed both into "no url".
    """
    return _result(
        executor,
        request,
        LiveActionStatus.FAILED,
        f"no {executor.vendor_id} destination is configured for this tenant",
        error=(
            f"{executor.vendor_id} notification needs {what}, which this tenant has not configured. "
            f"Nothing was sent, and this says nothing about the message."
        ),
    )


def _simulated(executor: LiveActionExecutor, request: LiveActionRequest) -> LiveActionResult:
    return _result(
        executor,
        request,
        LiveActionStatus.SIMULATED,
        f"would notify {executor.vendor_id}: {_message(request)[:120]}",
        details={"would_notify": executor.vendor_id, "message": _message(request)},
    )


@apply_contract
class TeamsWebhookNotify(LiveActionExecutor):
    """Post to a Teams channel through a Workflows webhook.

    The payload is the Bot Framework envelope a Power Automate "When a Teams
    webhook request is received" trigger accepts, carrying one Adaptive Card.
    The older ``MessageCard`` shape is deliberately not used: Microsoft
    retired Office 365 connectors, so a tenant setting this up today cannot
    create an endpoint that reads it.
    """

    vendor_id = "teams"
    capability = "notify"
    description = "Post a playbook notification to Microsoft Teams through a Workflows webhook."
    requires_credentials = True
    _credential_keys: tuple[str, ...] = ("webhook_url",)

    def _payload(self, request: LiveActionRequest) -> dict[str, Any]:
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "text": "AiSOC", "weight": "Bolder", "size": "Small", "isSubtle": True},
                            {"type": "TextBlock", "text": _message(request), "wrap": True},
                        ],
                    },
                }
            ],
        }

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        if request.dry_run:
            return _simulated(self, request)

        webhook_url = str((request.params or {}).get("webhook_url") or "").strip()
        if not webhook_url:
            return _missing(self, request, "a Workflows webhook URL")

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
                response = await client.post(webhook_url, json=self._payload(request))
        except httpx.HTTPError as exc:
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "Teams did not accept the notification",
                error=f"Teams webhook failed: {exc}",
            )

        if not 200 <= response.status_code < 300:
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                f"Teams rejected the notification (HTTP {response.status_code})",
                error=f"Teams webhook returned HTTP {response.status_code}: {response.text[:200]}",
            )

        return _result(
            self,
            request,
            LiveActionStatus.SUCCEEDED,
            f"Notified Teams: {_message(request)[:120]}",
            # The webhook URL is itself the bearer credential, so the audit
            # record names the destination and never its address.
            details={"destination": str((request.params or {}).get("destination") or ""), "http_status": response.status_code},
        )


@apply_contract
class PagerDutyNotify(LiveActionExecutor):
    """Page an on-call responder through the PagerDuty Events API v2.

    The routing key is the Events-API integration key, which is a different
    secret from the REST API key the PagerDuty *connector* stores — the two
    auth surfaces are separate by PagerDuty's design, and conflating them is
    why ``credential_resolver`` already carries a note about it.
    """

    vendor_id = "pagerduty"
    capability = "notify"
    description = "Trigger a PagerDuty incident for a playbook notification (Events API v2)."
    requires_credentials = True
    _credential_keys: tuple[str, ...] = ("pd_routing_key",)

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        if request.dry_run:
            return _simulated(self, request)

        params = request.params or {}
        routing_key = str(params.get("pd_routing_key") or "").strip()
        if not routing_key:
            return _missing(self, request, "an Events API v2 routing key")

        # AiSOC's five-tier severity is passed through as-is: the client owns
        # the fold onto the four values the Events API accepts, and a second
        # copy of that map here is a second thing to get wrong.
        #
        # `case_id` seeds the dedup key, so re-running a playbook updates the
        # existing page instead of opening a second one for the same incident.
        try:
            response = await PagerDutyClient(routing_key=routing_key).trigger_incident(
                summary=_message(request)[:1024],
                severity=str(params.get("severity") or "medium"),
                case_id=str(params.get("dedup_key") or request.playbook_run_id or request.request_id),
                source=str(params.get("source") or "aisoc"),
            )
        except Exception as exc:  # noqa: BLE001 — a vendor error is FAILED, never silent
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "PagerDuty did not accept the page",
                error=f"PagerDuty Events API failed: {exc}",
            )

        return _result(
            self,
            request,
            LiveActionStatus.SUCCEEDED,
            f"Paged PagerDuty: {_message(request)[:120]}",
            details={"destination": str(params.get("destination") or ""), "dedup_key": response.get("dedup_key", "")},
        )


def _send_smtp(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_username: str,
    smtp_password: str,
    smtp_use_tls: bool,
    sender: str,
    recipients: list[str],
    subject: str,
    body: str,
) -> None:
    """One blocking SMTP send, called off the event loop.

    ``smtplib`` rather than a new dependency: the playbook packages state
    "zero external dependencies beyond httpx + stdlib" and the pack
    validator imports this tree with only jsonschema, pydantic and httpx
    installed. A dependency added here fails that job rather than this one.
    """
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = subject
    message.set_content(body)

    if smtp_use_tls:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=_TIMEOUT_S) as server:
            server.starttls(context=ssl.create_default_context())
            if smtp_username:
                server.login(smtp_username, smtp_password)
            server.send_message(message)
        return
    with smtplib.SMTP(smtp_host, smtp_port, timeout=_TIMEOUT_S) as server:
        if smtp_username:
            server.login(smtp_username, smtp_password)
        server.send_message(message)


@apply_contract
class EmailNotify(LiveActionExecutor):
    """Send a playbook notification over the tenant's SMTP relay."""

    vendor_id = "email"
    capability = "notify"
    description = "Send a playbook notification by email through the tenant's SMTP relay."
    requires_credentials = True
    _credential_keys: tuple[str, ...] = (
        "smtp_host",
        "smtp_port",
        "smtp_username",
        "smtp_password",
        "smtp_use_tls",
        "smtp_sender",
        "smtp_recipients",
    )

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        if request.dry_run:
            return _simulated(self, request)

        params = request.params or {}
        host = str(params.get("smtp_host") or "").strip()
        raw_recipients = params.get("smtp_recipients") or params.get("to") or []
        recipients = [
            r.strip() for r in (raw_recipients.split(",") if isinstance(raw_recipients, str) else raw_recipients) if str(r).strip()
        ]
        if not host:
            return _missing(self, request, "an SMTP relay host")
        if not recipients:
            return _missing(self, request, "at least one recipient address")

        message = _message(request)
        try:
            await asyncio.to_thread(
                _send_smtp,
                smtp_host=host,
                smtp_port=int(params.get("smtp_port") or 587),
                smtp_username=str(params.get("smtp_username") or ""),
                smtp_password=str(params.get("smtp_password") or ""),
                smtp_use_tls=str(params.get("smtp_use_tls", "true")).strip().lower() not in {"0", "false", "no", "off"},
                sender=str(params.get("smtp_sender") or "aisoc@localhost"),
                recipients=recipients,
                subject=str(params.get("subject") or "AiSOC playbook notification"),
                body=message,
            )
        except Exception as exc:  # noqa: BLE001 — a relay error is FAILED, never silent
            return _result(
                self,
                request,
                LiveActionStatus.FAILED,
                "the SMTP relay did not accept the notification",
                error=f"SMTP send failed: {exc}",
            )

        return _result(
            self,
            request,
            LiveActionStatus.SUCCEEDED,
            f"Emailed {len(recipients)} recipient(s): {message[:120]}",
            details={"destination": str(params.get("destination") or ""), "recipient_count": len(recipients)},
        )


#: Channel name as a playbook author writes it -> the arm that serves it.
#: Exported so ``scripts`` and the API can answer "which channels deliver"
#: from the registry rather than from a second list.
NOTIFY_ARMS: tuple[type[LiveActionExecutor], ...] = (
    TeamsWebhookNotify,
    PagerDutyNotify,
    EmailNotify,
)


def notify_payload_preview(vendor_id: str, message: str) -> str:
    """The exact body an arm would post, for the docs and the mock tests."""
    executor = next((arm for arm in NOTIFY_ARMS if arm.vendor_id == vendor_id), None)
    if executor is None or not hasattr(executor, "_payload"):
        return ""
    request = LiveActionRequest(capability="notify", vendor_id=vendor_id, params={"message": message})
    # Guarded by the `hasattr` above: `_payload` is defined by the arms
    # that build a body, and this returns "" for the ones that do not.
    return json.dumps(executor()._payload(request), sort_keys=True)  # type: ignore[attr-defined]
