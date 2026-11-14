"""Out-of-band notification channels for HITL approval requests.

A pending HITL request fans out to:
- Console event bus (real-time WebSocket consumers / dashboard banners)
- Slack (interactive card with Approve / Deny buttons that deep-link to the
  console — webhooks alone can't carry MFA, so the buttons land in the secure
  console where MFA is enforced)
- Teams (same)

Network calls are best-effort: a transient send failure must not block the
HITL gateway. Failures are captured on the HitlRequest.notifications array for
audit.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.api.events import bus
from app.config import settings
from app.models.hitl import HitlRequest

logger = logging.getLogger(__name__)

# Keep the network egress fast — a slow Slack/Teams ingest must never stall
# an analyst in front of the approval card.
_HTTP_TIMEOUT = httpx.Timeout(5.0, connect=3.0)


def _approval_url(req: HitlRequest) -> str:
    base = settings.hitl_console_base_url.rstrip("/")
    return f"{base}/cases/{req.case_id}#hitl-{req.id}"


def _summary_text(req: HitlRequest) -> str:
    return (
        f"[HITL] {req.agent} → {req.tool_name} on case #{req.case_id}\n"
        f"risk={req.risk_class}  expires={req.expires_at.isoformat()}\n"
        f"rationale: {req.rationale or '(none)'}"
    )


def _slack_payload(req: HitlRequest) -> dict[str, Any]:
    url = _approval_url(req)
    return {
        "text": f"Cyble AiSOC: approval required for {req.tool_name}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔒 HITL approval — {req.tool_name}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Case*\n#{req.case_id}"},
                    {"type": "mrkdwn", "text": f"*Agent*\n{req.agent}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk*\n{req.risk_class}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Expires*\n{req.expires_at.isoformat()}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Rationale*\n{req.rationale or '_(no rationale provided)_'}",
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "style": "primary",
                        "text": {"type": "plain_text", "text": "Review & Approve"},
                        "url": url,
                    },
                    {
                        "type": "button",
                        "style": "danger",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "url": url + "?action=deny",
                    },
                ],
            },
        ],
    }


def _teams_payload(req: HitlRequest) -> dict[str, Any]:
    url = _approval_url(req)
    return {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": f"HITL approval — {req.tool_name}",
        "themeColor": "D63333",
        "title": f"Cyble AiSOC: HITL approval — {req.tool_name}",
        "sections": [
            {
                "facts": [
                    {"name": "Case", "value": f"#{req.case_id}"},
                    {"name": "Agent", "value": req.agent},
                    {"name": "Tool", "value": req.tool_name},
                    {"name": "Integration", "value": req.integration},
                    {"name": "Risk class", "value": req.risk_class},
                    {"name": "Expires at", "value": req.expires_at.isoformat()},
                ],
                "text": req.rationale or "_(no rationale provided)_",
            }
        ],
        "potentialAction": [
            {
                "@type": "OpenUri",
                "name": "Review & Approve in console",
                "targets": [{"os": "default", "uri": url}],
            },
            {
                "@type": "OpenUri",
                "name": "Deny in console",
                "targets": [{"os": "default", "uri": url + "?action=deny"}],
            },
        ],
    }


async def _post_webhook(name: str, url: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Best-effort webhook POST. Returns a notification record dict."""
    rec: dict[str, Any] = {
        "channel": name,
        "sent_at": datetime.now(timezone.utc).isoformat(),
        "ok": False,
    }
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            r = await client.post(url, json=payload)
        rec["ok"] = 200 <= r.status_code < 300
        if not rec["ok"]:
            rec["error"] = f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as exc:  # pragma: no cover - network only
        rec["error"] = f"{type(exc).__name__}: {exc}"
    return rec


def publish_console_event(event: dict[str, Any]) -> None:
    """Publish to the in-process event bus (WebSocket fan-out)."""
    try:
        bus.publish(event)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("hitl: console event publish failed: %s", exc)


async def dispatch_request(req: HitlRequest) -> list[dict[str, Any]]:
    """Fan out a newly-created HITL request to all configured channels."""
    notifications: list[dict[str, Any]] = []

    # 1. Console event bus — always on, the operator console is the
    #    authoritative approval surface.
    publish_console_event(
        {
            "type": "hitl.requested",
            "tenant_id": req.tenant_id,
            "request_id": req.id,
            "case_id": req.case_id,
            "agent": req.agent,
            "tool_name": req.tool_name,
            "integration": req.integration,
            "risk_class": req.risk_class,
            "expires_at": req.expires_at.isoformat(),
            "rationale": req.rationale,
            "blast_radius": req.blast_radius,
            "approval_url": _approval_url(req),
        }
    )
    notifications.append(
        {
            "channel": "console",
            "sent_at": datetime.now(timezone.utc).isoformat(),
            "ok": True,
        }
    )

    # 2. Slack
    if settings.hitl_slack_webhook:
        notifications.append(
            await _post_webhook("slack", settings.hitl_slack_webhook, _slack_payload(req))
        )

    # 3. Teams
    if settings.hitl_teams_webhook:
        notifications.append(
            await _post_webhook("teams", settings.hitl_teams_webhook, _teams_payload(req))
        )

    return notifications


def publish_decision_event(req: HitlRequest) -> None:
    """Broadcast a decision so blocked agents and UI clients can react."""
    publish_console_event(
        {
            "type": "hitl.decided",
            "tenant_id": req.tenant_id,
            "request_id": req.id,
            "case_id": req.case_id,
            "state": req.state.value if hasattr(req.state, "value") else str(req.state),
            "decided_by": req.decided_by,
            "decided_at": req.decided_at.isoformat() if req.decided_at else None,
            "channel": req.decided_channel.value if req.decided_channel else None,
        }
    )


def publish_escalation_event(req: HitlRequest) -> None:
    publish_console_event(
        {
            "type": "hitl.escalated",
            "tenant_id": req.tenant_id,
            "request_id": req.id,
            "case_id": req.case_id,
            "escalation_target": req.escalation_target,
            "escalated_at": req.escalated_at.isoformat() if req.escalated_at else None,
        }
    )
