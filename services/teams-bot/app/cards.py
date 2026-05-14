"""
Adaptive Card factories for the AiSOC Teams bot.

Mirrors :mod:`services.slack-bot.app.blocks` but emits Microsoft Teams
Adaptive Card JSON (schema 1.5 — the highest Outlook + Teams desktop +
mobile all support).

Every card we ship binds three primitives:

* **Header** — case number, severity, status, deep-link to the web UI.
* **Body** — action context (target, blast radius, rationale).
* **Actions** — Approve / Deny / Need-Info, each one an
  ``Action.Submit`` whose ``data`` payload carries the verb, the action
  id, the case id, an issuance timestamp, and an HMAC signature over
  those four canonical fields. The callback handler verifies the
  signature before touching upstream services so a malformed or
  replayed card payload is rejected locally.

The Adaptive Card schema reference lives at
https://adaptivecards.io/explorer/ — we lean on ``Container`` /
``FactSet`` / ``ActionSet`` because those render identically across
Teams desktop, web, and the new Outlook Actionable Message host.

Why a hand-rolled factory rather than the bot-builder SDK
=========================================================

The microsoft-bot-builder Python SDK weighs ~40 dependencies and is
focused on stateful conversation orchestration. Approval cards are
stateless one-shot payloads — the *only* logic on the Teams side is
"render JSON, post to the activity endpoint, verify the signed reply".
Keeping this as a pure-Python factory makes it:

* trivially unit-testable (dict equality, no network);
* import-free (we don't drag the bot framework into the audit pipeline);
* portable to Outlook Actionable Messages without a rewrite — the
  Action.Submit payload shape is the same.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin

from app.services.hmac_signer import sign_card_data

SEVERITY_COLOUR = {
    "critical": "attention",
    "high": "warning",
    "medium": "warning",
    "low": "good",
    "info": "default",
}


def _case_url(web_base: str, case_id: str) -> str:
    if not case_id:
        return web_base
    return urljoin(web_base.rstrip("/") + "/", f"cases/{case_id}")


def _truncate(text: str, *, limit: int = 240) -> str:
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _envelope(card: dict[str, Any]) -> dict[str, Any]:
    """Wrap a card body in the standard Adaptive Card envelope."""
    return {
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "type": "AdaptiveCard",
        "version": "1.5",
        **card,
    }


def case_context_card(case: dict[str, Any], *, web_base: str) -> dict[str, Any]:
    """Lightweight informational card with case header + open link."""
    case_id = str(case.get("id") or "")
    case_number = case.get("case_number") or case_id[:8]
    title = case.get("title") or "(untitled case)"
    severity = (case.get("severity") or "info").lower()
    status = (case.get("status") or "new").replace("_", " ").title()
    url = _case_url(web_base, case_id)

    return _envelope(
        {
            "body": [
                {
                    "type": "TextBlock",
                    "text": f"Case {case_number}",
                    "weight": "Bolder",
                    "size": "Large",
                    "color": SEVERITY_COLOUR.get(severity, "default"),
                },
                {
                    "type": "TextBlock",
                    "text": _truncate(title, limit=200),
                    "wrap": True,
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Severity", "value": severity.title()},
                        {"title": "Status", "value": status},
                    ],
                },
            ],
            "actions": [
                {
                    "type": "Action.OpenUrl",
                    "title": "Open in AiSOC",
                    "url": url,
                }
            ],
        }
    )


def approval_card(
    *,
    action: dict[str, Any],
    case: dict[str, Any],
    requested_by: str,
    web_base: str,
    signing_secret: str,
    timeout_seconds: int | None = None,
    safe_default: str = "rejected",
    issued_at: int | None = None,
) -> dict[str, Any]:
    """
    Render an interactive approval card with Approve / Deny / Need-Info
    ``Action.Submit`` buttons.

    Each button's ``data`` payload is HMAC-signed by
    :func:`app.services.hmac_signer.sign_card_data` so the callback
    handler can reject a forged or replayed payload before it ever
    touches ``services/actions``.
    """
    action_id = str(action.get("id") or action.get("action_id") or "")
    action_type = action.get("action_type") or "unknown"
    target = action.get("target") or "unknown"
    blast = action.get("blast_radius") or "unknown"
    case_id = str(case.get("id") or "")
    case_number = case.get("case_number") or case_id[:8]
    rationale = _truncate(action.get("rationale") or "", limit=400)
    severity = (case.get("severity") or "info").lower()
    issued = int(issued_at if issued_at is not None else time.time())

    def _button(verb: str, title: str, style: str | None = None) -> dict[str, Any]:
        data = sign_card_data(
            verb=verb,
            action_id=action_id,
            case_id=case_id,
            issued_at=issued,
            secret=signing_secret,
        )
        btn: dict[str, Any] = {
            "type": "Action.Submit",
            "title": title,
            "data": data,
        }
        if style:
            btn["style"] = style
        return btn

    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": f"⚠️  Approval required — {action_type} on {target}",
            "weight": "Bolder",
            "size": "Large",
            "color": SEVERITY_COLOUR.get(severity, "attention"),
            "wrap": True,
        },
        {
            "type": "TextBlock",
            "text": f"Case {case_number} · Requested by {requested_by}",
            "isSubtle": True,
            "wrap": True,
        },
        {
            "type": "FactSet",
            "facts": [
                {"title": "Action", "value": action_type},
                {"title": "Target", "value": target},
                {"title": "Blast radius", "value": str(blast)},
                {"title": "Action id", "value": action_id},
            ],
        },
        {
            "type": "TextBlock",
            "text": f"**Rationale**\n{rationale or '_(none provided)_'}",
            "wrap": True,
        },
    ]

    if timeout_seconds and timeout_seconds > 0:
        minutes = max(1, timeout_seconds // 60)
        verb = "denied" if safe_default == "rejected" else safe_default
        body.append(
            {
                "type": "TextBlock",
                "text": f"⏱️  Auto-{verb} in {minutes} min · safe-default `{safe_default}`",
                "isSubtle": True,
                "size": "Small",
                "spacing": "Medium",
            }
        )

    actions = [
        _button("approve", "Approve", style="positive"),
        _button("reject", "Deny", style="destructive"),
        _button("need_info", "Need info"),
        {
            "type": "Action.OpenUrl",
            "title": "Open case",
            "url": _case_url(web_base, case_id),
        },
    ]

    return _envelope({"body": body, "actions": actions})


def decision_card(*, decision: str, action_id: str, decided_by: str) -> dict[str, Any]:
    """Replace the approval card with a static decision audit-trail line."""
    icon = {"approved": "✅", "rejected": "🛑", "need_info": "❓", "timeout_fallback": "⌛"}.get(decision, "ℹ️")
    return _envelope(
        {
            "body": [
                {
                    "type": "TextBlock",
                    "text": f"{icon} {decided_by} {decision} action {action_id}",
                    "wrap": True,
                }
            ]
        }
    )
