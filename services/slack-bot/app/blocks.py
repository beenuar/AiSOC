"""
Slack Block Kit builders for the AiSOC bot.

Every Slack response in the bot — slash command output, approval prompts,
post-decision confirmations — flows through one of these helpers. Centralising
them here means:

* the layout is unit-testable (we just compare dicts)
* the command handlers stay small and focused on orchestration
* visual consistency stays high (severity emoji, deep-link URLs, action ids)

Block Kit reference: https://api.slack.com/block-kit
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin

# --- Severity / status presentation -----------------------------------------

# Severity → emoji used at the start of every case headline. Slack-friendly
# unicode so we don't depend on a custom emoji pack being installed in the
# workspace.
_SEVERITY_EMOJI = {
    "critical": "🚨",
    "high": "🔴",
    "medium": "🟠",
    "low": "🟡",
    "info": "🔵",
}

# Status → label. We capitalise + de-snake-case so the audit trail in Slack
# matches what an analyst sees in the web UI.
_STATUS_LABEL = {
    "new": "New",
    "triaged": "Triaged",
    "investigating": "Investigating",
    "containment": "Containment",
    "remediated": "Remediated",
    "closed": "Closed",
    "false_positive": "False positive",
}


def _sev_label(severity: str | None) -> str:
    if not severity:
        return "🔵 Info"
    key = severity.lower()
    return f"{_SEVERITY_EMOJI.get(key, '⚪')} {key.title()}"


def _status_label(status: str | None) -> str:
    if not status:
        return "Unknown"
    return _STATUS_LABEL.get(status.lower(), status.replace("_", " ").title())


def _case_url(web_base: str, case_id: str) -> str:
    """
    Build a deep-link to the case in the web app. Slack requires absolute URLs
    in link buttons, so we always emit a fully-qualified ``https://`` URL even
    if the bot is configured with a base ending in ``/``.
    """
    return urljoin(web_base.rstrip("/") + "/", f"cases/{case_id}")


def _truncate(text: str, *, limit: int = 240) -> str:
    """
    Slack section text caps at 3000 chars. We keep things much shorter so
    cards stay readable in a busy SOC channel.
    """
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


# --- Public builders --------------------------------------------------------


def case_list_blocks(
    cases: list[dict[str, Any]],
    *,
    web_base: str,
    title: str = "Open cases",
) -> list[dict[str, Any]]:
    """
    Render the response to ``/aisoc list``.

    We render at most ten cases (Slack performance + screen-real-estate) and
    add a footer that prompts the analyst to filter further if the result was
    truncated.
    """
    if not cases:
        return [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{title}* — nothing to triage right now. ✅",
                },
            }
        ]

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": title, "emoji": True},
        }
    ]

    visible = cases[:10]
    for case in visible:
        case_id = str(case.get("id") or "")
        case_number = case.get("case_number") or case_id[:8]
        title_text = case.get("title") or "(untitled case)"
        severity = _sev_label(case.get("severity"))
        status = _status_label(case.get("status"))
        url = _case_url(web_base, case_id) if case_id else web_base
        line = f"*<{url}|{case_number}>* — {_truncate(title_text, limit=120)}\n{severity} · _{status}_"
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": line},
            }
        )

    if len(cases) > len(visible):
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (f"Showing {len(visible)} of {len(cases)} open cases — use `/aisoc list <severity>` to narrow."),
                    }
                ],
            }
        )

    return blocks


def case_card_blocks(
    case: dict[str, Any],
    *,
    web_base: str,
) -> list[dict[str, Any]]:
    """
    Render a single-case detail card used as the parent message for
    ``/aisoc investigate`` and ``/aisoc explain``.
    """
    case_id = str(case.get("id") or "")
    case_number = case.get("case_number") or case_id[:8]
    title = case.get("title") or "(untitled case)"
    severity = _sev_label(case.get("severity"))
    status = _status_label(case.get("status"))
    description = _truncate(case.get("description") or "")
    url = _case_url(web_base, case_id) if case_id else web_base

    fields = [
        {"type": "mrkdwn", "text": f"*Severity*\n{severity}"},
        {"type": "mrkdwn", "text": f"*Status*\n{status}"},
    ]
    alert_count = case.get("alert_count")
    if alert_count is not None:
        fields.append({"type": "mrkdwn", "text": f"*Alerts*\n{alert_count}"})
    if case.get("priority"):
        fields.append({"type": "mrkdwn", "text": f"*Priority*\n{case['priority']}"})

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Case {case_number}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{title}*"},
            "accessory": {
                "type": "button",
                "text": {"type": "plain_text", "text": "Open in AiSOC"},
                "url": url,
                "action_id": "case_open_link",
            },
        },
        {"type": "section", "fields": fields},
    ]
    if description:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": description}})

    return blocks


def investigation_started_blocks(
    case: dict[str, Any],
    investigation: dict[str, Any],
    *,
    web_base: str,
) -> list[dict[str, Any]]:
    """
    Confirmation message after ``/aisoc investigate`` succeeds.

    We include the run id and a deep-link so the analyst can hop straight to
    the live timeline in the web app.
    """
    case_id = str(case.get("id") or "")
    case_number = case.get("case_number") or case_id[:8]
    run_id = investigation.get("run_id") or investigation.get("id") or "(pending)"
    deep_link = _case_url(web_base, case_id) if case_id else web_base

    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (f"🛰️ *Investigation launched* for <{deep_link}|{case_number}>\nRun id: `{run_id}`"),
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "Live timeline updates will appear in the case channel.",
                }
            ],
        },
    ]


def case_explanation_blocks(
    case: dict[str, Any],
    summary: dict[str, Any],
    *,
    web_base: str,
) -> list[dict[str, Any]]:
    """
    Render a case auto-summary as Slack blocks (``/aisoc explain``).

    The summary endpoint returns a JSON payload with at minimum a ``summary``
    or ``narrative`` field; we surface both that and any structured
    ``recommendations`` / ``next_steps`` lists when present.
    """
    blocks = case_card_blocks(case, web_base=web_base)

    narrative = summary.get("summary") or summary.get("narrative") or summary.get("explanation") or ""
    if narrative:
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*AI summary*\n{_truncate(narrative, limit=2500)}",
                },
            }
        )

    recommendations = summary.get("recommendations") or summary.get("next_steps") or []
    if isinstance(recommendations, list) and recommendations:
        bullets = "\n".join(f"• {_truncate(str(r), limit=300)}" for r in recommendations[:6])
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Recommended next steps*\n{bullets}"},
            }
        )

    return blocks


def approval_card_blocks(
    *,
    action: dict[str, Any],
    case: dict[str, Any],
    requested_by_slack_id: str,
    web_base: str,
    timeout_seconds: int | None = None,
    safe_default: str = "rejected",
) -> list[dict[str, Any]]:
    """
    Render an approval prompt for an awaiting-approval response action.

    The ``action_id`` and ``case_id`` are stuffed into the button's ``value``
    field so the interactive handler can route the approval without a
    round-trip to the database. When ``timeout_seconds`` is set we surface a
    contextual footer so analysts know the safe-default fires automatically
    if no one decides in time (T3.6 — Block Kit v2).
    """
    action_id = str(action.get("id") or action.get("action_id") or "")
    action_type = action.get("action_type") or "unknown"
    target = action.get("target") or "unknown"
    blast = action.get("blast_radius") or "unknown"
    case_id = str(case.get("id") or "")
    case_number = case.get("case_number") or case_id[:8]
    rationale = _truncate(action.get("rationale") or "", limit=400)
    case_url = _case_url(web_base, case_id) if case_id else web_base

    button_value = f"{action_id}|{case_id}"

    headline = (
        f"⚠️ *Approval required* — `{action_type}` on `{target}`\nCase: <{case_url}|{case_number}> · Requested by <@{requested_by_slack_id}>"
    )

    blocks: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": headline}},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Action*\n`{action_type}`"},
                {"type": "mrkdwn", "text": f"*Target*\n`{target}`"},
                {"type": "mrkdwn", "text": f"*Blast radius*\n{blast}"},
                {"type": "mrkdwn", "text": f"*Action id*\n`{action_id}`"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Rationale*\n{rationale or '_(none provided)_'}",
            },
        },
        {
            "type": "actions",
            "block_id": "aisoc_action_decision",
            "elements": [
                {
                    "type": "button",
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "action_id": "aisoc_action_approve",
                    "value": button_value,
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Approve action?"},
                        "text": {
                            "type": "mrkdwn",
                            "text": (f"This will execute `{action_type}` on `{target}` and is logged to the case timeline."),
                        },
                        "confirm": {"type": "plain_text", "text": "Approve"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
                {
                    "type": "button",
                    "style": "danger",
                    "text": {"type": "plain_text", "text": "Deny"},
                    "action_id": "aisoc_action_deny",
                    "value": button_value,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Need info"},
                    "action_id": "aisoc_action_need_info",
                    "value": button_value,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Open case"},
                    "url": case_url,
                    "action_id": "aisoc_action_open_case",
                },
            ],
        },
    ]

    if timeout_seconds and timeout_seconds > 0:
        verb = "denied" if safe_default == "rejected" else safe_default
        minutes = max(1, timeout_seconds // 60)
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (f"⏱️ Auto-{verb} in *{minutes} min* if no human decides. Safe-default: `{safe_default}`."),
                    }
                ],
            }
        )

    return blocks


def rich_approval_card_blocks(
    *,
    action: dict[str, Any],
    case: dict[str, Any],
    requested_by_slack_id: str,
    web_base: str,
    timeout_seconds: int | None = None,
    safe_default: str = "rejected",
    related_alerts: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """
    Block Kit v2 approval card with full case context.

    Renders the standard approval card plus a contextual *Related alerts*
    bullet list and a *Why this matters* section pulled from the case
    description / fields. Used for high-blast-radius actions where the
    approver needs the surrounding signal to decide.

    The Approve / Deny / Need-Info routing tokens are identical to
    :func:`approval_card_blocks` so the same Bolt handlers can dispatch
    on either card shape — callers swap factories without rewiring
    interactions.
    """
    base = approval_card_blocks(
        action=action,
        case=case,
        requested_by_slack_id=requested_by_slack_id,
        web_base=web_base,
        timeout_seconds=timeout_seconds,
        safe_default=safe_default,
    )

    description = _truncate(case.get("description") or case.get("narrative") or "", limit=600)
    enriched: list[dict[str, Any]] = list(base)
    if description:
        enriched.insert(
            3,
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Why this matters*\n{description}"},
            },
        )

    alerts = related_alerts or case.get("alerts") or []
    if isinstance(alerts, list) and alerts:
        bullets = "\n".join(
            f"• `{_truncate(str(a.get('rule_name') or a.get('title') or a.get('id') or 'alert'), limit=120)}`"
            f"  {_sev_label(a.get('severity'))}"
            for a in alerts[:6]
            if isinstance(a, dict)
        )
        if bullets:
            enriched.insert(
                4 if description else 3,
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*Related alerts*\n{bullets}"},
                },
            )

    return enriched


def action_decision_blocks(
    *,
    decision: str,
    action: dict[str, Any],
    decided_by_slack_id: str,
) -> list[dict[str, Any]]:
    """
    Render the post-decision message that replaces the approval card.

    We deliberately strip the buttons so an action can't be approved twice;
    the audit trail is preserved in services/actions and surfaced on the case
    timeline. ``decision`` is ``"approved"`` or ``"rejected"`` (caller is
    responsible for normalising).
    """
    decision = decision.lower()
    icon = {"approved": "✅", "rejected": "🛑"}.get(decision, "ℹ️")
    verb = {"approved": "approved", "rejected": "denied"}.get(decision, decision)
    action_id = str(action.get("id") or action.get("action_id") or "")
    action_type = action.get("action_type") or "unknown"
    target = action.get("target") or "unknown"

    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (f"{icon} <@{decided_by_slack_id}> *{verb}* `{action_type}` on `{target}` · action `{action_id}`"),
            },
        },
    ]


def error_blocks(message: str) -> list[dict[str, Any]]:
    """
    Render a one-line error response. Used when the backend call fails or the
    user's slash command syntax is wrong; never include a stack trace because
    Slack messages can leak into customer screen-shares.
    """
    return [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"❌ {_truncate(message, limit=400)}",
            },
        }
    ]


def help_blocks() -> list[dict[str, Any]]:
    """
    Static help text rendered for ``/aisoc help`` and as a fallback for
    unknown subcommands.
    """
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "AiSOC Slack commands"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*`/aisoc list [severity]`* — list open cases\n"
                    "*`/aisoc investigate <case_id>`* — launch an investigation\n"
                    "*`/aisoc explain <case_id>`* — show the AI auto-summary\n"
                    "*`/aisoc isolate <host> <case_id> [reason]`* — request host isolation (approval required)\n"
                    "*`/aisoc block <ip|domain> <case_id> [reason]`* — request a network block (approval required)\n"
                    "*`/aisoc help`* — show this message"
                ),
            },
        },
    ]
