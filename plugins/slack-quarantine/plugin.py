"""
Slack Quarantine Notifier — AiSOC Reference Plugin
====================================================
Posts quarantine / isolation events to Slack using Block Kit formatting.

Payload keys:
  host        (str)  : Hostname or IP being quarantined.
  user        (str)  : (optional) Associated user account.
  case_id     (str)  : AiSOC case identifier.
  reason      (str)  : Brief description of why the host is being isolated.
  severity    (str)  : "info" | "low" | "medium" | "high" | "critical"
  action      (str)  : "quarantine" | "unquarantine" | "update"
  channel     (str)  : (optional) Override default channel.
  thread_ts   (str)  : (optional) Post as a thread reply.

Config keys:
  bot_token    — Slack Bot OAuth token (xoxb-...).
  channel      — Default channel.
  oncall_user  — Slack user ID to DM on critical events.
"""
from __future__ import annotations

import os
from typing import Any

try:
    import httpx
    _HTTPX = True
except ModuleNotFoundError:
    _HTTPX = False

_SEVERITY_EMOJIS = {
    "info": ":information_source:",
    "low": ":large_yellow_circle:",
    "medium": ":large_orange_circle:",
    "high": ":red_circle:",
    "critical": ":rotating_light:",
}
_ACTION_EMOJIS = {
    "quarantine": ":lock:",
    "unquarantine": ":unlock:",
    "update": ":notepad_spiral:",
}


def _build_blocks(payload: dict) -> list[dict]:
    host = payload.get("host", "unknown")
    user = payload.get("user", "—")
    case_id = payload.get("case_id", "—")
    reason = payload.get("reason", "No reason provided.")
    severity = payload.get("severity", "medium").lower()
    action = payload.get("action", "quarantine").lower()

    sev_emoji = _SEVERITY_EMOJIS.get(severity, ":large_yellow_circle:")
    act_emoji = _ACTION_EMOJIS.get(action, ":notepad_spiral:")
    title = f"{act_emoji} Host {action.title()}: `{host}`"

    return [
        {"type": "header", "text": {"type": "plain_text", "text": f"AiSOC — {action.title()} Event", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": title}},
        {"type": "divider"},
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Host*\n`{host}`"},
                {"type": "mrkdwn", "text": f"*User*\n{user}"},
                {"type": "mrkdwn", "text": f"*Severity*\n{sev_emoji} {severity.upper()}"},
                {"type": "mrkdwn", "text": f"*Case*\n{case_id}"},
            ],
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Reason*\n{reason}"}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": "Powered by *AiSOC Autonomous SOC v4.0*"}]},
    ]


class Plugin:
    """Slack Quarantine Notifier plugin."""

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _HTTPX:
            return {"error": "httpx not installed; run `pip install httpx`"}

        cfg = context.get("config", {})
        token = cfg.get("bot_token") or os.getenv("SLACK_BOT_TOKEN", "")
        default_channel = cfg.get("channel") or os.getenv("SLACK_CHANNEL", "#soc-alerts")
        oncall_user = cfg.get("oncall_user") or os.getenv("SLACK_ONCALL_USER", "")

        if not token:
            return {"error": "Slack bot_token is required"}

        channel = payload.get("channel") or default_channel
        thread_ts = payload.get("thread_ts")
        blocks = _build_blocks(payload)

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {"channel": channel, "blocks": blocks}
        if thread_ts:
            body["thread_ts"] = thread_ts

        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post("https://slack.com/api/chat.postMessage", headers=headers, json=body)
            r.raise_for_status()
            data = r.json()

        if not data.get("ok"):
            return {"error": data.get("error", "Unknown Slack error"), "raw": data}

        result: dict[str, Any] = {
            "channel": data.get("channel"),
            "ts": data.get("ts"),
            "ok": True,
        }

        # DM the on-call analyst on critical events
        if oncall_user and payload.get("severity", "").lower() == "critical":
            dm_body = {
                "channel": oncall_user,
                "text": f":rotating_light: *CRITICAL* — Host quarantined: `{payload.get('host')}` — Case `{payload.get('case_id')}`",
            }
            dr = await (httpx.AsyncClient(timeout=10)).__aenter__()
            try:
                dmr = await dr.post("https://slack.com/api/chat.postMessage", headers=headers, json=dm_body)
                result["oncall_dm"] = dmr.json().get("ok", False)
            finally:
                await dr.__aexit__(None, None, None)

        return result
