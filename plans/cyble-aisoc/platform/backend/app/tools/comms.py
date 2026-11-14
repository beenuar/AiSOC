"""Comms tools: Slack, Teams notification.

Forward ``slack.notify`` posts a message; the reverse pair
``slack.delete_message`` removes it using the ``channel`` + ``ts``
(message timestamp) coordinates Slack's ``chat.delete`` API requires.

We expose this as a real reverse so an analyst who triggered an
incorrect notification (wrong channel, bad rationale, leaked sensitive
host name) can immediately retract it via the standard rollback API
without a separate "delete Slack message" tool path.
"""
from __future__ import annotations

from typing import Any

from app.tools.registry import RiskClass, tool


def _reverse_slack_notify(
    params: dict[str, Any], result: dict[str, Any]
) -> dict[str, Any]:
    """Build reverse params for ``slack.notify``.

    ``chat.delete`` requires both the channel id and the message ts.
    The forward result already contains both; we surface them as the
    reverse params so a rollback round-trips with no additional lookup.
    """
    channel = result.get("channel") or params.get("channel")
    ts = result.get("ts")
    if not channel or not ts:
        raise ValueError(
            "slack.notify result missing channel/ts; cannot build reverse"
        )
    return {"channel": channel, "ts": ts}


@tool(
    name="slack.notify",
    integration="slack",
    risk=RiskClass.WRITE_REVERSIBLE,
    description="Post a notification to a Slack channel about a case.",
    params={
        "type": "object",
        "properties": {
            "channel": {"type": "string"},
            "message": {"type": "string"},
        },
        "required": ["channel", "message"],
    },
    result={
        "type": "object",
        "properties": {
            "channel": {"type": "string"},
            "ts": {"type": "string"},
            "delivered": {"type": "boolean"},
        },
        "required": ["channel", "delivered"],
        "additionalProperties": False,
    },
    reverse_tool="slack.delete_message",
    reverse_params_builder=_reverse_slack_notify,
)
async def slack_notify(channel: str, message: str) -> dict[str, Any]:
    return {"channel": channel, "ts": "1745890123.001200", "delivered": True}


@tool(
    name="slack.delete_message",
    integration="slack",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: this tool exists as the
    # reverse pair of slack.notify. A deleted Slack message cannot be
    # un-deleted via Slack's API — Slack does not let us re-post with the
    # original ts. Re-notifying after a delete should be a fresh decision,
    # not an automated rollback of the rollback. Symmetric HITL gating
    # with slack.notify; rollback service correctly refuses to auto-undo.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "this IS the reverse of slack.notify; Slack's API cannot un-delete "
        "a message or re-post with the original ts. Re-notify must be a "
        "fresh slack.notify call, not a rollback chain"
    ),
    description=(
        "Delete a previously-posted Slack message via channel+ts. "
        "Reverse pair of slack.notify."
    ),
    params={
        "type": "object",
        "properties": {
            "channel": {"type": "string"},
            "ts": {"type": "string"},
        },
        "required": ["channel", "ts"],
    },
    result={
        "type": "object",
        "properties": {
            "channel": {"type": "string"},
            "ts": {"type": "string"},
            "deleted": {"type": "boolean"},
        },
        "required": ["channel", "ts", "deleted"],
        "additionalProperties": False,
    },
    tags=["rollback"],
)
async def slack_delete_message(channel: str, ts: str) -> dict[str, Any]:
    return {"channel": channel, "ts": ts, "deleted": True}
