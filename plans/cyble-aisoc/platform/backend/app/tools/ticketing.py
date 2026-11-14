"""Ticketing tools: Jira, ServiceNow.

Forward and paired reverse actions for case-tracking tickets.

The reverse model for ticketing is "close + comment", not "delete": real
Jira/ServiceNow tenants almost universally forbid hard-deleting issues
(audit/compliance), so the rollback of ``ticket.create`` is
``ticket.close`` with a system rationale that points back to the
original forward ToolCall.
"""
from __future__ import annotations

from typing import Any

from app.tools.registry import RiskClass, tool


def _reverse_ticket_create(
    params: dict[str, Any], result: dict[str, Any]
) -> dict[str, Any]:
    """Build reverse params for ``ticket.create``.

    Picks the ``ticket_id`` from the forward call's result and constructs
    a close-with-rationale request. We deliberately surface a stable
    ``rationale`` string so the audit log of the downstream ticketing
    system makes the link back to the original create obvious without
    needing to cross-reference our ``rollback_of_id`` column.
    """
    ticket_id = result.get("ticket_id")
    if not ticket_id:
        # Without a ticket_id we have nothing actionable; the rollback
        # service treats a raised exception as "reverse params could not
        # be materialized" and renders the action ineligible.
        raise ValueError(
            "ticket.create result missing ticket_id; cannot build reverse"
        )
    return {
        "ticket_id": ticket_id,
        "rationale": "rolled back by aisoc",
    }


@tool(
    name="ticket.create",
    integration="jira",
    risk=RiskClass.WRITE_REVERSIBLE,
    description="Create a tracking ticket for a security case.",
    params={
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "description": {"type": "string"},
            "priority": {"enum": ["P0", "P1", "P2", "P3"]},
        },
        "required": ["title"],
    },
    result={
        "type": "object",
        "properties": {
            "ticket_id": {"type": "string"},
            "title": {"type": "string"},
            "priority": {"type": "string"},
            "url": {"type": "string"},
        },
        "required": ["ticket_id", "title"],
        "additionalProperties": False,
    },
    reverse_tool="ticket.close",
    reverse_params_builder=_reverse_ticket_create,
)
async def ticket_create(title: str, description: str = "", priority: str = "P2") -> dict[str, Any]:
    return {
        "ticket_id": "SEC-44211",
        "title": title,
        "priority": priority,
        "url": "https://cyble.atlassian.net/browse/SEC-44211",
    }


@tool(
    name="ticket.close",
    integration="jira",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: this tool exists as the
    # reverse pair of ticket.create. We deliberately do NOT register its
    # own reverse_tool (ticket.reopen) because re-opening a previously
    # closed audit/compliance ticket should be a fresh analyst decision,
    # not an automated rollback of a rollback. Symmetric HITL gating
    # with ticket.create; rollback service correctly refuses to auto-undo.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "this IS the reverse of ticket.create; re-opening a closed "
        "audit/compliance ticket must be a fresh analyst decision with its "
        "own rationale, not an automated rollback chain"
    ),
    description=(
        "Close a previously-created ticket with a rationale. "
        "Reverse pair of ticket.create."
    ),
    params={
        "type": "object",
        "properties": {
            "ticket_id": {"type": "string"},
            "rationale": {"type": "string"},
        },
        "required": ["ticket_id"],
    },
    result={
        "type": "object",
        "properties": {
            "ticket_id": {"type": "string"},
            "closed": {"type": "boolean"},
            "rationale": {"type": "string"},
        },
        "required": ["ticket_id", "closed"],
        "additionalProperties": False,
    },
    tags=["rollback"],
)
async def ticket_close(
    ticket_id: str, rationale: str = "rolled back by aisoc"
) -> dict[str, Any]:
    return {
        "ticket_id": ticket_id,
        "closed": True,
        "rationale": rationale,
    }
