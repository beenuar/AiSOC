"""Email security: header analysis, message clawback, sender reputation.

Thin wrappers over the connector SDK. Each tool resolves the per-tenant
email connector (Proofpoint / Microsoft 365 / mock fallback) via
:func:`app.connectors.get_connector` and delegates to the matching
protocol method on :class:`app.connectors.sdk.protocols.BaseEmailConnector`.

Tenancy
-------
Every handler is tagged with ``needs:tenant``. The agent base injects
``params["tenant_id"]`` from its own bound tenant before dispatch — the
LLM never sees ``tenant_id`` in the JSON schema and cannot spoof it.
"""
from __future__ import annotations

from typing import Any

from app.connectors import ConnectorKind, get_connector
from app.tools.registry import RiskClass, tool


_NEEDS_TENANT = "needs:tenant"


# ── Reverse-params builders (t1-reverse-actions) ───────────────────────────
def _reverse_clawback_message(
    params: dict[str, Any], _result: dict[str, Any]
) -> dict[str, Any]:
    return {"message_id": params["message_id"]}


def _reverse_block_sender(
    params: dict[str, Any], _result: dict[str, Any]
) -> dict[str, Any]:
    return {"sender": params["sender"]}


@tool(
    name="email.analyze_message",
    integration="proofpoint",
    risk=RiskClass.READ,
    description="Analyze message headers, links, attachments. Returns auth results and suspicion score.",
    params={"type": "object", "properties": {"message_id": {"type": "string"}}, "required": ["message_id"]},
    result={
        "type": "object",
        "properties": {
            "message_id": {"type": "string"},
            "from": {"type": "string"},
            "auth": {
                "type": "object",
                "properties": {
                    "spf": {"type": "string"},
                    "dkim": {"type": "string"},
                    "dmarc": {"type": "string"},
                },
                "additionalProperties": True,
            },
            "links": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string"},
                        "risk": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            },
            "attachments": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "filename": {"type": "string"},
                        "sha256": {"type": "string"},
                        "macros": {"type": "boolean"},
                    },
                    "additionalProperties": True,
                },
            },
            "suspicion_score": {"type": "number"},
        },
        "required": ["message_id"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "email"],
)
async def email_analyze_message(
    *, tenant_id: str, message_id: str
) -> dict[str, Any]:
    email = await get_connector(tenant_id, ConnectorKind.EMAIL)
    return await email.analyze_message(message_id=message_id)


@tool(
    name="email.clawback_message",
    integration="proofpoint",
    risk=RiskClass.WRITE_REVERSIBLE,
    description="Recall/quarantine a delivered email from all recipient mailboxes.",
    params={"type": "object", "properties": {"message_id": {"type": "string"}}, "required": ["message_id"]},
    result={
        "type": "object",
        "properties": {
            "message_id": {"type": "string"},
            "recipients_affected": {"type": "integer"},
            "status": {"type": "string"},
        },
        "required": ["message_id", "status"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment"],
    reverse_tool="email.restore_message",
    reverse_params_builder=_reverse_clawback_message,
)
async def email_clawback_message(
    *, tenant_id: str, message_id: str
) -> dict[str, Any]:
    email = await get_connector(tenant_id, ConnectorKind.EMAIL)
    return await email.clawback_message(message_id=message_id)


@tool(
    name="email.restore_message",
    integration="proofpoint",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: this tool exists as the
    # reverse pair of email.clawback_message. Putting a previously
    # quarantined message back into recipient mailboxes is itself a
    # significant action — symmetric HITL with clawback — and we
    # deliberately do not register its own reverse_tool: a re-clawback
    # should be a new forward decision, not an automatic rollback chain.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "this IS the reverse of email.clawback_message; re-clawing-back via "
        "rollback would loop. Re-claw must be a fresh HITL decision via "
        "email.clawback_message"
    ),
    description=(
        "Re-deliver a previously clawed-back email to its original recipients. "
        "Reverse pair of email.clawback_message."
    ),
    params={
        "type": "object",
        "properties": {"message_id": {"type": "string"}},
        "required": ["message_id"],
    },
    result={
        "type": "object",
        "properties": {
            "message_id": {"type": "string"},
            "recipients_restored": {"type": "integer"},
            "status": {"type": "string"},
        },
        "required": ["message_id", "status"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "rollback"],
)
async def email_restore_message(
    *, tenant_id: str, message_id: str
) -> dict[str, Any]:
    email = await get_connector(tenant_id, ConnectorKind.EMAIL)
    return await email.restore_message(message_id=message_id)


@tool(
    name="email.block_sender",
    integration="proofpoint",
    risk=RiskClass.WRITE_REVERSIBLE,
    description="Add a sender domain to the block list at the email gateway.",
    params={"type": "object", "properties": {"sender": {"type": "string"}}, "required": ["sender"]},
    result={
        "type": "object",
        "properties": {
            "sender": {"type": "string"},
            "blocked": {"type": "boolean"},
        },
        "required": ["sender", "blocked"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "email"],
    reverse_tool="email.unblock_sender",
    reverse_params_builder=_reverse_block_sender,
)
async def email_block_sender(*, tenant_id: str, sender: str) -> dict[str, Any]:
    email = await get_connector(tenant_id, ConnectorKind.EMAIL)
    return await email.block_sender(sender=sender)


@tool(
    name="email.unblock_sender",
    integration="proofpoint",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: this tool exists as the
    # reverse pair of email.block_sender. Removing a sender from the
    # gateway blocklist is itself a meaningful state change (it allows
    # future mail through), symmetric HITL with the block. We do not
    # register its own reverse_tool: re-blocking should be a fresh
    # decision, not an automated rollback of the unblock.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "this IS the reverse of email.block_sender; re-blocking via "
        "rollback would loop. Re-block must be a fresh HITL decision via "
        "email.block_sender"
    ),
    description=(
        "Remove a sender domain from the email gateway block list. "
        "Reverse pair of email.block_sender."
    ),
    params={
        "type": "object",
        "properties": {"sender": {"type": "string"}},
        "required": ["sender"],
    },
    result={
        "type": "object",
        "properties": {
            "sender": {"type": "string"},
            "blocked": {"type": "boolean"},
        },
        "required": ["sender", "blocked"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "rollback"],
)
async def email_unblock_sender(*, tenant_id: str, sender: str) -> dict[str, Any]:
    email = await get_connector(tenant_id, ConnectorKind.EMAIL)
    return await email.unblock_sender(sender=sender)
