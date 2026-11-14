"""EDR tools: process tree, host isolation, file quarantine, kill process.

Thin wrappers over the connector SDK. Each tool resolves the per-tenant
EDR connector (CrowdStrike / SentinelOne / mock fallback) via
:func:`app.connectors.get_connector` and delegates to the matching
protocol method on :class:`app.connectors.sdk.protocols.BaseEdrConnector`.

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
# Pure functions: (original_params, original_result) -> reverse_params.
# They must NOT touch the network or the DB — the rollback service runs
# them while constructing the paired ToolCall row, before any vendor call.
# `tenant_id` is intentionally NOT propagated here: the agent base injects
# it on dispatch (the LLM never sees it) so adding it would double-inject.
def _reverse_isolate_host(
    params: dict[str, Any], _result: dict[str, Any]
) -> dict[str, Any]:
    return {"host": params["host"]}


def _reverse_quarantine_file(
    params: dict[str, Any], _result: dict[str, Any]
) -> dict[str, Any]:
    return {"sha256": params["sha256"]}


@tool(
    name="edr.get_process_tree",
    integration="sentinelone",
    risk=RiskClass.READ,
    description="Retrieve process ancestry and child processes for a host.",
    params={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "process_name": {"type": "string"},
        },
        "required": ["host"],
    },
    result={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            # `tree` items can recurse arbitrarily — we only constrain the
            # envelope and let nested process records carry whatever fields
            # the EDR vendor provides.
            "tree": {
                "type": "array",
                "items": {"type": "object", "additionalProperties": True},
            },
        },
        "required": ["host", "tree"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "edr"],
)
async def edr_get_process_tree(
    *, tenant_id: str, host: str, process_name: str | None = None
) -> dict[str, Any]:
    edr = await get_connector(tenant_id, ConnectorKind.EDR)
    return await edr.get_process_tree(host=host, process_name=process_name)


@tool(
    name="edr.isolate_host",
    integration="sentinelone",
    risk=RiskClass.WRITE_SIGNIFICANT,
    description="Network-isolate a host from the corporate network. Reversible via release.",
    params={
        "type": "object",
        "properties": {"host": {"type": "string"}, "reason": {"type": "string"}},
        "required": ["host", "reason"],
    },
    result={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "isolated": {"type": "boolean"},
            "reason": {"type": "string"},
            "ticket": {"type": "string"},
        },
        "required": ["host", "isolated"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment"],
    reverse_tool="edr.release_host",
    reverse_params_builder=_reverse_isolate_host,
)
async def edr_isolate_host(
    *, tenant_id: str, host: str, reason: str
) -> dict[str, Any]:
    edr = await get_connector(tenant_id, ConnectorKind.EDR)
    return await edr.isolate_host(host=host, reason=reason)


@tool(
    name="edr.release_host",
    integration="sentinelone",
    # Releasing a host back onto the network is itself a meaningful state
    # change — gate it as WRITE_SIGNIFICANT so HITL policies that approve
    # forward containment can also gate the rollback symmetrically.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "this IS the reverse of edr.isolate_host; re-isolating via rollback "
        "would re-trigger containment and loop. Re-isolation must be a fresh "
        "HITL decision"
    ),
    description=(
        "Restore network connectivity for a previously isolated host. "
        "Reverse pair of edr.isolate_host."
    ),
    params={
        "type": "object",
        "properties": {"host": {"type": "string"}},
        "required": ["host"],
    },
    result={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "isolated": {"type": "boolean"},
            "ticket": {"type": "string"},
        },
        "required": ["host", "isolated"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "rollback"],
)
async def edr_release_host(*, tenant_id: str, host: str) -> dict[str, Any]:
    edr = await get_connector(tenant_id, ConnectorKind.EDR)
    return await edr.release_host(host=host)


@tool(
    name="edr.quarantine_file",
    integration="sentinelone",
    risk=RiskClass.WRITE_REVERSIBLE,
    description="Quarantine a file by SHA256 hash across the fleet.",
    params={
        "type": "object",
        "properties": {"sha256": {"type": "string"}},
        "required": ["sha256"],
    },
    result={
        "type": "object",
        "properties": {
            "sha256": {"type": "string"},
            "quarantined_on_endpoints": {"type": "integer"},
            "ticket": {"type": "string"},
        },
        "required": ["sha256", "quarantined_on_endpoints"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "containment"],
    reverse_tool="edr.restore_file",
    reverse_params_builder=_reverse_quarantine_file,
)
async def edr_quarantine_file(*, tenant_id: str, sha256: str) -> dict[str, Any]:
    edr = await get_connector(tenant_id, ConnectorKind.EDR)
    return await edr.quarantine_file(sha256=sha256)


@tool(
    name="edr.restore_file",
    integration="sentinelone",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: this tool exists as the
    # reverse pair of edr.quarantine_file. Restoring a previously
    # quarantined binary across the fleet is itself a meaningful, audited
    # state change — symmetric HITL gating with quarantine — and we do
    # NOT register its own reverse_tool (a re-quarantine after restore
    # should originate as a fresh forward decision, not an automated
    # rollback of a rollback).
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "this IS the reverse of edr.quarantine_file; re-quarantining via "
        "rollback would loop. Re-quarantine must be a fresh HITL decision"
    ),
    description=(
        "Restore a previously quarantined file by SHA256 across the fleet. "
        "Reverse pair of edr.quarantine_file."
    ),
    params={
        "type": "object",
        "properties": {"sha256": {"type": "string"}},
        "required": ["sha256"],
    },
    result={
        "type": "object",
        "properties": {
            "sha256": {"type": "string"},
            "restored_on_endpoints": {"type": "integer"},
            "ticket": {"type": "string"},
        },
        "required": ["sha256", "restored_on_endpoints"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "rollback"],
)
async def edr_restore_file(*, tenant_id: str, sha256: str) -> dict[str, Any]:
    edr = await get_connector(tenant_id, ConnectorKind.EDR)
    return await edr.restore_file(sha256=sha256)


@tool(
    name="edr.kill_process",
    integration="sentinelone",
    # DESTRUCTIVE, not WRITE_REVERSIBLE: a terminated process cannot be
    # "un-killed" — in-memory state is gone, file handles closed, sockets
    # dropped. The rollback service ignores DESTRUCTIVE actions entirely;
    # HITL must gate this forward-only and accept the consequences.
    risk=RiskClass.DESTRUCTIVE,
    description="Force-terminate a running process by PID on a specific host.",
    params={
        "type": "object",
        "properties": {"host": {"type": "string"}, "pid": {"type": "integer"}},
        "required": ["host", "pid"],
    },
    result={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "pid": {"type": "integer"},
            "terminated": {"type": "boolean"},
        },
        "required": ["host", "pid", "terminated"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "edr"],
)
async def edr_kill_process(
    *, tenant_id: str, host: str, pid: int
) -> dict[str, Any]:
    edr = await get_connector(tenant_id, ConnectorKind.EDR)
    return await edr.kill_process(host=host, pid=pid)
