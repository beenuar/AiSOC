"""Live endpoint forensics tools (Theme 2j).

Thin wrappers over the connector SDK's :class:`BaseForensicsConnector`
(Velociraptor / KAPE / GRR / Wazuh FIM). Each tool resolves the
per-tenant forensics connector via :func:`app.connectors.get_connector`
and delegates to the matching protocol method.

Distinct from ``edr.*`` tools:

  * EDR ships always-on telemetry; forensics pulls artifacts *now* from
    the live OS (registry, MFT, prefetch, in-memory process maps).
  * EDR exposes containment (isolate / kill); forensics exposes deep
    artifact collection plus a destructive ``kill_process`` of last
    resort for environments where EDR isn't deployed.

Tenancy
-------
Every handler is tagged ``needs:tenant``. The agent base injects
``params["tenant_id"]`` from its bound tenant before dispatch — the
LLM never sees ``tenant_id`` in the JSON schema and cannot spoof it.

Risk classes
------------
``collect_artifact`` / ``run_hunt`` / ``fetch_file`` are ``READ`` — they
return data, never mutate the endpoint. ``kill_process`` is
``DESTRUCTIVE`` (a terminated PID cannot be resurrected) and is
explicitly *not* paired with a reverse action.
"""
from __future__ import annotations

from typing import Any

from app.connectors import ConnectorKind, get_connector
from app.tools.registry import RiskClass, tool


_NEEDS_TENANT = "needs:tenant"


@tool(
    name="forensics.collect_artifact",
    integration="velociraptor",
    risk=RiskClass.READ,
    description=(
        "Run a single named forensics artifact (e.g. Windows.System.Pslist, "
        "Linux.Sys.BashShell) against one host and return its rows. "
        "Pull, on-demand, often seconds-to-minutes."
    ),
    params={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "artifact": {"type": "string"},
            "parameters": {
                "type": "object",
                "additionalProperties": True,
            },
            "timeout_s": {"type": "integer", "minimum": 1, "maximum": 3600},
        },
        "required": ["host", "artifact"],
    },
    result={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "artifact": {"type": "string"},
            "flow_id": {"type": "string"},
            "started_at": {"type": "string"},
            "completed_at": {"type": "string"},
            "status": {
                "type": "string",
                "enum": ["completed", "failed", "timeout"],
            },
            # Artifact rows vary widely by artifact (process records,
            # registry keys, file MFT entries, …) — only constrain the
            # envelope, not row shape.
            "rows": {
                "type": "array",
                "items": {"type": "object", "additionalProperties": True},
            },
            "row_count": {"type": "integer"},
            "total_uploaded_bytes": {"type": "integer"},
            "error": {"type": ["string", "null"]},
        },
        "required": ["host", "artifact", "status", "rows"],
        "additionalProperties": True,
    },
    tags=[_NEEDS_TENANT, "forensics"],
)
async def forensics_collect_artifact(
    *,
    tenant_id: str,
    host: str,
    artifact: str,
    parameters: dict[str, Any] | None = None,
    timeout_s: int = 300,
) -> dict[str, Any]:
    conn = await get_connector(tenant_id, ConnectorKind.FORENSICS)
    return await conn.collect_artifact(
        host=host,
        artifact=artifact,
        parameters=parameters,
        timeout_s=timeout_s,
    )


@tool(
    name="forensics.run_hunt",
    integration="velociraptor",
    risk=RiskClass.READ,
    description=(
        "Fan a forensics artifact out across many endpoints at once, "
        "bounded by a label selector or explicit host list. Returns the "
        "scheduled hunt's identifier plus a results summary."
    ),
    params={
        "type": "object",
        "properties": {
            "artifact": {"type": "string"},
            "label_selector": {"type": "string"},
            "host_ids": {
                "type": "array",
                "items": {"type": "string"},
            },
            "parameters": {
                "type": "object",
                "additionalProperties": True,
            },
            "timeout_s": {"type": "integer", "minimum": 1, "maximum": 7200},
        },
        # Exactly-one-of is enforced at the protocol layer; the JSON
        # Schema here mirrors the protocol's "artifact required, scope
        # caller-specified" contract.
        "required": ["artifact"],
    },
    result={
        "type": "object",
        "properties": {
            "hunt_id": {"type": "string"},
            "artifact": {"type": "string"},
            "started_at": {"type": "string"},
            "scheduled_clients": {"type": "integer"},
            "completed_clients": {"type": "integer"},
            "error_clients": {"type": "integer"},
            "status": {
                "type": "string",
                "enum": ["running", "completed", "cancelled"],
            },
            "results_summary": {
                "type": "object",
                "properties": {
                    "row_count": {"type": "integer"},
                    "unique_hosts": {"type": "integer"},
                },
                "additionalProperties": True,
            },
        },
        "required": ["hunt_id", "artifact", "status"],
        "additionalProperties": True,
    },
    tags=[_NEEDS_TENANT, "forensics"],
)
async def forensics_run_hunt(
    *,
    tenant_id: str,
    artifact: str,
    label_selector: str | None = None,
    host_ids: list[str] | None = None,
    parameters: dict[str, Any] | None = None,
    timeout_s: int = 600,
) -> dict[str, Any]:
    conn = await get_connector(tenant_id, ConnectorKind.FORENSICS)
    return await conn.run_hunt(
        artifact=artifact,
        label_selector=label_selector,
        host_ids=host_ids,
        parameters=parameters,
        timeout_s=timeout_s,
    )


@tool(
    name="forensics.fetch_file",
    integration="velociraptor",
    risk=RiskClass.READ,
    description=(
        "Pull a specific file off the endpoint for offline analysis. "
        "Returns a SHA-256 chain-of-custody hash and a vault URL the "
        "agent can hand to a malware sandbox."
    ),
    params={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "path": {"type": "string"},
            "max_size_mb": {"type": "integer", "minimum": 1, "maximum": 4096},
        },
        "required": ["host", "path"],
    },
    result={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "path": {"type": "string"},
            "size_bytes": {"type": "integer"},
            "sha256": {"type": "string"},
            "vault_url": {"type": "string"},
            "fetched_at": {"type": "string"},
            "truncated": {"type": "boolean"},
        },
        "required": ["host", "path", "sha256"],
        "additionalProperties": True,
    },
    tags=[_NEEDS_TENANT, "forensics"],
)
async def forensics_fetch_file(
    *,
    tenant_id: str,
    host: str,
    path: str,
    max_size_mb: int = 100,
) -> dict[str, Any]:
    conn = await get_connector(tenant_id, ConnectorKind.FORENSICS)
    return await conn.fetch_file(host=host, path=path, max_size_mb=max_size_mb)


@tool(
    name="forensics.kill_process",
    integration="velociraptor",
    # DESTRUCTIVE, not WRITE_REVERSIBLE: a terminated process cannot be
    # un-killed — in-memory state is gone, file handles closed, sockets
    # dropped. Overlaps deliberately with edr.kill_process: the forensics
    # path becomes the containment path of last resort in environments
    # where EDR isn't deployed but Velociraptor is. Forward-only; HITL
    # must gate and accept consequences.
    risk=RiskClass.DESTRUCTIVE,
    description=(
        "Force-terminate a process by PID via the forensics agent "
        "(Velociraptor/GRR). Containment of last resort when EDR is "
        "unavailable. Destructive — no rollback."
    ),
    params={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "pid": {"type": "integer", "minimum": 1},
            "reason": {"type": "string"},
        },
        "required": ["host", "pid"],
    },
    result={
        "type": "object",
        "properties": {
            "host": {"type": "string"},
            "pid": {"type": "integer"},
            "terminated": {"type": "boolean"},
            "ticket": {"type": "string"},
            "error": {"type": ["string", "null"]},
        },
        "required": ["host", "pid", "terminated"],
        "additionalProperties": True,
    },
    tags=[_NEEDS_TENANT, "forensics", "containment"],
)
async def forensics_kill_process(
    *,
    tenant_id: str,
    host: str,
    pid: int,
    reason: str | None = None,
) -> dict[str, Any]:
    conn = await get_connector(tenant_id, ConnectorKind.FORENSICS)
    return await conn.terminate_process(host=host, pid=pid, reason=reason)
