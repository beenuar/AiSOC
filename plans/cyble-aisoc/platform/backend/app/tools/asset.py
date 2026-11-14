"""Asset / CMDB tools (todo ``t2i-tool``).

Exposes the Asset CMDB intelligence layer (``app.cmdb``) as registered
agent tools. Two surfaces:

* ``asset.get_context`` (READ) — the rich asset profile every agent
  reads before reasoning about scope, criticality, blast radius, or
  compliance. This is the *primary* tool — Triager, Investigator,
  Responder, Reporter, and Attack-Path all call it.
* ``asset.upsert`` (WRITE_REVERSIBLE) — connector-friendly write path
  for ingesting CMDB rows. Idempotent on
  ``(tenant_id, asset_type, key)``. Reversible in the sense that it
  never deletes — re-running with the prior payload restores the
  previous shape (modulo monotonic ``last_seen``).
* ``asset.list`` (READ) — paginated CMDB browse, used by the UI and
  by sub-agents that need to enumerate, e.g. "all crown jewels in PCI
  scope".

Tenancy
-------
Every handler is tagged with ``needs:tenant``. The agent base injects
``params["tenant_id"]`` from its own bound tenant before dispatch — the
LLM never sees ``tenant_id`` in the JSON schema and cannot spoof it.
"""
from __future__ import annotations

from typing import Any

from app.cmdb import (
    get_asset_context,
    list_assets,
    upsert_asset,
)
from app.tools.registry import RiskClass, tool


_NEEDS_TENANT = "needs:tenant"


# ──────────────────────────────────────────────────────────────────────
# Reusable JSON-schema fragments
# ──────────────────────────────────────────────────────────────────────

_STRING_ARRAY = {"type": "array", "items": {"type": "string"}}

_ASSET_OBJECT_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": ["integer", "null"]},
        "tenant_id": {"type": "string"},
        "asset_type": {"type": "string"},
        "key": {"type": "string"},
        "name": {"type": "string"},
        "aliases": _STRING_ARRAY,
        "criticality": {"type": "string"},
        "environment": {"type": "string"},
        "owner": {"type": "string"},
        "business_unit": {"type": "string"},
        "location": {"type": "string"},
        "cost_center": {"type": "string"},
        "compliance_scopes": _STRING_ARRAY,
        "data_classifications": _STRING_ARRAY,
        "ip_addresses": _STRING_ARRAY,
        "mac_addresses": _STRING_ARRAY,
        "os": {"type": "string"},
        "os_version": {"type": "string"},
        "cloud_provider": {"type": "string"},
        "cloud_account_id": {"type": "string"},
        "region": {"type": "string"},
        "sources": _STRING_ARRAY,
        "tags": _STRING_ARRAY,
        "notes": {"type": "string"},
        "first_seen": {"type": ["string", "null"]},
        "last_seen": {"type": ["string", "null"]},
        "decommissioned_at": {"type": ["string", "null"]},
        "attributes": {"type": "object", "additionalProperties": True},
    },
    "required": ["asset_type", "key", "criticality", "environment"],
    "additionalProperties": True,
}


# ──────────────────────────────────────────────────────────────────────
# asset.get_context — the agent's primary CMDB read
# ──────────────────────────────────────────────────────────────────────


@tool(
    name="asset.get_context",
    integration="cmdb",
    risk=RiskClass.READ,
    description=(
        "Return the rich CMDB profile for an asset: criticality, owner, "
        "environment, compliance scope, IPs, recent cases that touched "
        "it, graph neighbours, last-activity hints, and a small "
        "explainable risk profile. Resolves fuzzy identifiers (short "
        "hostname → FQDN, alias, IP) automatically. Returns "
        "{found: false} when the asset is unknown — that itself is "
        "actionable signal (probably needs onboarding)."
    ),
    params={
        "type": "object",
        "properties": {
            "identifier": {
                "type": "string",
                "description": (
                    "Hostname, FQDN, user principal, alias, or IP. Whatever "
                    "the alert mentioned — fuzzy matching handles the rest."
                ),
            },
            "asset_type": {
                "type": "string",
                "enum": [
                    "host",
                    "user",
                    "cloud_resource",
                    "saas_app",
                    "network_device",
                    "service",
                    "other",
                ],
                "description": "Optional hint to disambiguate identifier.",
            },
            "recent_case_limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 25,
            },
            "graph_depth": {
                "type": "integer",
                "minimum": 1,
                "maximum": 3,
            },
            "graph_limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 200,
            },
        },
        "required": ["identifier"],
    },
    result={
        "type": "object",
        "properties": {
            "found": {"type": "boolean"},
            "identifier": {"type": "string"},
            "asset": _ASSET_OBJECT_SCHEMA,
            "recent_cases": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer"},
                        "title": {"type": "string"},
                        "status": {"type": "string"},
                        "severity": {"type": "string"},
                        "verdict": {"type": "string"},
                        "confidence": {"type": "number"},
                        "created_at": {"type": "string"},
                        "closed_at": {"type": ["string", "null"]},
                    },
                    "additionalProperties": True,
                },
            },
            "graph_neighbors": {
                "type": "array",
                "items": {"type": "object", "additionalProperties": True},
            },
            "last_activity": {
                "type": "object",
                "properties": {
                    "last_seen": {"type": ["string", "null"]},
                    "last_case_at": {"type": ["string", "null"]},
                    "open_cases": {"type": "integer"},
                },
                "additionalProperties": True,
            },
            "compliance": {
                "type": "object",
                "properties": {
                    "scopes": _STRING_ARRAY,
                    "data_classifications": _STRING_ARRAY,
                    "in_regulated_scope": {"type": "boolean"},
                },
                "additionalProperties": True,
            },
            "risk_profile": {
                "type": "object",
                "properties": {
                    "score": {"type": "number"},
                    "criticality_weight": {"type": "number"},
                    "environment_weight": {"type": "number"},
                    "open_case_pressure": {"type": "number"},
                    "compliance_bump": {"type": "number"},
                    "requires_hitl_for_destructive": {"type": "boolean"},
                },
                "additionalProperties": True,
            },
        },
        "required": ["found", "identifier"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "cmdb"],
    cyble_native=True,
)
async def asset_get_context(
    *,
    tenant_id: str,
    identifier: str,
    asset_type: str | None = None,
    recent_case_limit: int = 5,
    graph_depth: int = 1,
    graph_limit: int = 25,
) -> dict[str, Any]:
    ctx = get_asset_context(
        tenant_id=tenant_id,
        identifier=identifier,
        asset_type=asset_type,
        recent_case_limit=recent_case_limit,
        graph_depth=graph_depth,
        graph_limit=graph_limit,
    )
    if ctx is None:
        # Unknown-asset is itself signal; agents should still proceed.
        return {"found": False, "identifier": identifier}
    payload = ctx.to_dict()
    payload["found"] = True
    payload["identifier"] = identifier
    return payload


# ──────────────────────────────────────────────────────────────────────
# asset.upsert — connector-side CMDB writes
# ──────────────────────────────────────────────────────────────────────


@tool(
    name="asset.upsert",
    integration="cmdb",
    # Reversible because (a) it never deletes and (b) re-running the
    # previous payload restores the prior shape (last_seen is monotonic
    # and intentionally so — telling us "this thing existed at time T"
    # is not undone). We deliberately do *not* pair a reverse tool: the
    # forward call is its own undo.
    risk=RiskClass.WRITE_REVERSIBLE,
    forward_only_reason=(
        "idempotent: re-applying the prior payload restores prior state; "
        "last_seen is intentionally monotonic"
    ),
    description=(
        "Insert or update a CMDB asset record. Idempotent on "
        "(tenant_id, asset_type, key). List-shaped fields (aliases, "
        "ip_addresses, compliance_scopes, ...) are unioned; scalar "
        "fields overwrite only when explicitly supplied. Mirrors into "
        "the threat graph so blast-radius and attack-path queries see "
        "the new business context immediately."
    ),
    params={
        "type": "object",
        "properties": {
            "asset_type": {
                "type": "string",
                "enum": [
                    "host",
                    "user",
                    "cloud_resource",
                    "saas_app",
                    "network_device",
                    "service",
                    "other",
                ],
            },
            "key": {"type": "string"},
            "name": {"type": "string"},
            "aliases": _STRING_ARRAY,
            "criticality": {
                "type": "string",
                "enum": ["crown_jewel", "high", "medium", "low", "unknown"],
            },
            "environment": {
                "type": "string",
                "enum": ["prod", "staging", "dev", "sandbox", "dr", "unknown"],
            },
            "owner": {"type": "string"},
            "business_unit": {"type": "string"},
            "location": {"type": "string"},
            "cost_center": {"type": "string"},
            "compliance_scopes": _STRING_ARRAY,
            "data_classifications": _STRING_ARRAY,
            "ip_addresses": _STRING_ARRAY,
            "mac_addresses": _STRING_ARRAY,
            "os": {"type": "string"},
            "os_version": {"type": "string"},
            "cloud_provider": {"type": "string"},
            "cloud_account_id": {"type": "string"},
            "region": {"type": "string"},
            "sources": _STRING_ARRAY,
            "tags": _STRING_ARRAY,
            "notes": {"type": "string"},
            "attributes": {"type": "object", "additionalProperties": True},
        },
        "required": ["asset_type", "key"],
    },
    result={
        "type": "object",
        "properties": {
            "asset_id": {"type": "integer"},
            "tenant_id": {"type": "string"},
            "asset_type": {"type": "string"},
            "key": {"type": "string"},
            "name": {"type": "string"},
            "criticality": {"type": "string"},
            "environment": {"type": "string"},
            "matched_on": {"type": "string"},
        },
        "required": ["asset_id", "asset_type", "key"],
        "additionalProperties": True,
    },
    tags=[_NEEDS_TENANT, "cmdb"],
    cyble_native=True,
)
async def asset_upsert(
    *,
    tenant_id: str,
    asset_type: str,
    key: str,
    name: str | None = None,
    aliases: list[str] | None = None,
    criticality: str | None = None,
    environment: str | None = None,
    owner: str | None = None,
    business_unit: str | None = None,
    location: str | None = None,
    cost_center: str | None = None,
    compliance_scopes: list[str] | None = None,
    data_classifications: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    mac_addresses: list[str] | None = None,
    os: str | None = None,
    os_version: str | None = None,
    cloud_provider: str | None = None,
    cloud_account_id: str | None = None,
    region: str | None = None,
    sources: list[str] | None = None,
    tags: list[str] | None = None,
    notes: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ref = upsert_asset(
        tenant_id=tenant_id,
        asset_type=asset_type,
        key=key,
        name=name,
        aliases=aliases,
        criticality=criticality,
        environment=environment,
        owner=owner,
        business_unit=business_unit,
        location=location,
        cost_center=cost_center,
        compliance_scopes=compliance_scopes,
        data_classifications=data_classifications,
        ip_addresses=ip_addresses,
        mac_addresses=mac_addresses,
        os=os,
        os_version=os_version,
        cloud_provider=cloud_provider,
        cloud_account_id=cloud_account_id,
        region=region,
        sources=sources,
        tags=tags,
        notes=notes,
        attributes=attributes,
    )
    return {
        "asset_id": ref.asset_id,
        "tenant_id": ref.tenant_id,
        "asset_type": ref.asset_type.value,
        "key": ref.key,
        "name": ref.name,
        "criticality": ref.criticality.value,
        "environment": ref.environment.value,
        "matched_on": ref.matched_on,
    }


# ──────────────────────────────────────────────────────────────────────
# asset.list — paginated browse
# ──────────────────────────────────────────────────────────────────────


@tool(
    name="asset.list",
    integration="cmdb",
    risk=RiskClass.READ,
    description=(
        "Paginated CMDB browse, with light filtering by asset_type, "
        "criticality, environment, and a free-text query against key/"
        "name/owner. Used by the UI and by sub-agents that need to "
        "enumerate, e.g. 'every crown jewel in PCI scope'."
    ),
    params={
        "type": "object",
        "properties": {
            "asset_type": {
                "type": "string",
                "enum": [
                    "host",
                    "user",
                    "cloud_resource",
                    "saas_app",
                    "network_device",
                    "service",
                    "other",
                ],
            },
            "criticality": {
                "type": "string",
                "enum": ["crown_jewel", "high", "medium", "low", "unknown"],
            },
            "environment": {
                "type": "string",
                "enum": ["prod", "staging", "dev", "sandbox", "dr", "unknown"],
            },
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 500},
            "offset": {"type": "integer", "minimum": 0},
        },
    },
    result={
        "type": "object",
        "properties": {
            "assets": {"type": "array", "items": _ASSET_OBJECT_SCHEMA},
            "count": {"type": "integer"},
        },
        "required": ["assets", "count"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "cmdb"],
)
async def asset_list(
    *,
    tenant_id: str,
    asset_type: str | None = None,
    criticality: str | None = None,
    environment: str | None = None,
    query: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict[str, Any]:
    rows = list_assets(
        tenant_id=tenant_id,
        asset_type=asset_type,
        criticality=criticality,
        environment=environment,
        query=query,
        limit=limit,
        offset=offset,
    )
    return {"assets": rows, "count": len(rows)}
