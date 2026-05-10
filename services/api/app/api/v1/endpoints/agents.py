"""Agent-facing endpoints — capability tools surface (Workstream 4).

This module is the *agent layer's* read-side over the connector platform.
It does **not** execute anything by itself. Its sole responsibility is to
answer: *"For this tenant, what verbs is the agent allowed to invoke,
against which connector instances, with which JSON-Schema-shaped inputs?"*

Why a separate endpoint rather than re-using ``GET /connectors``:

* Different audience. ``/connectors`` is operator-facing (wizard,
  health rollup, credential management). ``/agents/tools`` is the
  catalogue an LLM-driven agent reads when it picks a tool to call.
* Different shape. The agent doesn't care about ``auth_config`` keys
  or schema-drift fingerprints — it cares about *callable verbs*. So
  this endpoint pivots from instance → capability → tool descriptor.
* Different scope-narrowing rules. The agent never sees disabled
  instances and never sees capabilities outside ``allowed_capabilities``,
  even if the connector class declares more. ``/connectors`` returns
  the unfiltered truth.

Tenant scoping invariants:

* Every query filters on ``Connector.tenant_id == current_user.tenant_id``.
* Disabled instances (``is_enabled = False``) are dropped — there is no
  "what *would* I be able to do?" view; the agent sees only what it can
  *actually* invoke right now.
* Per-instance ``allowed_capabilities`` (managed via
  ``PUT /connectors/{id}/capabilities``) is intersected with the connector
  class's declared ``capabilities()`` server-side. A tampered request
  on the management endpoint can't widen reach because *that* endpoint
  validates against the declared set; here we just read the column.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.api.v1.endpoints.connectors import _fetch_catalog, _safe_log_val
from app.models.connector import Connector

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/agents", tags=["agents"])


# --------------------------------------------------------------- Pydantic schemas


class AgentToolDescriptor(BaseModel):
    """One callable verb on one connector instance, as the agent sees it.

    The descriptor is intentionally LLM-friendly:

    * ``name`` is unique per tenant (``{connector_id}.{capability}``) and
      stable across redeploys, so an agent's tool-choice memory still
      resolves after a redeployment.
    * ``description`` is human-readable and pulled from the connector
      class so updates ship with the connector code, not the agent.
    * ``input_schema`` follows JSON-Schema conventions so most agent
      frameworks (LangChain, LangGraph, MCP) can drop it in unchanged.
    """

    name: str = Field(
        description=(
            "Stable unique identifier for this tool, formatted as "
            "'<connector_instance_id>.<capability>'. The connector_instance_id "
            "rather than connector_type so multiple instances of the same "
            "connector — e.g. two CrowdStrike tenants — are addressable."
        ),
    )
    connector_id: str = Field(description="Connector instance UUID.")
    connector_type: str = Field(description="Catalog connector type, e.g. 'crowdstrike'.")
    connector_name: str = Field(
        description="Operator-chosen instance display name (e.g. 'CrowdStrike — prod').",
    )
    category: str = Field(description="Catalog category, e.g. 'edr', 'siem', 'iam'.")
    capability: str = Field(
        description=("The capability verb (one of the values from the Capability enum, e.g. 'pull_alerts', 'query_logs', 'isolate_host')."),
    )
    capability_group: str = Field(
        description=(
            "Coarse grouping derived from CAPABILITY_GROUPS in services/connectors. "
            "Lets an agent pre-filter by intent — e.g. only consider 'CONTAIN' "
            "verbs when deciding to quarantine a host."
        ),
    )
    description: str = Field(
        description="Human-readable summary of the verb, surfaced in tool prompts.",
    )
    input_schema: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}},
        description=(
            "JSON-Schema for the verb's arguments. Empty by default; concrete "
            "connectors will fill this in as the per-capability call surface "
            "stabilises in subsequent workstreams."
        ),
    )


class AgentToolsResponse(BaseModel):
    """Tenant-wide tool catalogue surfaced to the agent layer."""

    tools: list[AgentToolDescriptor]
    # Lightweight metadata so callers can short-circuit on emptiness
    # without iterating ``tools``. ``connector_count`` is the number of
    # *instances* contributing tools (i.e. enabled, non-empty effective
    # capability set), distinct from total instances on the tenant.
    tool_count: int
    connector_count: int


# ---------------------------------------------------------------------- helpers


# Coarse grouping mirrors CAPABILITY_GROUPS in
# ``services/connectors/app/connectors/base.py``. We duplicate it here
# (rather than import across services) so the API can serve agent
# descriptors even when the connectors microservice is briefly
# unavailable. The catalog endpoint already falls back to the bundled
# manifest in that case; this keeps that resilience consistent.
#
# Keep this in sync with the ``Capability`` enum and ``CAPABILITY_GROUPS``
# in ``services/connectors/app/connectors/base.py``. A capability that
# lands in the enum but not here will surface to the agent as group
# "unknown", which is observable but not fatal — it's a soft drift signal.
_CAPABILITY_GROUP_LOOKUP: dict[str, str] = {
    # READ — passive pulls of events / records the source already produced.
    "pull_alerts": "read",
    "pull_logs": "read",
    "pull_audit": "read",
    "pull_pcap": "read",
    "pull_file": "read",
    # QUERY — ad-hoc search across the source's index.
    "query_logs": "query",
    "query_processes": "query",
    # PIVOT — "given this entity, return everything you know about it".
    "pivot_user": "pivot",
    "pivot_host": "pivot",
    "pivot_ip": "pivot",
    "pivot_hash": "pivot",
    "pivot_domain": "pivot",
    # ENRICH — return contextual reputation / metadata for a single entity.
    "enrich_user": "enrich",
    "enrich_host": "enrich",
    "enrich_ioc": "enrich",
    "enrich_domain": "enrich",
    "enrich_vuln": "enrich",
    "enrich_asset": "enrich",
    # CONTAIN — kinetic actions on hosts / files / IOCs.
    "isolate_host": "contain",
    "unisolate_host": "contain",
    "kill_process": "contain",
    "quarantine_file": "contain",
    "block_hash": "contain",
    "block_domain": "contain",
    # REMEDIATE — kinetic actions on identities / credentials.
    "block_user_signin": "remediate",
    "disable_user": "remediate",
    "revoke_session": "remediate",
    "reset_password": "remediate",
    "revoke_token": "remediate",
    # TICKET — bidirectional ITSM (Jira / ServiceNow / etc.).
    "push_case": "ticket",
    "push_status": "ticket",
    # AUDIT — read-only configuration / posture queries.
    "read_audit_trail": "audit",
}


def _capability_group_of(capability: str) -> str:
    """Return the coarse group for a capability string, or 'unknown'.

    Unknown capabilities are still surfaced (we don't filter them out)
    because dropping a verb the connector class declared would silently
    hide functionality from the agent. 'unknown' lets the agent layer
    log a warning and decide whether to use it anyway. Group names are
    lowercase to mirror ``CAPABILITY_GROUPS`` in the connectors service.
    """
    return _CAPABILITY_GROUP_LOOKUP.get(capability, "unknown")


def _capability_descriptions(catalog_entry: dict[str, Any]) -> dict[str, str]:
    """Pull capability descriptions from a catalog entry, with safe defaults.

    The connectors microservice may surface capability metadata as
    ``[{"value": "pull_alerts", "description": "..."}]`` or as a flat
    list of strings. We accept both so we don't have to coordinate a
    breaking change across services — older catalog payloads continue
    to work, just without rich descriptions.
    """
    raw = catalog_entry.get("capabilities") or []
    out: dict[str, str] = {}
    for item in raw:
        if isinstance(item, dict):
            name = item.get("value") or item.get("name")
            if isinstance(name, str):
                desc = item.get("description")
                out[name] = desc if isinstance(desc, str) and desc else _default_description(name)
        elif isinstance(item, str):
            out[item] = _default_description(item)
    return out


def _default_description(capability: str) -> str:
    """Generate a passable description when the catalog doesn't supply one.

    Replaces underscores with spaces and adds a verb-style framing.
    Cheap, deterministic, and good enough for tool prompts until each
    connector ships hand-written copy.
    """
    pretty = capability.replace("_", " ")
    return f"Invoke '{pretty}' on this connector instance."


# -------------------------------------------------------------------- endpoints


@router.get("/tools", response_model=AgentToolsResponse)
async def list_agent_tools(
    current_user: Annotated[AuthUser, Depends(require_permission("connectors:read"))],
    db: DBSession,
) -> AgentToolsResponse:
    """Return the agent's allowed tool surface for this tenant.

    The pivot is **instance × effective capability**:

    1. Pull every enabled connector for the tenant.
    2. For each instance, look up the connector class's declared
       capabilities from the live catalog.
    3. Intersect with the per-instance ``allowed_capabilities`` column
       (``NULL`` = no downscope; ``[]`` = explicit zero verbs; non-empty
       list = exact allowlist).
    4. Emit one ``AgentToolDescriptor`` per surviving (instance, capability)
       pair.

    Result is sorted deterministically by ``(connector_name, capability)``
    so two consecutive calls return the same ordering — important for
    agent caches keyed off tool list hashes.
    """
    # 1. Active instances on this tenant. We deliberately don't filter
    #    on health_status — an agent can still "ask" a degraded
    #    connector and the call will surface the live failure, which is
    #    more useful than silently hiding the tool.
    result = await db.execute(
        select(Connector).where(
            Connector.tenant_id == current_user.tenant_id,
            Connector.is_enabled.is_(True),
        )
    )
    instances = list(result.scalars().all())

    if not instances:
        return AgentToolsResponse(tools=[], tool_count=0, connector_count=0)

    # 2. Catalog lookup, once. We index by connector_id (the catalog's
    #    notion of "type slug", not a UUID) so we can answer per-instance
    #    questions without N round-trips to the connectors service.
    catalog = await _fetch_catalog()
    catalog_by_type: dict[str, dict[str, Any]] = {
        entry["connector_id"]: entry for entry in catalog if isinstance(entry, dict) and isinstance(entry.get("connector_id"), str)
    }

    tools: list[AgentToolDescriptor] = []
    contributing_instances = 0

    for inst in instances:
        catalog_entry = catalog_by_type.get(inst.connector_type)
        if catalog_entry is None:
            # Stale row — connector class was removed from the build but
            # the instance row outlived it. Skip silently rather than
            # crashing; the operator-facing endpoint will already be
            # surfacing the orphan separately.
            logger.info(
                "agents.tools.skip_orphan tenant_id=%s connector_id=%s connector_type=%s",
                current_user.tenant_id,
                inst.id,
                _safe_log_val(inst.connector_type),
            )
            continue

        declared_descriptions = _capability_descriptions(catalog_entry)
        declared_set = set(declared_descriptions.keys())

        # 3. Apply per-instance downscope.
        if inst.allowed_capabilities is None:
            effective: list[str] = sorted(declared_set)
        else:
            allowed_set = {str(c) for c in inst.allowed_capabilities}
            # Intersection — if the column ever drifted ahead of the
            # connector class's declared set (e.g. via a manual SQL
            # tweak), we still don't surface verbs the class can't
            # actually execute. Defence-in-depth alongside the
            # validation in PUT /connectors/{id}/capabilities.
            effective = sorted(allowed_set & declared_set)

        if not effective:
            continue
        contributing_instances += 1

        category = catalog_entry.get("category") or inst.category or "uncategorized"
        connector_id_str = str(inst.id)

        for cap in effective:
            tools.append(
                AgentToolDescriptor(
                    name=f"{connector_id_str}.{cap}",
                    connector_id=connector_id_str,
                    connector_type=inst.connector_type,
                    connector_name=inst.name,
                    category=category,
                    capability=cap,
                    capability_group=_capability_group_of(cap),
                    description=declared_descriptions[cap],
                    # input_schema left as the empty-object default for
                    # now. Per-capability argument schemas land with the
                    # subsequent workstreams that flesh out concrete
                    # call surfaces (e.g. WS5 for self-healing actions,
                    # WS8 for ITSM push verbs). Doing it here would
                    # require touching every connector class twice —
                    # once now for the surface, once later for the
                    # logic — and the agent layer is already happy
                    # with an open object during early integration.
                ),
            )

    # 4. Deterministic ordering for stable tool-list hashes.
    tools.sort(key=lambda t: (t.connector_name.lower(), t.capability))

    logger.info(
        "agents.tools.served tenant_id=%s instances=%d tools=%d",
        current_user.tenant_id,
        contributing_instances,
        len(tools),
    )

    return AgentToolsResponse(
        tools=tools,
        tool_count=len(tools),
        connector_count=contributing_instances,
    )
