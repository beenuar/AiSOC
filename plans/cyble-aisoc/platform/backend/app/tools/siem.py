"""SIEM tools: query alerts, enrich with related events.

These handlers are thin wrappers around the connector SDK. Each tool
resolves the per-tenant SIEM connector (Splunk / Sentinel / mock fallback)
via :func:`app.connectors.get_connector` and delegates to the connector's
protocol method.

Tenancy
-------
Every handler is tagged with ``needs:tenant``. The agent base
(:class:`app.agents.base.BaseAgent.call_tool`) injects
``params["tenant_id"] = self.tenant_id`` before dispatch — the LLM cannot
read another tenant's SIEM by guessing a string, and the audit trail
records the *real* bound tenant. The JSON schema deliberately does **not**
declare ``tenant_id``: the model never sees that slot.
"""
from __future__ import annotations

from typing import Any

from app.connectors import ConnectorKind, get_connector
from app.tools.registry import RiskClass, tool


# Tag conventions consumed by BaseAgent.call_tool injection. Tools tagged
# `needs:tenant` get the agent's `tenant_id` forcibly stamped into the
# params, regardless of what the LLM produced.
_NEEDS_TENANT = "needs:tenant"


@tool(
    name="siem.search_events",
    integration="splunk",
    risk=RiskClass.READ,
    description="Search SIEM events around a host or user within a time window.",
    params={
        "type": "object",
        "properties": {
            "entity": {"type": "string"},
            "entity_type": {"enum": ["host", "user", "ip"]},
            "minutes": {"type": "integer", "default": 60},
        },
        "required": ["entity", "entity_type"],
    },
    result={
        "type": "object",
        "properties": {
            "entity": {"type": "string"},
            "entity_type": {"type": "string"},
            "window_minutes": {"type": "integer"},
            "events": {
                "type": "array",
                # Event payloads vary by event type (auth, process, net,
                # ...). We only enforce the envelope (ts + type) and let
                # vendor-specific fields ride along.
                "items": {
                    "type": "object",
                    "properties": {
                        "ts": {"type": "string"},
                        "type": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            },
        },
        "required": ["entity", "events"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "enrichment", "siem"],
)
async def siem_search_events(
    *,
    tenant_id: str,
    entity: str,
    entity_type: str,
    minutes: int = 60,
) -> dict[str, Any]:
    siem = await get_connector(tenant_id, ConnectorKind.SIEM)
    return await siem.search_events(
        entity=entity, entity_type=entity_type, minutes=minutes
    )


@tool(
    name="siem.get_related_alerts",
    integration="splunk",
    risk=RiskClass.READ,
    description="Find other alerts on same host/user within a window.",
    params={
        "type": "object",
        "properties": {
            "entity": {"type": "string"},
            "hours": {"type": "integer", "default": 24},
        },
        "required": ["entity"],
    },
    result={
        "type": "object",
        "properties": {
            "entity": {"type": "string"},
            "related_count": {"type": "integer"},
            "related": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "title": {"type": "string"},
                        "severity": {"type": "string"},
                    },
                    "additionalProperties": True,
                },
            },
        },
        "required": ["entity", "related"],
        "additionalProperties": False,
    },
    tags=[_NEEDS_TENANT, "siem"],
)
async def siem_get_related_alerts(
    *, tenant_id: str, entity: str, hours: int = 24
) -> dict[str, Any]:
    siem = await get_connector(tenant_id, ConnectorKind.SIEM)
    return await siem.get_related_alerts(entity=entity, hours=hours)
