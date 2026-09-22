"""Investigation primitives, exposed to the model as callable tools.

Pillar 2. The registry held four enrichment calls — extract IOCs, map to
ATT&CK, look up a technique, enrich one indicator. That supports
alert-enrich-summarise and stops there, because none of them take another
tool's output as input. An investigation is a chain:

    process on a host -> where else that binary ran -> who was logged in ->
    where else that account authenticated -> which other hosts saw the
    indicator -> the timeline across all of them

These tools compose, so the model can follow that chain instead of being
handed one pre-serialised blob and asked to summarise it.

Execution is delegated to the API, which owns the lake connection and the
tenant predicate. The agent never builds SQL and never passes a tenant: the
API takes it from the authenticated session, because a tool argument named
``tenant_id`` would be the single most valuable thing to prompt-inject.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

from app.tools.registry import Tool

logger = structlog.get_logger()

# Investigation pivots hit the lake, which is slower than an enrichment
# lookup but is the whole point. Bounded so one slow pivot cannot stall a
# tool loop indefinitely.
TOOL_TIMEOUT_SECONDS = 20.0


def _api_url() -> str:
    return os.getenv("AISOC_API_URL", "http://api:8000").rstrip("/")


async def call_investigation_tool(tool: str, tenant_id: str, **args: Any) -> dict[str, Any]:
    """Run one pivot through the API.

    Errors are returned as data rather than raised: the tool loop feeds
    results back to the model, and a model that receives
    ``{"available": false, "reason": ...}`` can adapt, whereas an exception
    ends the investigation.
    """
    try:
        async with httpx.AsyncClient(timeout=TOOL_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{_api_url()}/api/v1/graph/investigate/query",
                json={"tool": tool, "args": args},
                headers={"X-Tenant-ID": tenant_id},
            )
            response.raise_for_status()
            return response.json()
    except Exception as exc:
        logger.warning("investigation_tool.failed", tool=tool, error=type(exc).__name__)
        return {
            "tool": tool,
            "available": False,
            # Worded for the model. "No results" and "the lookup failed" must
            # not read the same, or the second becomes evidence of absence.
            "reason": (
                f"Could not reach the investigation service ({type(exc).__name__}). "
                f"This is a lookup failure, not an absence of evidence — do not "
                f"conclude the activity did not occur."
            ),
        }


def _schema(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required}


_HOURS = {
    "type": "integer",
    "description": "Lookback window in hours. Defaults to 24, capped at 90 days.",
}
_DAYS = {
    "type": "integer",
    "description": "Lookback window in days. Capped at 90.",
}


def investigation_tools(tenant_id: str) -> list[Tool]:
    """Build the investigation toolset bound to one tenant.

    The tenant is captured here rather than exposed as a tool argument, so it
    is not in the schema the model sees and cannot be supplied by it.
    """

    def bind(name: str):
        async def _call(**args: Any) -> dict[str, Any]:
            return await call_investigation_tool(name, tenant_id, **args)

        return _call

    return [
        Tool(
            name="process_activity",
            description=(
                "List processes that executed on a host, most recent first. Use this "
                "first when an alert names a host, to see what actually ran."
            ),
            parameters=_schema(
                {
                    "hostname": {"type": "string", "description": "The host to inspect."},
                    "hours": _HOURS,
                },
                ["hostname"],
            ),
            fn=bind("process_activity"),
        ),
        Tool(
            name="historical_execution",
            description=(
                "Find every host and account that has run a binary, by name or SHA-256. "
                "Turns a single suspicious process into a fleet-wide picture: a binary "
                "first seen on three hosts this morning is a different finding from one "
                "that has run daily for a year."
            ),
            parameters=_schema(
                {
                    "process_name": {"type": "string"},
                    "sha256": {"type": "string"},
                    "days": _DAYS,
                },
                [],
            ),
            fn=bind("historical_execution"),
        ),
        Tool(
            name="network_connections",
            description=(
                "Outbound connections from a host or source address, grouped by "
                "destination. Use after process_activity to see where a process "
                "talked to."
            ),
            parameters=_schema(
                {"hostname": {"type": "string"}, "source_ip": {"type": "string"}, "hours": _HOURS},
                [],
            ),
            fn=bind("network_connections"),
        ),
        Tool(
            name="authentication_events",
            description=(
                "Where and from what addresses an account authenticated. Use to check "
                "for impossible travel: several distinct source addresses for one "
                "account inside a window too short to have travelled."
            ),
            parameters=_schema({"user_name": {"type": "string"}, "hours": _HOURS}, ["user_name"]),
            fn=bind("authentication_events"),
        ),
        Tool(
            name="fleet_ioc_hunt",
            description=(
                "Find every host that has observed an indicator (IP, domain, hash). "
                "This is the pivot that finds the second compromised machine."
            ),
            parameters=_schema(
                {
                    "indicator": {"type": "string", "description": "IP, domain or SHA-256."},
                    "days": _DAYS,
                },
                ["indicator"],
            ),
            fn=bind("fleet_ioc_hunt"),
        ),
        Tool(
            name="entity_timeline",
            description=(
                "Every event touching one host or account, in chronological order. Use "
                "last, to reconstruct the sequence once the entities are known."
            ),
            parameters=_schema(
                {"hostname": {"type": "string"}, "user_name": {"type": "string"}, "hours": _HOURS},
                [],
            ),
            fn=bind("entity_timeline"),
        ),
        Tool(
            name="technique_activity",
            description=(
                "Other events mapped to the same ATT&CK technique. Answers whether a "
                "behaviour is isolated or a pattern, which often separates a true "
                "positive from a noisy rule."
            ),
            parameters=_schema(
                {"technique_id": {"type": "string", "description": "e.g. T1059.001"}, "days": _DAYS},
                ["technique_id"],
            ),
            fn=bind("technique_activity"),
        ),
        # Present deliberately, even though they cannot answer. A model that
        # finds no process-tree tool pivots to whatever tool it does have and
        # presents the result as lineage; one that is told the data class is
        # not ingested reports the gap, which is both true and actionable.
        Tool(
            name="process_tree",
            description=(
                "Parent-child process lineage on a host. Reports whether this data "
                "class is ingested; it requires an EDR connector that emits process "
                "lineage."
            ),
            parameters=_schema({"hostname": {"type": "string"}, "pid": {"type": "integer"}}, ["hostname"]),
            fn=bind("process_tree"),
        ),
        Tool(
            name="mailbox_activity",
            description=(
                "Mailbox rules and access for an account. Reports whether this data "
                "class is ingested; it requires a Microsoft 365 or Google Workspace "
                "audit connector."
            ),
            parameters=_schema({"user_name": {"type": "string"}}, ["user_name"]),
            fn=bind("mailbox_activity"),
        ),
        Tool(
            name="oauth_grants",
            description=(
                "OAuth application consent grants for an account. Reports whether this "
                "data class is ingested; it requires an Entra ID or Okta system-log "
                "connector."
            ),
            parameters=_schema({"user_name": {"type": "string"}}, ["user_name"]),
            fn=bind("oauth_grants"),
        ),
        Tool(
            name="persistence_mechanisms",
            description=(
                "Run keys, scheduled tasks, launch agents and cron entries on a host. "
                "Reports whether this data class is ingested; it requires an EDR or "
                "osquery connector."
            ),
            parameters=_schema({"hostname": {"type": "string"}}, ["hostname"]),
            fn=bind("persistence_mechanisms"),
        ),
    ]
