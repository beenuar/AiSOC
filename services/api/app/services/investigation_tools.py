"""Typed investigation primitives over the event lake.

Pillar 2. The agent's toolset was four enrichment calls — extract IOCs, map to
ATT&CK, look up a technique, enrich one indicator. That supports
alert-enrich-summarise and nothing deeper. A real investigation pivots:

    process on a host -> where else has that binary run -> who was logged in
    -> where else did that account authenticate -> which other hosts saw the
    same indicator -> what is the timeline across all of them

Every hop needs the *previous* hop's answer as its input, which is what makes
it an investigation rather than an enrichment.

Two decisions shape this module.

**The model never writes SQL.** Each tool takes typed arguments and composes a
parameterised query here. Handing an LLM the lake SQL endpoint would put
prompt-injectable text one step from the query planner, and the tenant
predicate is the only thing standing between two customers' data.

**A tool that has no data says so, and says why.** The lake stores what the
connected connectors send. Mailbox activity, OAuth grants and parent-process
lineage are not columns in ``aisoc.raw_events`` — no connector populates them
today. The honest response is ``available: false`` naming the missing data
class, not an empty result set. An empty result reads to a model as "I
checked and there is nothing", which is how an investigation concludes benign
on evidence it never had.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from app.db.clickhouse import execute_lake_query

logger = logging.getLogger("aisoc.investigation_tools")

LAKE_TABLE = "aisoc.raw_events"

# Hard caps. An investigation tool is called by a model in a loop, so an
# unbounded row count is both a cost and a context-window problem.
MAX_ROWS = 200
DEFAULT_ROWS = 50
MAX_LOOKBACK_DAYS = 90
DEFAULT_LOOKBACK_HOURS = 24

#: Columns ``aisoc.raw_events`` actually has. Anything a tool wants that is
#: not here cannot be answered, and the tool must say so rather than return
#: an empty set.
LAKE_COLUMNS = frozenset(
    {
        "tenant_id",
        "event_time",
        "event_id",
        "connector_type",
        "user_name",
        "source_ip",
        "dest_ip",
        "src_port",
        "dst_port",
        "src_hostname",
        "dst_hostname",
        "process_name",
        "file_path",
        "hash_sha256",
        "severity_id",
        "protocol",
        "mitre_techniques",
        "mitre_tactics",
        "iocs",
        "raw_payload",
    }
)

#: Data classes an investigation wants that nothing currently ingests.
#: Declared rather than silently absent, so a tool can explain the gap.
UNAVAILABLE_DATA: dict[str, str] = {
    "process_tree": (
        "Parent-process lineage is not stored: aisoc.raw_events has process_name "
        "but no parent_process_name or process_guid. An EDR connector that emits "
        "process lineage (CrowdStrike, Defender, SentinelOne) would populate it."
    ),
    "mailbox_activity": ("Mailbox events are not ingested. Connect a Microsoft 365 or Google Workspace audit connector."),
    "oauth_grants": ("OAuth consent grants are not ingested. Connect an Entra ID or Okta system-log connector."),
    "persistence": (
        "Persistence mechanisms (run keys, scheduled tasks, launch agents, cron) "
        "are not stored as a distinct data class. An EDR or osquery connector "
        "would populate them."
    ),
}


@dataclass
class ToolResult:
    """One tool's answer, including whether it could answer at all.

    ``available=False`` is deliberately distinct from ``rows=[]``. The first
    means the data class is not ingested; the second means it is ingested and
    there was nothing matching. A model handed the same shape for both will
    treat "we cannot see it" as "it did not happen".
    """

    tool: str
    available: bool = True
    rows: list[dict[str, Any]] = field(default_factory=list)
    row_count: int = 0
    truncated: bool = False
    reason: str | None = None
    query_description: str = ""

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "tool": self.tool,
            "available": self.available,
            "row_count": self.row_count,
            "rows": self.rows,
        }
        if self.truncated:
            payload["truncated"] = True
            payload["note"] = (
                f"Result capped at {MAX_ROWS} rows. Narrow the time window or the "
                f"entity to see the rest; do not treat this as the full set."
            )
        if self.reason:
            payload["reason"] = self.reason
        if self.query_description:
            payload["query"] = self.query_description
        return payload


def unavailable(tool: str, data_class: str) -> ToolResult:
    return ToolResult(
        tool=tool,
        available=False,
        reason=UNAVAILABLE_DATA.get(data_class, f"{data_class} is not ingested by any connected connector."),
    )


def _clamp_rows(limit: int | None) -> int:
    if not limit or limit < 1:
        return DEFAULT_ROWS
    return min(int(limit), MAX_ROWS)


def _clamp_hours(hours: int | None) -> int:
    if not hours or hours < 1:
        return DEFAULT_LOOKBACK_HOURS
    return min(int(hours), MAX_LOOKBACK_DAYS * 24)


async def _run(
    tool: str,
    sql: str,
    params: dict[str, Any],
    *,
    limit: int,
    description: str,
) -> ToolResult:
    """Execute a composed query. Every caller goes through here.

    The tenant predicate is bound as a parameter and is not optional: a tool
    reaching this function without one is a bug, and the assertion makes it a
    loud one rather than a cross-tenant read.
    """
    assert "tenant_id" in params, f"{tool}: composed a lake query with no tenant binding"
    assert "%(tenant_id)s" in sql, f"{tool}: tenant predicate missing from SQL"

    try:
        result = await execute_lake_query(sql, params=params)
    except Exception as exc:
        logger.warning("investigation_tool.%s failed err=%s", tool, type(exc).__name__)
        return ToolResult(
            tool=tool,
            available=False,
            reason=f"Lake query failed ({type(exc).__name__}). This is a lookup failure, not an absence of evidence.",
            query_description=description,
        )

    columns = list(result.columns or [])
    rows = [dict(zip(columns, row, strict=False)) for row in (result.rows or [])]
    return ToolResult(
        tool=tool,
        rows=rows,
        row_count=len(rows),
        truncated=len(rows) >= limit,
        query_description=description,
    )


# ── the tools ───────────────────────────────────────────────────────────────
# Each takes typed arguments and composes its own parameterised SQL. None
# accepts SQL, a column name, or an operator from the caller.


async def process_activity(
    tenant_id: uuid.UUID | str,
    hostname: str,
    *,
    hours: int = DEFAULT_LOOKBACK_HOURS,
    limit: int = DEFAULT_ROWS,
) -> ToolResult:
    """What executed on a host, most recent first."""
    hours, limit = _clamp_hours(hours), _clamp_rows(limit)
    sql = f"""
        SELECT event_time, process_name, file_path, hash_sha256, user_name, connector_type
        FROM {LAKE_TABLE}
        WHERE tenant_id = %(tenant_id)s
          AND src_hostname = %(hostname)s
          AND process_name != ''
          AND event_time >= now() - INTERVAL %(hours)s HOUR
        ORDER BY event_time DESC
        LIMIT %(limit)s
    """
    return await _run(
        "process_activity",
        sql,
        {"tenant_id": str(tenant_id), "hostname": hostname, "hours": hours, "limit": limit},
        limit=limit,
        description=f"processes on {hostname} in the last {hours}h",
    )


async def historical_execution(
    tenant_id: uuid.UUID | str,
    *,
    process_name: str | None = None,
    sha256: str | None = None,
    days: int = 30,
    limit: int = DEFAULT_ROWS,
) -> ToolResult:
    """Where else this binary has run, across the fleet.

    The pivot that turns "suspicious process on one host" into "this binary
    first appeared on three hosts this morning".
    """
    if not process_name and not sha256:
        return ToolResult(
            tool="historical_execution",
            available=False,
            reason="Supply either process_name or sha256.",
        )
    days = min(max(int(days or 30), 1), MAX_LOOKBACK_DAYS)
    limit = _clamp_rows(limit)

    clause = "hash_sha256 = %(sha256)s" if sha256 else "process_name = %(process_name)s"
    sql = f"""
        SELECT src_hostname, user_name, min(event_time) AS first_seen,
               max(event_time) AS last_seen, count() AS executions
        FROM {LAKE_TABLE}
        WHERE tenant_id = %(tenant_id)s
          AND {clause}
          AND event_time >= now() - INTERVAL %(days)s DAY
        GROUP BY src_hostname, user_name
        ORDER BY first_seen ASC
        LIMIT %(limit)s
    """
    return await _run(
        "historical_execution",
        sql,
        {
            "tenant_id": str(tenant_id),
            "sha256": sha256 or "",
            "process_name": process_name or "",
            "days": days,
            "limit": limit,
        },
        limit=limit,
        description=f"executions of {sha256 or process_name} across the fleet, last {days}d",
    )


async def network_connections(
    tenant_id: uuid.UUID | str,
    *,
    hostname: str | None = None,
    source_ip: str | None = None,
    hours: int = DEFAULT_LOOKBACK_HOURS,
    limit: int = DEFAULT_ROWS,
) -> ToolResult:
    """Outbound connections from a host or address."""
    if not hostname and not source_ip:
        return ToolResult(
            tool="network_connections",
            available=False,
            reason="Supply either hostname or source_ip.",
        )
    hours, limit = _clamp_hours(hours), _clamp_rows(limit)
    clause = "src_hostname = %(hostname)s" if hostname else "source_ip = %(source_ip)s"
    sql = f"""
        SELECT dest_ip, dst_hostname, dst_port, protocol,
               count() AS connections, max(event_time) AS last_seen
        FROM {LAKE_TABLE}
        WHERE tenant_id = %(tenant_id)s
          AND {clause}
          AND dest_ip != ''
          AND event_time >= now() - INTERVAL %(hours)s HOUR
        GROUP BY dest_ip, dst_hostname, dst_port, protocol
        ORDER BY connections DESC
        LIMIT %(limit)s
    """
    return await _run(
        "network_connections",
        sql,
        {
            "tenant_id": str(tenant_id),
            "hostname": hostname or "",
            "source_ip": source_ip or "",
            "hours": hours,
            "limit": limit,
        },
        limit=limit,
        description=f"connections from {hostname or source_ip} in the last {hours}h",
    )


async def authentication_events(
    tenant_id: uuid.UUID | str,
    user_name: str,
    *,
    hours: int = 168,
    limit: int = DEFAULT_ROWS,
) -> ToolResult:
    """Where and from what addresses an account authenticated.

    The source of an impossible-travel finding: distinct source addresses for
    one account inside a window too short to have travelled.
    """
    hours, limit = _clamp_hours(hours), _clamp_rows(limit)
    sql = f"""
        SELECT event_time, source_ip, src_hostname, connector_type, severity_id
        FROM {LAKE_TABLE}
        WHERE tenant_id = %(tenant_id)s
          AND user_name = %(user_name)s
          AND source_ip != ''
          AND event_time >= now() - INTERVAL %(hours)s HOUR
        ORDER BY event_time DESC
        LIMIT %(limit)s
    """
    return await _run(
        "authentication_events",
        sql,
        {"tenant_id": str(tenant_id), "user_name": user_name, "hours": hours, "limit": limit},
        limit=limit,
        description=f"authentication events for {user_name} in the last {hours}h",
    )


async def fleet_ioc_hunt(
    tenant_id: uuid.UUID | str,
    indicator: str,
    *,
    days: int = 30,
    limit: int = DEFAULT_ROWS,
) -> ToolResult:
    """Every host that has seen an indicator.

    The hop that finds the second compromised machine.
    """
    days = min(max(int(days or 30), 1), MAX_LOOKBACK_DAYS)
    limit = _clamp_rows(limit)
    # The indicator can appear in any of several columns depending on which
    # connector observed it, so all are checked. Each is a bound parameter.
    sql = f"""
        SELECT src_hostname, user_name, connector_type,
               min(event_time) AS first_seen, max(event_time) AS last_seen,
               count() AS hits
        FROM {LAKE_TABLE}
        WHERE tenant_id = %(tenant_id)s
          AND event_time >= now() - INTERVAL %(days)s DAY
          AND (
            source_ip = %(indicator)s
            OR dest_ip = %(indicator)s
            OR dst_hostname = %(indicator)s
            OR hash_sha256 = %(indicator)s
            OR has(iocs, %(indicator)s)
          )
        GROUP BY src_hostname, user_name, connector_type
        ORDER BY first_seen ASC
        LIMIT %(limit)s
    """
    return await _run(
        "fleet_ioc_hunt",
        sql,
        {"tenant_id": str(tenant_id), "indicator": indicator, "days": days, "limit": limit},
        limit=limit,
        description=f"hosts that observed {indicator} in the last {days}d",
    )


async def entity_timeline(
    tenant_id: uuid.UUID | str,
    *,
    hostname: str | None = None,
    user_name: str | None = None,
    hours: int = DEFAULT_LOOKBACK_HOURS,
    limit: int = DEFAULT_ROWS,
) -> ToolResult:
    """Everything touching one entity, in order. The reconstruction step."""
    if not hostname and not user_name:
        return ToolResult(
            tool="entity_timeline",
            available=False,
            reason="Supply either hostname or user_name.",
        )
    hours, limit = _clamp_hours(hours), _clamp_rows(limit)
    clause = "src_hostname = %(hostname)s" if hostname else "user_name = %(user_name)s"
    sql = f"""
        SELECT event_time, connector_type, user_name, src_hostname,
               process_name, source_ip, dest_ip, severity_id, mitre_techniques
        FROM {LAKE_TABLE}
        WHERE tenant_id = %(tenant_id)s
          AND {clause}
          AND event_time >= now() - INTERVAL %(hours)s HOUR
        ORDER BY event_time ASC
        LIMIT %(limit)s
    """
    return await _run(
        "entity_timeline",
        sql,
        {
            "tenant_id": str(tenant_id),
            "hostname": hostname or "",
            "user_name": user_name or "",
            "hours": hours,
            "limit": limit,
        },
        limit=limit,
        description=f"timeline for {hostname or user_name} over the last {hours}h",
    )


async def technique_activity(
    tenant_id: uuid.UUID | str,
    technique_id: str,
    *,
    days: int = 7,
    limit: int = DEFAULT_ROWS,
) -> ToolResult:
    """Other events mapped to the same ATT&CK technique.

    Answers "is this an isolated behaviour or a pattern", which is often the
    difference between a true positive and a noisy rule.
    """
    days = min(max(int(days or 7), 1), MAX_LOOKBACK_DAYS)
    limit = _clamp_rows(limit)
    sql = f"""
        SELECT src_hostname, user_name, connector_type,
               count() AS events, max(event_time) AS last_seen
        FROM {LAKE_TABLE}
        WHERE tenant_id = %(tenant_id)s
          AND has(mitre_techniques, %(technique_id)s)
          AND event_time >= now() - INTERVAL %(days)s DAY
        GROUP BY src_hostname, user_name, connector_type
        ORDER BY events DESC
        LIMIT %(limit)s
    """
    return await _run(
        "technique_activity",
        sql,
        {"tenant_id": str(tenant_id), "technique_id": technique_id, "days": days, "limit": limit},
        limit=limit,
        description=f"activity mapped to {technique_id} in the last {days}d",
    )


# ── tools that cannot be answered from what is ingested ─────────────────────
# Present rather than absent, because a model that finds no process-tree tool
# will pivot to whatever tool it does have and present the result as lineage.
# An explicit "not ingested, connect an EDR connector" is both truthful and
# actionable.


async def process_tree(tenant_id: uuid.UUID | str, hostname: str, pid: int | None = None) -> ToolResult:
    return unavailable("process_tree", "process_tree")


async def mailbox_activity(tenant_id: uuid.UUID | str, user_name: str) -> ToolResult:
    return unavailable("mailbox_activity", "mailbox_activity")


async def oauth_grants(tenant_id: uuid.UUID | str, user_name: str) -> ToolResult:
    return unavailable("oauth_grants", "oauth_grants")


async def persistence_mechanisms(tenant_id: uuid.UUID | str, hostname: str) -> ToolResult:
    return unavailable("persistence_mechanisms", "persistence")


#: Name -> coroutine. The dispatch table the API endpoint and the agent
#: registry both read, so the two cannot drift.
TOOLS: dict[str, Any] = {
    "process_activity": process_activity,
    "historical_execution": historical_execution,
    "network_connections": network_connections,
    "authentication_events": authentication_events,
    "fleet_ioc_hunt": fleet_ioc_hunt,
    "entity_timeline": entity_timeline,
    "technique_activity": technique_activity,
    "process_tree": process_tree,
    "mailbox_activity": mailbox_activity,
    "oauth_grants": oauth_grants,
    "persistence_mechanisms": persistence_mechanisms,
}

#: Tools backed by real lake columns today. The rest report why they cannot
#: answer. Kept explicit so the split is reviewable rather than inferred.
BACKED_TOOLS = frozenset(
    {
        "process_activity",
        "historical_execution",
        "network_connections",
        "authentication_events",
        "fleet_ioc_hunt",
        "entity_timeline",
        "technique_activity",
    }
)


async def dispatch(name: str, tenant_id: uuid.UUID | str, args: dict[str, Any]) -> ToolResult:
    """Run one tool by name with the caller's tenant.

    ``tenant_id`` is supplied by the authenticated request, never by the
    model: a tool argument named tenant_id would be the one parameter worth
    prompt-injecting.
    """
    fn = TOOLS.get(name)
    if fn is None:
        return ToolResult(
            tool=name,
            available=False,
            reason=f"Unknown tool {name!r}. Available: {', '.join(sorted(TOOLS))}",
        )
    safe_args = {k: v for k, v in (args or {}).items() if k != "tenant_id"}
    try:
        return await fn(tenant_id, **safe_args)
    except TypeError as exc:
        return ToolResult(
            tool=name,
            available=False,
            reason=f"Invalid arguments for {name}: {exc}",
        )
