"""Cold-archive query tool — registered on import (t6-cold-storage).

Wraps :func:`app.cold_storage.query.query_cold_archive` in the
platform's standard tool contract so the Hunter / Investigator /
Reporter agents can call it through the same dispatch path they
use for SIEM and CTI lookups.

Risk class is ``READ`` — querying cold storage has no side
effects, so it is safe to run without HITL. The result schema
documents the row-count + tier so the prompt-injection defense
layer can drop unexpected keys before the response re-enters the
LLM context.
"""
from __future__ import annotations

from typing import Any

from app.cold_storage.query import query_cold_archive
from app.models.tool_call import RiskClass
from app.tools.registry import tool


@tool(
    name="cold_archive.query",
    integration="cold_archive",
    risk=RiskClass.READ,
    description=(
        "Query the tenant's cold archive (warm and cold tiers) using the "
        "platform's compact SQL grammar: SELECT * FROM tenant.<tenant_id> "
        "[WHERE field = value [AND ...]] [LIMIT n]. The optional WHERE "
        "predicate '__tier = warm|cold' selects which tier to scan; the "
        "default is cold. Returns a row count, the scan total, and the "
        "first N matching rows."
    ),
    params={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": (
                    "SQL-ish query: SELECT * FROM tenant.<tenant_id> "
                    "[WHERE field=value [AND ...]] [LIMIT n]"
                ),
            }
        },
        "required": ["query"],
    },
    result={
        "type": "object",
        "properties": {
            "row_count": {"type": "integer"},
            "scanned": {"type": "integer"},
            "tier": {"type": "string"},
            "truncated": {"type": "boolean"},
            "rows": {"type": "array"},
        },
    },
    tags=["cold-storage", "historical-search"],
)
async def cold_archive_query(query: str, **_: Any) -> dict[str, Any]:
    return query_cold_archive(query=query)
