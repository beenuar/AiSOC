"""Memory tools — scratchpad, episodic recall, and threat graph.

These wrap :mod:`app.memory` so agents can call them like any other tool
and we get the full audit trail (trace step, tool call, prompt-injection
defense, HITL gating if configured) for free.

Tenancy & case scoping
----------------------
Memory operations are *always* tenant-scoped (and most are case-scoped).
We never want the LLM to supply ``tenant_id`` / ``case_id`` itself — the
model must not be able to read another tenant's graph by guessing a
plausible string. So these tools carry two well-known tags:

* ``needs:tenant`` — :class:`app.agents.base.BaseAgent.call_tool` injects
  ``params["tenant_id"] = self.tenant_id`` before dispatch, overriding
  anything the model produced.
* ``needs:case`` — same idea for ``case_id``.

Because injection happens *before* the trace is written, the audit record
shows the real bound values, not a forgery.

Risk classes
------------
* Read-only recall / lookup / neighbour traversal → ``READ``.
* ``memory.scratchpad_set`` → ``WRITE_REVERSIBLE``. Paired with
  ``memory.scratchpad_delete`` (defined below) so the rollback service
  can surgically undo a single scratchpad key, not the whole pad.
* ``memory.episodic_record``, ``graph.upsert_node``, ``graph.upsert_edge``
  → ``WRITE_SIGNIFICANT``. We deliberately do NOT pair these with
  reverse handlers (see audit note below): an episodic memory or graph
  node, once written, may already have been consumed by downstream
  recall / pivots, and a true inverse would require also rolling back
  every read that hit it. HITL surfaces these as significant so an
  analyst can choose to mark a row stale, but the rollback service will
  not automatically undo them.
"""
from __future__ import annotations

from typing import Any

from app.memory import (
    episodic_recall,
    episodic_record,
    graph_find_nodes,
    graph_neighbors,
    graph_upsert_edge,
    graph_upsert_node,
    scratchpad,
)
from app.tools.registry import RiskClass, tool


# ── Tag conventions used by BaseAgent.call_tool injection ─────────────
_NEEDS_TENANT = "needs:tenant"
_NEEDS_CASE = "needs:case"


# ─────────────────────────────────────────────────────────────────────
# Scratchpad — per-case key/value pad
# ─────────────────────────────────────────────────────────────────────


def _scratchpad_set_reverse_params(
    *, params: dict[str, Any], result: dict[str, Any] | None
) -> dict[str, Any]:
    """Reverse-param builder for ``memory.scratchpad_set``.

    The forward call wrote a single ``key`` on the per-case scratchpad.
    The inverse is to delete exactly that key — *not* to wipe the whole
    pad. ``case_id`` is bound by the BaseAgent injection layer at
    dispatch time, so we only need to surface ``key`` here.
    """
    return {"key": params["key"]}


@tool(
    name="memory.scratchpad_set",
    integration="aisoc-memory",
    risk=RiskClass.WRITE_REVERSIBLE,
    description=(
        "Write a key on this case's scratchpad. Use to remember intermediate "
        "facts (working hypotheses, decoded blobs, partial findings) across "
        "tool calls. Reversible via memory.scratchpad_delete."
    ),
    params={
        "type": "object",
        "properties": {
            "key": {"type": "string"},
            "value": {},
        },
        "required": ["key", "value"],
    },
    result={
        "type": "object",
        "properties": {"ok": {"type": "boolean"}, "key": {"type": "string"}},
        "required": ["ok", "key"],
    },
    tags=[_NEEDS_CASE, "memory", "scratchpad"],
    reverse_tool="memory.scratchpad_delete",
    reverse_params_builder=_scratchpad_set_reverse_params,
)
async def memory_scratchpad_set(
    *, case_id: int, key: str, value: Any
) -> dict[str, Any]:
    scratchpad.set(case_id, key, value)
    return {"ok": True, "key": key}


@tool(
    name="memory.scratchpad_delete",
    integration="aisoc-memory",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: this tool exists primarily as
    # the reverse handler for memory.scratchpad_set. We deliberately do NOT
    # pair it with its own reverse (which would have to restore the prior
    # value), because tracking and replaying overwritten scratchpad values
    # adds non-trivial complexity for marginal benefit. Per the audit
    # convention, a reverse handler that has no reverse-of-its-own is
    # WRITE_SIGNIFICANT so HITL still gates it, but rollback_service.classify
    # correctly refuses to auto-undo it.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "this IS the reverse of memory.scratchpad_set; restoring an "
        "overwritten value would require keeping prior-value history we "
        "intentionally don't maintain. Re-set must be a fresh forward call"
    ),
    description=(
        "Delete a single key from this case's scratchpad. Primarily used as "
        "the paired reverse handler for memory.scratchpad_set so the "
        "rollback service can surgically undo a forgotten note without "
        "wiping the entire scratchpad."
    ),
    params={
        "type": "object",
        "properties": {"key": {"type": "string"}},
        "required": ["key"],
    },
    result={
        "type": "object",
        "properties": {
            "ok": {"type": "boolean"},
            "key": {"type": "string"},
            "existed": {"type": "boolean"},
        },
        "required": ["ok", "key", "existed"],
    },
    tags=[_NEEDS_CASE, "memory", "scratchpad"],
)
async def memory_scratchpad_delete(
    *, case_id: int, key: str
) -> dict[str, Any]:
    existed = scratchpad.delete(case_id, key)
    return {"ok": True, "key": key, "existed": existed}


@tool(
    name="memory.scratchpad_get",
    integration="aisoc-memory",
    risk=RiskClass.READ,
    description=(
        "Read a key from this case's scratchpad. Returns the stored value, "
        "or null if the key was never written."
    ),
    params={
        "type": "object",
        "properties": {"key": {"type": "string"}},
        "required": ["key"],
    },
    result={
        "type": "object",
        "properties": {
            "key": {"type": "string"},
            "found": {"type": "boolean"},
            "value": {},
        },
        "required": ["key", "found"],
    },
    tags=[_NEEDS_CASE, "memory", "scratchpad"],
)
async def memory_scratchpad_get(
    *, case_id: int, key: str
) -> dict[str, Any]:
    sentinel = object()
    value = scratchpad.get(case_id, key, default=sentinel)
    if value is sentinel:
        return {"key": key, "found": False, "value": None}
    return {"key": key, "found": True, "value": value}


@tool(
    name="memory.scratchpad_all",
    integration="aisoc-memory",
    risk=RiskClass.READ,
    description=(
        "Return the full scratchpad for this case as a {key: value} map. "
        "Useful at the start of a turn to recall prior intermediate state."
    ),
    params={"type": "object", "properties": {}},
    result={
        "type": "object",
        "properties": {
            "case_id": {"type": "integer"},
            "entries": {"type": "object"},
        },
        "required": ["case_id", "entries"],
    },
    tags=[_NEEDS_CASE, "memory", "scratchpad"],
)
async def memory_scratchpad_all(*, case_id: int) -> dict[str, Any]:
    return {"case_id": case_id, "entries": scratchpad.all(case_id)}


# ─────────────────────────────────────────────────────────────────────
# Episodic memory — recall past closed investigations
# ─────────────────────────────────────────────────────────────────────


@tool(
    name="memory.episodic_recall",
    integration="aisoc-memory",
    risk=RiskClass.READ,
    description=(
        "Recall the top-K most similar past investigations for a free-text "
        "query (e.g. 'lateral movement via SMB from contractor host'). "
        "Returns title, narrative, verdict, and tags for each hit. "
        "Tenancy-scoped: only this tenant's history is returned."
    ),
    params={
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "k": {"type": "integer", "default": 3, "minimum": 1, "maximum": 20},
        },
        "required": ["query"],
    },
    result={
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "hits": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "title": {"type": "string"},
                        "narrative": {"type": "string"},
                        "verdict": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "score": {"type": "number"},
                    },
                },
            },
        },
        "required": ["query", "hits"],
    },
    tags=[_NEEDS_TENANT, "memory", "episodic"],
)
async def memory_episodic_recall(
    *, tenant_id: str, query: str, k: int = 3
) -> dict[str, Any]:
    hits = episodic_recall(query=query, k=k, tenant_id=tenant_id)
    return {"query": query, "hits": hits}


@tool(
    name="memory.episodic_record",
    integration="aisoc-memory",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: once an episodic memory is
    # indexed it may already have been retrieved by downstream recall
    # (across other cases or tenants in the global pool), and we have no
    # safe inverse for "un-influence" past LLM turns. HITL can flag the
    # row stale; the rollback service deliberately leaves it alone.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "an indexed episodic memory may already have been retrieved by "
        "downstream cases or tenants; there is no inverse for un-influencing "
        "prior LLM turns. HITL marks rows stale instead"
    ),
    description=(
        "Record this case as an episodic memory for future recall. Usually "
        "called by the Reporter at case close — the title + narrative + "
        "verdict become a retrieval target for similar future cases."
    ),
    params={
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "narrative": {"type": "string"},
            "verdict": {"type": "string"},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["title", "narrative", "verdict"],
    },
    result={
        "type": "object",
        "properties": {"ok": {"type": "boolean"}, "title": {"type": "string"}},
        "required": ["ok", "title"],
    },
    tags=[_NEEDS_CASE, _NEEDS_TENANT, "memory", "episodic"],
)
async def memory_episodic_record(
    *,
    case_id: int,
    tenant_id: str,
    title: str,
    narrative: str,
    verdict: str,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    episodic_record(
        case_id=case_id,
        title=title,
        narrative=narrative,
        verdict=verdict,
        tags=tags or [],
        tenant_id=tenant_id,
    )
    return {"ok": True, "title": title}


# ─────────────────────────────────────────────────────────────────────
# Threat graph — entities and relationships
# ─────────────────────────────────────────────────────────────────────


@tool(
    name="graph.upsert_node",
    integration="aisoc-memory",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: graph upserts are
    # idempotent and additive — a "reverse" would be ambiguous because
    # we don't know whether the node existed before this call, and
    # other edges may have been hung off the node since. Leave HITL to
    # decide. The rollback service intentionally won't auto-undo this.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "graph upserts are idempotent and additive; a 'reverse' is "
        "ambiguous because we can't tell whether the node pre-existed, "
        "and other edges may now depend on it. HITL marks nodes stale"
    ),
    description=(
        "Idempotently add or update an entity in the threat graph. Use to "
        "register IOCs, assets, users, actors, campaigns, techniques, tools, "
        "vulnerabilities, or cases. Returns the node id. Auto-creates if "
        "missing."
    ),
    params={
        "type": "object",
        "properties": {
            "type": {
                "type": "string",
                "enum": [
                    "ioc",
                    "asset",
                    "user",
                    "actor",
                    "campaign",
                    "technique",
                    "tool",
                    "vulnerability",
                    "case",
                ],
            },
            "key": {"type": "string"},
            "label": {"type": "string"},
            "props": {"type": "object"},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["type", "key"],
    },
    result={
        "type": "object",
        "properties": {
            "node_id": {"type": "integer"},
            "type": {"type": "string"},
            "key": {"type": "string"},
        },
        "required": ["node_id", "type", "key"],
    },
    tags=[_NEEDS_TENANT, "memory", "graph"],
)
async def graph_upsert_node_tool(
    *,
    tenant_id: str,
    type: str,
    key: str,
    label: str = "",
    props: dict[str, Any] | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    node_id = graph_upsert_node(
        tenant_id=tenant_id,
        type=type,
        key=key,
        label=label,
        props=props or {},
        tags=tags or [],
    )
    return {"node_id": node_id, "type": type, "key": key}


@tool(
    name="graph.upsert_edge",
    integration="aisoc-memory",
    # WRITE_SIGNIFICANT, not WRITE_REVERSIBLE: same reasoning as
    # graph.upsert_node — upserts are idempotent and may already have
    # been traversed by `graph.neighbors` calls. The rollback service
    # does not auto-undo this; HITL marks bad edges stale instead.
    risk=RiskClass.WRITE_SIGNIFICANT,
    forward_only_reason=(
        "edge upserts are idempotent and may already have influenced "
        "graph.neighbors traversals; there is no safe inverse. HITL marks "
        "bad edges stale instead"
    ),
    description=(
        "Idempotently add or update a typed relationship between two graph "
        "nodes. Endpoints are auto-created if missing. Edge types: "
        "communicates_with, observed_on, attributed_to, uses, exploits, "
        "part_of, related_to, involved_in, authenticated_as."
    ),
    params={
        "type": "object",
        "properties": {
            "src_type": {"type": "string"},
            "src_key": {"type": "string"},
            "dst_type": {"type": "string"},
            "dst_key": {"type": "string"},
            "type": {
                "type": "string",
                "enum": [
                    "communicates_with",
                    "observed_on",
                    "attributed_to",
                    "uses",
                    "exploits",
                    "part_of",
                    "related_to",
                    "involved_in",
                    "authenticated_as",
                ],
            },
            "weight": {"type": "number", "default": 1.0},
            "props": {"type": "object"},
        },
        "required": ["src_type", "src_key", "dst_type", "dst_key", "type"],
    },
    result={
        "type": "object",
        "properties": {"edge_id": {"type": "integer"}, "type": {"type": "string"}},
        "required": ["edge_id", "type"],
    },
    tags=[_NEEDS_TENANT, "memory", "graph"],
)
async def graph_upsert_edge_tool(
    *,
    tenant_id: str,
    src_type: str,
    src_key: str,
    dst_type: str,
    dst_key: str,
    type: str,
    weight: float = 1.0,
    props: dict[str, Any] | None = None,
) -> dict[str, Any]:
    edge_id = graph_upsert_edge(
        tenant_id=tenant_id,
        src=(src_type, src_key),
        dst=(dst_type, dst_key),
        type=type,
        weight=weight,
        props=props or {},
    )
    return {"edge_id": edge_id, "type": type}


@tool(
    name="graph.neighbors",
    integration="aisoc-memory",
    risk=RiskClass.READ,
    description=(
        "Traverse the threat graph from a node. Returns neighbours within "
        "`depth` hops with the edge that connected them. Use to answer "
        "'what else has this C2 talked to?', 'which assets touched this "
        "actor?', etc. Set include_global=true to also walk Cyble's shared "
        "CTI graph."
    ),
    params={
        "type": "object",
        "properties": {
            "type": {"type": "string"},
            "key": {"type": "string"},
            "edge_types": {"type": "array", "items": {"type": "string"}},
            "depth": {"type": "integer", "default": 1, "minimum": 1, "maximum": 3},
            "include_global": {"type": "boolean", "default": False},
            "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200},
        },
        "required": ["type", "key"],
    },
    result={
        "type": "object",
        "properties": {
            "node": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "key": {"type": "string"},
                },
            },
            "neighbors": {"type": "array", "items": {"type": "object"}},
        },
        "required": ["node", "neighbors"],
    },
    tags=[_NEEDS_TENANT, "memory", "graph"],
)
async def graph_neighbors_tool(
    *,
    tenant_id: str,
    type: str,
    key: str,
    edge_types: list[str] | None = None,
    depth: int = 1,
    include_global: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    rows = graph_neighbors(
        tenant_id=tenant_id,
        type=type,
        key=key,
        edge_types=edge_types,
        depth=depth,
        include_global=include_global,
        limit=limit,
    )
    return {
        "node": {"type": type, "key": key},
        "neighbors": rows,
    }


@tool(
    name="graph.find_nodes",
    integration="aisoc-memory",
    risk=RiskClass.READ,
    description=(
        "Look up nodes by type and/or a key prefix. Use to find every IOC "
        "starting with '1.2.3.*', list known actors, or enumerate known "
        "assets. Tenancy-scoped unless include_global is set."
    ),
    params={
        "type": "object",
        "properties": {
            "type": {"type": "string"},
            "key_prefix": {"type": "string"},
            "include_global": {"type": "boolean", "default": False},
            "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 200},
        },
    },
    result={
        "type": "object",
        "properties": {
            "count": {"type": "integer"},
            "nodes": {"type": "array", "items": {"type": "object"}},
        },
        "required": ["count", "nodes"],
    },
    tags=[_NEEDS_TENANT, "memory", "graph"],
)
async def graph_find_nodes_tool(
    *,
    tenant_id: str,
    type: str | None = None,
    key_prefix: str | None = None,
    include_global: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    rows = graph_find_nodes(
        tenant_id=tenant_id,
        type=type,
        key_prefix=key_prefix,
        include_global=include_global,
        limit=limit,
    )
    return {"count": len(rows), "nodes": rows}
