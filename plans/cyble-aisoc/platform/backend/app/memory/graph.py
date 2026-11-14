"""Threat graph: cross-case entity + relationship store.

Two-tier design, same pattern as :mod:`app.memory.scratchpad` and
:mod:`app.memory.episodic`:

* **SQLite backend** (default) — always works, uses :class:`GraphNode` /
  :class:`GraphEdge` tables.
* **Neo4j backend** — real property graph behind ``bolt://``. Every
  write also mirrors into SQLite so reads still answer if Neo4j is
  unreachable, and so existing SQL-based queries keep working during
  cutover.

Tenancy is enforced at the API boundary: every read and write requires
``tenant_id``. Reads may opt into the shared CTI namespace
(``tenant_id="__global__"``) via ``include_global=True``.

Public API
----------

``graph_upsert_node(tenant_id, type, key, label=..., props=..., tags=...)`` → ``node_id``
``graph_upsert_edge(tenant_id, src=(type,key), dst=(type,key), type, props=...)`` → ``edge_id``
``graph_neighbors(tenant_id, type, key, edge_types=..., depth=1, include_global=False)`` → list of ``(edge, node)`` dicts
``graph_find_nodes(tenant_id, type=..., key_prefix=..., include_global=False)`` → list of node dicts
``graph_backend_name()`` → ``"sqlite"`` or ``"neo4j"``

The public surface returns plain dicts (not ORM rows) so callers don't
need to know which backend served them.
"""
from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any, Iterable, Optional, Protocol

from sqlmodel import select

from app.config import settings
from app.db import session_scope
from app.models.graph import EdgeType, GraphEdge, GraphNode, NodeType

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _coerce_node_type(t: NodeType | str) -> NodeType:
    return t if isinstance(t, NodeType) else NodeType(t)


def _coerce_edge_type(t: EdgeType | str) -> EdgeType:
    return t if isinstance(t, EdgeType) else EdgeType(t)


def _node_to_dict(n: GraphNode) -> dict[str, Any]:
    return {
        "id": n.id,
        "tenant_id": n.tenant_id,
        "type": n.type.value if isinstance(n.type, NodeType) else n.type,
        "key": n.key,
        "label": n.label or n.key,
        "props": dict(n.props or {}),
        "tags": list(n.tags or []),
        "first_seen": n.first_seen.isoformat() if n.first_seen else None,
        "last_seen": n.last_seen.isoformat() if n.last_seen else None,
    }


def _edge_to_dict(e: GraphEdge) -> dict[str, Any]:
    return {
        "id": e.id,
        "tenant_id": e.tenant_id,
        "src_id": e.src_id,
        "dst_id": e.dst_id,
        "type": e.type.value if isinstance(e.type, EdgeType) else e.type,
        "weight": e.weight,
        "props": dict(e.props or {}),
        "first_seen": e.first_seen.isoformat() if e.first_seen else None,
        "last_seen": e.last_seen.isoformat() if e.last_seen else None,
    }


# ---------------------------------------------------------------------------
# backend protocol
# ---------------------------------------------------------------------------


class _Backend(Protocol):
    name: str

    def upsert_node(
        self,
        *,
        tenant_id: str,
        type: NodeType,
        key: str,
        label: str,
        props: dict[str, Any],
        tags: list[str],
    ) -> int: ...

    def upsert_edge(
        self,
        *,
        tenant_id: str,
        src_type: NodeType,
        src_key: str,
        dst_type: NodeType,
        dst_key: str,
        type: EdgeType,
        weight: float,
        props: dict[str, Any],
    ) -> int: ...

    def neighbors(
        self,
        *,
        tenant_id: str,
        type: NodeType,
        key: str,
        edge_types: Optional[list[EdgeType]],
        depth: int,
        include_global: bool,
        limit: int,
    ) -> list[dict[str, Any]]: ...

    def find_nodes(
        self,
        *,
        tenant_id: str,
        type: Optional[NodeType],
        key_prefix: Optional[str],
        include_global: bool,
        limit: int,
    ) -> list[dict[str, Any]]: ...


# ---------------------------------------------------------------------------
# SQLite backend (default, always works)
# ---------------------------------------------------------------------------


class _SQLiteBackend:
    """SQLModel-backed graph. The canonical source of truth.

    The Neo4j backend also calls into this one to mirror writes so reads
    keep working if the graph DB goes down.
    """

    name = "sqlite"

    def _tenant_scope(self, tenant_id: str, include_global: bool) -> tuple[str, ...]:
        if include_global and tenant_id != "__global__":
            return (tenant_id, "__global__")
        return (tenant_id,)

    def upsert_node(
        self,
        *,
        tenant_id: str,
        type: NodeType,
        key: str,
        label: str,
        props: dict[str, Any],
        tags: list[str],
    ) -> int:
        with session_scope() as s:
            existing = s.exec(
                select(GraphNode).where(
                    GraphNode.tenant_id == tenant_id,
                    GraphNode.type == type,
                    GraphNode.key == key,
                )
            ).first()
            now = _now()
            if existing is not None:
                # Merge: keep first_seen, advance last_seen, union tags, shallow-merge props.
                existing.last_seen = now
                if label and not existing.label:
                    existing.label = label
                if props:
                    merged = dict(existing.props or {})
                    merged.update(props)
                    existing.props = merged
                if tags:
                    existing.tags = sorted(set((existing.tags or []) + tags))
                s.add(existing)
                s.flush()
                assert existing.id is not None
                return existing.id
            node = GraphNode(
                tenant_id=tenant_id,
                type=type,
                key=key,
                label=label or key,
                props=dict(props or {}),
                tags=list(tags or []),
                first_seen=now,
                last_seen=now,
            )
            s.add(node)
            s.flush()
            assert node.id is not None
            return node.id

    def _get_node_id(
        self, s, tenant_id: str, type: NodeType, key: str
    ) -> Optional[int]:
        row = s.exec(
            select(GraphNode.id).where(
                GraphNode.tenant_id == tenant_id,
                GraphNode.type == type,
                GraphNode.key == key,
            )
        ).first()
        return row

    def upsert_edge(
        self,
        *,
        tenant_id: str,
        src_type: NodeType,
        src_key: str,
        dst_type: NodeType,
        dst_key: str,
        type: EdgeType,
        weight: float,
        props: dict[str, Any],
    ) -> int:
        # Make sure both endpoints exist (auto-create skeletal nodes).
        self.upsert_node(
            tenant_id=tenant_id, type=src_type, key=src_key,
            label=src_key, props={}, tags=[],
        )
        self.upsert_node(
            tenant_id=tenant_id, type=dst_type, key=dst_key,
            label=dst_key, props={}, tags=[],
        )
        with session_scope() as s:
            src_id = self._get_node_id(s, tenant_id, src_type, src_key)
            dst_id = self._get_node_id(s, tenant_id, dst_type, dst_key)
            assert src_id is not None and dst_id is not None
            existing = s.exec(
                select(GraphEdge).where(
                    GraphEdge.tenant_id == tenant_id,
                    GraphEdge.src_id == src_id,
                    GraphEdge.dst_id == dst_id,
                    GraphEdge.type == type,
                )
            ).first()
            now = _now()
            if existing is not None:
                existing.last_seen = now
                existing.weight = max(existing.weight, weight)
                if props:
                    merged = dict(existing.props or {})
                    merged.update(props)
                    existing.props = merged
                s.add(existing)
                s.flush()
                assert existing.id is not None
                return existing.id
            edge = GraphEdge(
                tenant_id=tenant_id,
                src_id=src_id,
                dst_id=dst_id,
                type=type,
                weight=weight,
                props=dict(props or {}),
                first_seen=now,
                last_seen=now,
            )
            s.add(edge)
            s.flush()
            assert edge.id is not None
            return edge.id

    def neighbors(
        self,
        *,
        tenant_id: str,
        type: NodeType,
        key: str,
        edge_types: Optional[list[EdgeType]],
        depth: int,
        include_global: bool,
        limit: int,
    ) -> list[dict[str, Any]]:
        scope = self._tenant_scope(tenant_id, include_global)
        depth = max(1, min(depth, 4))  # bound BFS for safety
        with session_scope() as s:
            # Locate the seed node(s) by (tenant_scope, type, key).
            seeds = s.exec(
                select(GraphNode).where(
                    GraphNode.tenant_id.in_(scope),  # type: ignore[attr-defined]
                    GraphNode.type == type,
                    GraphNode.key == key,
                )
            ).all()
            if not seeds:
                return []
            seed_ids = {n.id for n in seeds if n.id is not None}
            visited: set[int] = set(seed_ids)
            results: list[dict[str, Any]] = []
            frontier: deque[tuple[int, int]] = deque((sid, 0) for sid in seed_ids)
            while frontier and len(results) < limit:
                node_id, hop = frontier.popleft()
                if hop >= depth:
                    continue
                # Outgoing edges from node_id.
                edge_q = select(GraphEdge).where(
                    GraphEdge.tenant_id.in_(scope),  # type: ignore[attr-defined]
                    GraphEdge.src_id == node_id,
                )
                if edge_types:
                    edge_q = edge_q.where(GraphEdge.type.in_(edge_types))  # type: ignore[attr-defined]
                edges = s.exec(edge_q).all()
                for e in edges:
                    if len(results) >= limit:
                        break
                    nbr = s.get(GraphNode, e.dst_id)
                    if nbr is None:
                        continue
                    results.append({
                        "edge": _edge_to_dict(e),
                        "node": _node_to_dict(nbr),
                        "hop": hop + 1,
                        "direction": "out",
                    })
                    if e.dst_id not in visited:
                        visited.add(e.dst_id)
                        frontier.append((e.dst_id, hop + 1))
                # Incoming edges into node_id (treat as undirected traversal for
                # "what else relates to X").
                in_q = select(GraphEdge).where(
                    GraphEdge.tenant_id.in_(scope),  # type: ignore[attr-defined]
                    GraphEdge.dst_id == node_id,
                )
                if edge_types:
                    in_q = in_q.where(GraphEdge.type.in_(edge_types))  # type: ignore[attr-defined]
                in_edges = s.exec(in_q).all()
                for e in in_edges:
                    if len(results) >= limit:
                        break
                    nbr = s.get(GraphNode, e.src_id)
                    if nbr is None:
                        continue
                    results.append({
                        "edge": _edge_to_dict(e),
                        "node": _node_to_dict(nbr),
                        "hop": hop + 1,
                        "direction": "in",
                    })
                    if e.src_id not in visited:
                        visited.add(e.src_id)
                        frontier.append((e.src_id, hop + 1))
            return results

    def find_nodes(
        self,
        *,
        tenant_id: str,
        type: Optional[NodeType],
        key_prefix: Optional[str],
        include_global: bool,
        limit: int,
    ) -> list[dict[str, Any]]:
        scope = self._tenant_scope(tenant_id, include_global)
        with session_scope() as s:
            q = select(GraphNode).where(
                GraphNode.tenant_id.in_(scope)  # type: ignore[attr-defined]
            )
            if type is not None:
                q = q.where(GraphNode.type == type)
            if key_prefix:
                q = q.where(GraphNode.key.like(f"{key_prefix}%"))  # type: ignore[attr-defined]
            q = q.limit(limit)
            return [_node_to_dict(n) for n in s.exec(q).all()]


# ---------------------------------------------------------------------------
# Neo4j backend (optional)
# ---------------------------------------------------------------------------


class _Neo4jBackend:
    """Neo4j-backed graph with SQLite mirror.

    Every write goes to Neo4j *and* the SQLite mirror so reads still
    work if Neo4j is unreachable. Reads prefer Neo4j; we only fall
    back to SQLite if the Neo4j call raises.

    Property maps are stored as flat key/value where values are JSON
    primitives — Neo4j doesn't accept nested maps as properties, so we
    serialize complex values into ``props_json`` (a string).
    """

    name = "neo4j"

    def __init__(self, driver: Any) -> None:
        self._driver = driver
        self._mirror = _SQLiteBackend()

    # ----- helpers ----------------------------------------------------------

    @staticmethod
    def _flatten_props(props: dict[str, Any]) -> dict[str, Any]:
        """Neo4j only stores primitives + arrays of primitives.

        Anything else gets shoved into ``props_json`` as a JSON string so
        we never lose data on the round-trip.
        """
        import json as _json

        flat: dict[str, Any] = {}
        complex_keys: dict[str, Any] = {}
        for k, v in (props or {}).items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                flat[k] = v
            elif isinstance(v, list) and all(
                isinstance(x, (str, int, float, bool)) for x in v
            ):
                flat[k] = v
            else:
                complex_keys[k] = v
        if complex_keys:
            flat["props_json"] = _json.dumps(complex_keys, default=str)
        return flat

    def _tenant_scope(self, tenant_id: str, include_global: bool) -> list[str]:
        return (
            [tenant_id, "__global__"]
            if include_global and tenant_id != "__global__"
            else [tenant_id]
        )

    # ----- writes -----------------------------------------------------------

    def upsert_node(
        self,
        *,
        tenant_id: str,
        type: NodeType,
        key: str,
        label: str,
        props: dict[str, Any],
        tags: list[str],
    ) -> int:
        # Mirror first so we get the SQL id (also keeps SQL durable).
        node_id = self._mirror.upsert_node(
            tenant_id=tenant_id, type=type, key=key,
            label=label, props=props, tags=tags,
        )
        # Write to Neo4j: MERGE on the natural key (tenant_id, type, key).
        # We label nodes with their type so Cypher queries can match by label.
        flat = self._flatten_props(props or {})
        try:
            with self._driver.session() as session:
                # Cypher labels can't be parameterised, so we whitelist via the enum.
                cypher = (
                    f"MERGE (n:{type.value} {{tenant_id: $tenant_id, key: $key}}) "
                    "SET n.label = coalesce($label, n.label, $key), "
                    "    n.tags = $tags, "
                    "    n.sql_id = $sql_id, "
                    "    n.last_seen = datetime(), "
                    "    n += $props "
                    "RETURN id(n) AS id"
                )
                session.run(
                    cypher,
                    tenant_id=tenant_id,
                    key=key,
                    label=label or key,
                    tags=list(tags or []),
                    sql_id=node_id,
                    props=flat,
                )
        except Exception as exc:  # pragma: no cover - depends on live DB
            log.warning("neo4j upsert_node failed (%s); SQL mirror only", exc)
        return node_id

    def upsert_edge(
        self,
        *,
        tenant_id: str,
        src_type: NodeType,
        src_key: str,
        dst_type: NodeType,
        dst_key: str,
        type: EdgeType,
        weight: float,
        props: dict[str, Any],
    ) -> int:
        edge_id = self._mirror.upsert_edge(
            tenant_id=tenant_id,
            src_type=src_type, src_key=src_key,
            dst_type=dst_type, dst_key=dst_key,
            type=type, weight=weight, props=props,
        )
        flat = self._flatten_props(props or {})
        try:
            with self._driver.session() as session:
                cypher = (
                    f"MATCH (s:{src_type.value} {{tenant_id: $tenant_id, key: $src_key}}) "
                    f"MATCH (d:{dst_type.value} {{tenant_id: $tenant_id, key: $dst_key}}) "
                    f"MERGE (s)-[r:{type.value} {{tenant_id: $tenant_id}}]->(d) "
                    "SET r.weight = coalesce($weight, r.weight, 1.0), "
                    "    r.sql_id = $sql_id, "
                    "    r.last_seen = datetime(), "
                    "    r += $props "
                    "RETURN id(r) AS id"
                )
                session.run(
                    cypher,
                    tenant_id=tenant_id,
                    src_key=src_key,
                    dst_key=dst_key,
                    weight=weight,
                    sql_id=edge_id,
                    props=flat,
                )
        except Exception as exc:  # pragma: no cover - depends on live DB
            log.warning("neo4j upsert_edge failed (%s); SQL mirror only", exc)
        return edge_id

    # ----- reads ------------------------------------------------------------

    def neighbors(
        self,
        *,
        tenant_id: str,
        type: NodeType,
        key: str,
        edge_types: Optional[list[EdgeType]],
        depth: int,
        include_global: bool,
        limit: int,
    ) -> list[dict[str, Any]]:
        scope = self._tenant_scope(tenant_id, include_global)
        depth = max(1, min(depth, 4))
        try:
            with self._driver.session() as session:
                # Build a variable-length pattern with optional edge-type filter.
                rel_filter = (
                    "|".join(t.value for t in edge_types) if edge_types else ""
                )
                rel_pattern = f":{rel_filter}" if rel_filter else ""
                cypher = (
                    f"MATCH (s:{type.value} {{key: $key}}) "
                    "WHERE s.tenant_id IN $scope "
                    f"MATCH (s)-[r{rel_pattern}*1..{depth}]-(n) "
                    "WHERE n.tenant_id IN $scope "
                    "RETURN DISTINCT n, last(r) AS edge, length(r) AS hop "
                    "LIMIT $limit"
                )
                rows = session.run(
                    cypher, key=key, scope=scope, limit=limit
                ).data()
                out: list[dict[str, Any]] = []
                for row in rows:
                    n = row.get("n", {})
                    e = row.get("edge", {})
                    out.append({
                        "node": {
                            "id": n.get("sql_id"),
                            "tenant_id": n.get("tenant_id"),
                            "type": list(n.labels)[0] if hasattr(n, "labels") else None,
                            "key": n.get("key"),
                            "label": n.get("label") or n.get("key"),
                            "props": dict(n),
                            "tags": n.get("tags") or [],
                        },
                        "edge": {
                            "id": e.get("sql_id"),
                            "tenant_id": e.get("tenant_id"),
                            "type": e.type if hasattr(e, "type") else None,
                            "weight": e.get("weight", 1.0),
                            "props": dict(e),
                        },
                        "hop": row.get("hop"),
                        "direction": "any",
                    })
                if out:
                    return out
        except Exception as exc:  # pragma: no cover
            log.warning("neo4j neighbors failed (%s); falling back to SQL mirror", exc)
        return self._mirror.neighbors(
            tenant_id=tenant_id, type=type, key=key,
            edge_types=edge_types, depth=depth,
            include_global=include_global, limit=limit,
        )

    def find_nodes(
        self,
        *,
        tenant_id: str,
        type: Optional[NodeType],
        key_prefix: Optional[str],
        include_global: bool,
        limit: int,
    ) -> list[dict[str, Any]]:
        # For find_nodes we just lean on the SQL mirror — it's faster for
        # prefix scans and keeps the result shape consistent.
        return self._mirror.find_nodes(
            tenant_id=tenant_id, type=type, key_prefix=key_prefix,
            include_global=include_global, limit=limit,
        )


# ---------------------------------------------------------------------------
# backend resolution (lazy + thread-safe)
# ---------------------------------------------------------------------------

_BACKEND: Optional[_Backend] = None
_LOCK = threading.Lock()


def _build_neo4j_backend() -> Optional[_Neo4jBackend]:
    if not settings.neo4j_uri:
        log.info("graph_backend=neo4j but neo4j_uri not configured; using SQLite")
        return None
    try:
        from neo4j import GraphDatabase  # type: ignore
    except ImportError:
        log.warning("graph_backend=neo4j but `neo4j` driver not installed; using SQLite")
        return None
    auth = None
    if settings.neo4j_user and settings.neo4j_password:
        auth = (settings.neo4j_user, settings.neo4j_password)
    try:
        driver = GraphDatabase.driver(settings.neo4j_uri, auth=auth)
        # Cheap connectivity check — fail fast if the DB is unreachable.
        driver.verify_connectivity()
        log.info("graph backend connected: neo4j @ %s", settings.neo4j_uri)
        return _Neo4jBackend(driver)
    except Exception as exc:
        log.warning(
            "neo4j unreachable at %s (%s); using SQLite mirror as primary",
            settings.neo4j_uri, exc,
        )
        return None


def _resolve_backend() -> _Backend:
    global _BACKEND
    if _BACKEND is not None:
        return _BACKEND
    with _LOCK:
        if _BACKEND is not None:
            return _BACKEND
        choice = (settings.graph_backend or "sqlite").lower()
        if choice == "neo4j":
            built = _build_neo4j_backend()
            _BACKEND = built or _SQLiteBackend()
        else:
            _BACKEND = _SQLiteBackend()
        log.info("graph backend resolved: %s", _BACKEND.name)
        return _BACKEND


def _reset_for_tests() -> None:
    """Drop the cached backend so the next call re-resolves from settings.

    Tests use this after they mutate ``settings.graph_backend`` or env vars.
    """
    global _BACKEND
    with _LOCK:
        _BACKEND = None


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


def graph_backend_name() -> str:
    return _resolve_backend().name


def graph_upsert_node(
    *,
    tenant_id: str,
    type: NodeType | str,
    key: str,
    label: str = "",
    props: Optional[dict[str, Any]] = None,
    tags: Optional[Iterable[str]] = None,
) -> int:
    """Idempotently add or update an entity node.

    Returns the SQL-side ``node_id`` (stable across mirror writes).
    """
    return _resolve_backend().upsert_node(
        tenant_id=tenant_id,
        type=_coerce_node_type(type),
        key=key,
        label=label,
        props=dict(props or {}),
        tags=list(tags or []),
    )


def graph_upsert_edge(
    *,
    tenant_id: str,
    src: tuple[NodeType | str, str],
    dst: tuple[NodeType | str, str],
    type: EdgeType | str,
    weight: float = 1.0,
    props: Optional[dict[str, Any]] = None,
) -> int:
    """Idempotently add or update a typed relationship.

    Auto-creates the endpoint nodes if they don't exist yet.
    """
    src_type, src_key = src
    dst_type, dst_key = dst
    return _resolve_backend().upsert_edge(
        tenant_id=tenant_id,
        src_type=_coerce_node_type(src_type),
        src_key=src_key,
        dst_type=_coerce_node_type(dst_type),
        dst_key=dst_key,
        type=_coerce_edge_type(type),
        weight=weight,
        props=dict(props or {}),
    )


def graph_neighbors(
    *,
    tenant_id: str,
    type: NodeType | str,
    key: str,
    edge_types: Optional[Iterable[EdgeType | str]] = None,
    depth: int = 1,
    include_global: bool = False,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Return neighbours within ``depth`` hops of ``(type, key)``.

    Each result is ``{"node": {...}, "edge": {...}, "hop": int, "direction": str}``.
    Set ``include_global=True`` to also traverse the shared CTI graph
    (``tenant_id="__global__"``).
    """
    etypes = (
        [_coerce_edge_type(t) for t in edge_types] if edge_types else None
    )
    return _resolve_backend().neighbors(
        tenant_id=tenant_id,
        type=_coerce_node_type(type),
        key=key,
        edge_types=etypes,
        depth=depth,
        include_global=include_global,
        limit=limit,
    )


def graph_find_nodes(
    *,
    tenant_id: str,
    type: Optional[NodeType | str] = None,
    key_prefix: Optional[str] = None,
    include_global: bool = False,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Look up nodes by ``type`` and/or a ``key`` prefix.

    Tenancy-scoped. Useful for "find every IOC starting with 1.2.3.*"
    or "list every actor we know about".
    """
    return _resolve_backend().find_nodes(
        tenant_id=tenant_id,
        type=_coerce_node_type(type) if type is not None else None,
        key_prefix=key_prefix,
        include_global=include_global,
        limit=limit,
    )
