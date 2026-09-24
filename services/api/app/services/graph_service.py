"""
Graph service: entity node management, attack-path queries, blast-radius traversal.
AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from app.db.neo4j import get_session

logger = logging.getLogger(__name__)


# ─── Entity Upsert Helpers ────────────────────────────────────────────────────


async def upsert_host(
    host_id: str,
    hostname: str,
    tenant_id: str,
    ip_address: str = "",
    os: str = "",
    criticality: str = "medium",
    extra: dict[str, Any] | None = None,
) -> None:
    """Create or update a Host node."""
    props = {
        "id": host_id,
        "hostname": hostname,
        "tenant_id": tenant_id,
        "ip_address": ip_address,
        "os": os,
        "criticality": criticality,
        "updated_at": datetime.now(UTC).isoformat(),
        **(extra or {}),
    }
    cypher = """
    MERGE (h:Host {id: $id})
    SET h += $props
    RETURN h.id AS node_id
    """
    async with get_session() as s:
        await s.run(cypher, id=host_id, props=props)


async def upsert_user(
    user_id: str,
    username: str,
    tenant_id: str,
    email: str = "",
    department: str = "",
    risk_score: float = 0.0,
) -> None:
    """Create or update a User node."""
    props = {
        "id": user_id,
        "username": username,
        "tenant_id": tenant_id,
        "email": email,
        "department": department,
        "risk_score": risk_score,
        "updated_at": datetime.now(UTC).isoformat(),
    }
    cypher = """
    MERGE (u:User {id: $id})
    SET u += $props
    RETURN u.id AS node_id
    """
    async with get_session() as s:
        await s.run(cypher, id=user_id, props=props)


async def upsert_alert_node(
    alert_id: str,
    tenant_id: str,
    title: str,
    severity: str,
    mitre_techniques: list[str] | None = None,
    host_id: str | None = None,
    user_id: str | None = None,
    ioc_values: list[str] | None = None,
) -> None:
    """Create Alert node and link it to related entities."""
    alert_props = {
        "id": alert_id,
        "tenant_id": tenant_id,
        "title": title,
        "severity": severity,
        "created_at": datetime.now(UTC).isoformat(),
    }

    async with get_session() as s:
        # Upsert Alert node
        await s.run(
            "MERGE (a:Alert {id: $id}) SET a += $props",
            id=alert_id,
            props=alert_props,
        )

        # Link to Host
        if host_id:
            await s.run(
                """
                MATCH (a:Alert {id: $alert_id})
                MERGE (h:Host {id: $host_id})
                MERGE (a)-[:OBSERVED_ON]->(h)
                """,
                alert_id=alert_id,
                host_id=host_id,
            )

        # Link to User
        if user_id:
            await s.run(
                """
                MATCH (a:Alert {id: $alert_id})
                MERGE (u:User {id: $user_id})
                MERGE (a)-[:INVOLVES_USER]->(u)
                """,
                alert_id=alert_id,
                user_id=user_id,
            )

        # Link to MITRE Techniques
        for technique_id in mitre_techniques or []:
            await s.run(
                """
                MATCH (a:Alert {id: $alert_id})
                MERGE (t:Technique {technique_id: $technique_id})
                SET t.updated_at = $ts
                MERGE (a)-[:MAPS_TO]->(t)
                """,
                alert_id=alert_id,
                technique_id=technique_id,
                ts=datetime.now(UTC).isoformat(),
            )

        # Link to IOCs
        for ioc_val in ioc_values or []:
            await s.run(
                """
                MATCH (a:Alert {id: $alert_id})
                MERGE (i:IOC {value: $ioc_val})
                SET i.tenant_id = $tenant_id, i.updated_at = $ts
                MERGE (a)-[:CONTAINS_IOC]->(i)
                """,
                alert_id=alert_id,
                ioc_val=ioc_val,
                tenant_id=tenant_id,
                ts=datetime.now(UTC).isoformat(),
            )


async def upsert_case_node(
    case_id: str,
    tenant_id: str,
    title: str,
    severity: str,
    alert_ids: list[str] | None = None,
) -> None:
    """Create Case node and link it to Alert nodes."""
    case_props = {
        "id": case_id,
        "tenant_id": tenant_id,
        "title": title,
        "severity": severity,
        "created_at": datetime.now(UTC).isoformat(),
    }

    async with get_session() as s:
        await s.run(
            "MERGE (c:Case {id: $id}) SET c += $props",
            id=case_id,
            props=case_props,
        )

        for alert_id in alert_ids or []:
            await s.run(
                """
                MATCH (c:Case {id: $case_id})
                MERGE (a:Alert {id: $alert_id})
                MERGE (c)-[:CONTAINS_ALERT]->(a)
                """,
                case_id=case_id,
                alert_id=alert_id,
            )


async def upsert_ioc(
    value: str,
    ioc_type: str,
    tenant_id: str,
    malicious: bool = False,
    confidence: float = 0.0,
    tags: list[str] | None = None,
) -> None:
    """Create or update an IOC node."""
    props = {
        "value": value,
        "ioc_type": ioc_type,
        "tenant_id": tenant_id,
        "malicious": malicious,
        "confidence": confidence,
        "tags": tags or [],
        "updated_at": datetime.now(UTC).isoformat(),
    }
    async with get_session() as s:
        await s.run(
            "MERGE (i:IOC {value: $value}) SET i += $props",
            value=value,
            props=props,
        )


# ─── Query Helpers ────────────────────────────────────────────────────────────


async def get_attack_path(case_id: str, tenant_id: str, max_depth: int = 6) -> dict[str, Any]:
    """
    Traverse the graph from a Case node to reconstruct the attack path.

    Returns nodes and relationships forming the attack chain:
    Case → Alerts → Hosts/Users → IOCs + Techniques
    """
    cypher = """
    MATCH (c:Case {id: $case_id, tenant_id: $tenant_id})
    CALL apoc.path.subgraphAll(c, {
        maxLevel: $max_depth,
        relationshipFilter: 'CONTAINS_ALERT>|OBSERVED_ON>|INVOLVES_USER>|CONTAINS_IOC>|MAPS_TO>'
    })
    YIELD nodes, relationships
    RETURN
        [n IN nodes | {
            id: coalesce(n.id, n.value, n.technique_id),
            label: labels(n)[0],
            properties: properties(n)
        }] AS nodes,
        [r IN relationships | {
            source: startNode(r).id,
            target: endNode(r).id,
            type: type(r)
        }] AS edges
    """
    async with get_session() as s:
        result = await s.run(cypher, case_id=case_id, tenant_id=tenant_id, max_depth=max_depth)
        record = await result.single()

    if not record:
        # APOC not available – fall back to manual multi-hop query
        return await _attack_path_fallback(case_id, tenant_id)

    return {
        "case_id": case_id,
        "nodes": record["nodes"],
        "edges": record["edges"],
        "node_count": len(record["nodes"]),
        "edge_count": len(record["edges"]),
    }


async def _attack_path_fallback(case_id: str, tenant_id: str) -> dict[str, Any]:
    """Manual attack path traversal when APOC is unavailable."""
    nodes: list[dict] = []
    edges: list[dict] = []

    async with get_session() as s:
        # Get case
        r = await s.run(
            "MATCH (c:Case {id: $id, tenant_id: $tid}) RETURN c",
            id=case_id,
            tid=tenant_id,
        )
        rec = await r.single()
        if not rec:
            return {"case_id": case_id, "nodes": [], "edges": [], "node_count": 0, "edge_count": 0}
        nodes.append({"id": case_id, "label": "Case", "properties": dict(rec["c"])})

        # Alerts
        # Defence in depth: the Case anchor above is already tenant-verified,
        # so these alerts are the tenant's own. Scoping anyway means a
        # mis-tagged CONTAINS_ALERT edge cannot pull in a foreign alert.
        r2 = await s.run(
            """
            MATCH (c:Case {id: $id})-[:CONTAINS_ALERT]->(a:Alert)
            WHERE a.tenant_id = $tid
            RETURN a
            """,
            id=case_id,
            tid=tenant_id,
        )
        alert_ids = []
        async for record in r2:
            a = dict(record["a"])
            nodes.append({"id": a["id"], "label": "Alert", "properties": a})
            edges.append({"source": case_id, "target": a["id"], "type": "CONTAINS_ALERT"})
            alert_ids.append(a["id"])

        # Hosts + Users + IOCs + Techniques linked from alerts
        for aid in alert_ids:
            r3 = await s.run(
                """
                MATCH (a:Alert {id: $aid})-[rel]->(n)
                RETURN n, type(rel) AS rel_type, labels(n)[0] AS label
                """,
                aid=aid,
            )
            async for record in r3:
                n = dict(record["n"])
                node_id = n.get("id") or n.get("value") or n.get("technique_id", "")
                nodes.append({"id": node_id, "label": record["label"], "properties": n})
                edges.append({"source": aid, "target": node_id, "type": record["rel_type"]})

    # Deduplicate nodes by id
    seen: set[str] = set()
    unique_nodes = []
    for node in nodes:
        nid = node["id"]
        if nid not in seen:
            seen.add(nid)
            unique_nodes.append(node)

    return {
        "case_id": case_id,
        "nodes": unique_nodes,
        "edges": edges,
        "node_count": len(unique_nodes),
        "edge_count": len(edges),
    }


#: Labels that are global reference data rather than tenant-owned estate.
#: MITRE techniques are shared by every tenant, so requiring a tenant_id on
#: them would make technique nodes unreachable for everyone.
_GLOBAL_LABELS = ("Technique", "Tactic", "Mitigation")

#: Cypher predicate asserting a node belongs to the querying tenant.
#:
#: `tenant_id IS NULL` is deliberately NOT accepted. An untagged node would
#: otherwise act as a bridge between tenants: a traversal could enter it from
#: tenant A and leave it into tenant B's estate.
#:
#: The Go graph writer MERGEs on `natural_key` alone with `tenant_id` as a
#: property, so shared entities such as a public IP are last-writer-wins. A
#: strict read filter therefore fails closed — safe, never leaking, at the cost
#: of some completeness on shared infrastructure nodes. Re-keying those nodes
#: on `(tenant_id, natural_key)` is the proper fix and needs a migration.
_TENANT_SCOPED = "({var}.tenant_id = $tenant_id OR any(l IN labels({var}) WHERE l IN $global_labels))"


def _scoped(var: str) -> str:
    """Tenant-scoping predicate for one Cypher variable."""
    return _TENANT_SCOPED.format(var=var)


def _is_global(var: str) -> str:
    """Predicate: this node is shared reference data, not tenant estate."""
    return f"any(l IN labels({var}) WHERE l IN $global_labels)"


async def get_blast_radius(entity_id: str, entity_type: str, tenant_id: str, hops: int = 3) -> dict[str, Any]:
    """
    Compute blast radius: all entities reachable from an IOC/Host/User within N hops.
    Used for impact assessment during incident response.
    """
    label_map = {
        "host": "Host",
        "user": "User",
        "ioc": "IOC",
        "alert": "Alert",
    }
    label = label_map.get(entity_type.lower(), "Host")
    id_prop = "value" if label == "IOC" else "id"

    # Every node of every path is scoped, not just the start node. Filtering
    # only `start` let the APOC expansion walk out through a shared entity —
    # a public IP seen by two tenants, for instance — and enumerate the other
    # tenant's hosts and users, returning their full properties. Blast radius
    # is exactly the query an attacker would want for reconnaissance.
    cypher = f"""
    MATCH (start:{label} {{{id_prop}: $entity_id}})
    WHERE {_scoped("start")}
    CALL apoc.path.expandConfig(start, {{
        maxLevel: $hops,
        bfs: true,
        uniqueness: 'NODE_GLOBAL'
    }})
    YIELD path
    WHERE all(pn IN nodes(path) WHERE {_scoped("pn")})
    WITH nodes(path) AS path_nodes, relationships(path) AS path_rels
    UNWIND path_nodes AS n
    WITH COLLECT(DISTINCT {{
        id: coalesce(n.id, n.value, n.technique_id),
        label: labels(n)[0],
        properties: properties(n)
    }}) AS all_nodes
    RETURN all_nodes
    """

    async with get_session() as s:
        result = await s.run(
            cypher,
            entity_id=entity_id,
            tenant_id=tenant_id,
            hops=hops,
            global_labels=list(_GLOBAL_LABELS),
        )
        record = await result.single()

    if not record:
        return await _blast_radius_fallback(entity_id, entity_type, tenant_id, hops)

    all_nodes = record["all_nodes"]
    type_counts: dict[str, int] = {}
    for node in all_nodes:
        lbl = node.get("label", "Unknown")
        type_counts[lbl] = type_counts.get(lbl, 0) + 1

    return {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "hops": hops,
        "affected_nodes": all_nodes,
        "total_affected": len(all_nodes),
        "type_breakdown": type_counts,
        "blast_radius_score": _calc_blast_score(type_counts),
    }


async def _blast_radius_fallback(entity_id: str, entity_type: str, tenant_id: str, hops: int) -> dict[str, Any]:
    """Simple 2-hop blast radius without APOC."""
    label_map = {"host": "Host", "user": "User", "ioc": "IOC", "alert": "Alert"}
    label = label_map.get(entity_type.lower(), "Host")
    id_prop = "value" if label == "IOC" else "id"

    # Scoped the same way as the APOC path above. Previously `start` had no
    # tenant predicate at all, the intermediate nodes of the variable-length
    # path were unchecked, and `tenant_id IS NULL` was accepted on the
    # endpoint — so an untagged node bridged straight into another tenant's
    # estate. Binding the path lets us assert every node on it.
    cypher = f"""
    MATCH (start:{label} {{{id_prop}: $entity_id}})
    WHERE {_scoped("start")}
    MATCH path = (start)-[*1..{hops}]-(n)
    WHERE all(pn IN nodes(path) WHERE {_scoped("pn")})
    RETURN COLLECT(DISTINCT {{
        id: coalesce(n.id, n.value, n.technique_id),
        label: labels(n)[0],
        properties: properties(n)
    }}) AS affected
    """
    async with get_session() as s:
        result = await s.run(
            cypher,
            entity_id=entity_id,
            tenant_id=tenant_id,
            global_labels=list(_GLOBAL_LABELS),
        )
        record = await result.single()

    affected = record["affected"] if record else []
    type_counts: dict[str, int] = {}
    for node in affected:
        lbl = node.get("label", "Unknown")
        type_counts[lbl] = type_counts.get(lbl, 0) + 1

    return {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "hops": hops,
        "affected_nodes": affected,
        "total_affected": len(affected),
        "type_breakdown": type_counts,
        "blast_radius_score": _calc_blast_score(type_counts),
    }


def _calc_blast_score(type_counts: dict[str, int]) -> float:
    """
    Heuristic blast-radius severity score 0–100.
    Weights: Alert=10, Host=5, User=8, IOC=3, Technique=2.
    """
    weights = {"Alert": 10, "Host": 5, "User": 8, "IOC": 3, "Technique": 2}
    raw = sum(weights.get(lbl, 1) * count for lbl, count in type_counts.items())
    return min(round(raw / 10, 1), 100.0)


async def get_entity_neighbors(
    entity_id: str,
    entity_type: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Return immediate neighbors of a node (depth 1)."""
    label_map = {"host": "Host", "user": "User", "ioc": "IOC", "alert": "Alert", "case": "Case"}
    label = label_map.get(entity_type.lower(), "Host")
    id_prop = "value" if label == "IOC" else "id"

    # This function accepted `tenant_id` and never bound or used it: the query
    # had no tenant predicate and the parameter was not even passed to
    # `s.run`. Any authenticated user could read any other tenant's host, user
    # or IOC node and all of its neighbours, with full node properties, just by
    # naming the id. Both the anchor node and each neighbour are now scoped.
    cypher = f"""
    MATCH (n:{label} {{{id_prop}: $entity_id}})
    WHERE {_scoped("n")}
    MATCH (n)-[r]-(neighbor)
    WHERE {_scoped("neighbor")}
    RETURN
        {{id: coalesce(n.id, n.value), label: labels(n)[0], properties: properties(n)}} AS source,
        COLLECT(DISTINCT {{
            id: coalesce(neighbor.id, neighbor.value, neighbor.technique_id),
            label: labels(neighbor)[0],
            rel_type: type(r),
            properties: properties(neighbor)
        }}) AS neighbors
    """
    async with get_session() as s:
        result = await s.run(
            cypher,
            entity_id=entity_id,
            tenant_id=tenant_id,
            global_labels=list(_GLOBAL_LABELS),
        )
        record = await result.single()

    if not record:
        return {"entity_id": entity_id, "entity_type": entity_type, "source": None, "neighbors": []}

    return {
        "entity_id": entity_id,
        "entity_type": entity_type,
        "source": record["source"],
        "neighbors": record["neighbors"],
        "neighbor_count": len(record["neighbors"]),
    }


#: Bounds on one overview response.
#:
#: The console renders this as a force-directed canvas. Past a few hundred
#: nodes the layout pass blocks the browser's main thread and the picture
#: stops being readable, so these are the point at which more data makes the
#: view worse — not a guess about what Neo4j can serve.
OVERVIEW_SEED_LIMIT = 120
OVERVIEW_NODE_LIMIT = 400
OVERVIEW_EDGE_LIMIT = 900

#: Properties that can carry the name an analyst would type into ``?entity=``.
#: Ordered by how specific they are; the first non-null wins.
_ENTITY_MATCH_PROPS = ("natural_key", "id", "hostname", "username", "name", "value", "technique_id")


def _overview_id_expr(var: str) -> str:
    """The business identifier for a node, whichever writer created it.

    The Go ingest writer keys on ``natural_key``; ``graph_service``'s own
    upserts key on ``id``; IOCs key on ``value`` and techniques on
    ``technique_id``. A single coalesce covers all four rather than the
    overview having to know which writer produced a given node.
    """
    return f"coalesce({', '.join(f'{var}.{p}' for p in ('natural_key', 'id', 'value', 'technique_id'))})"


async def get_graph_overview(
    tenant_id: str,
    depth: int = 3,
    entity: str | None = None,
) -> dict[str, Any]:
    """The tenant's entity graph, bounded, for the Attack Graph canvas.

    Two statements rather than one, because the second depends on the first
    having *already* proven every node it returns is in scope:

    1. Seed on the tenant's own nodes, expand up to ``depth`` hops, and keep
       a path only when **every node on it** satisfies the tenant predicate.
       Filtering the start node alone is what let a previous blast-radius
       traversal walk out through a shared entity — a public IP two tenants
       both saw — and enumerate the other tenant's estate. A node with no
       ``tenant_id`` is not readable either: ``_scoped`` does not accept
       null, so an untagged node cannot bridge between two tenants.
    2. Return relationships **only between nodes already in that set**. There
       is no second tenant predicate here and there does not need to be: both
       endpoints were resolved by step 1, so an edge can only exist in the
       answer if both of its ends were independently proven in scope.

    Seeds exclude the global MITRE labels. They are shared by every tenant,
    so seeding on them would start every overview from the same reference
    vocabulary; they remain reachable as neighbours, which is the point of
    the exemption.

    The Go writer ``MERGE``s on ``natural_key`` alone with ``tenant_id`` as a
    property, so a shared entity such as a public IP is last-writer-wins. The
    strict predicate therefore **fails closed** on those nodes — they drop out
    of the overview rather than appearing under the wrong tenant. That is the
    intended trade: completeness on shared infrastructure for never leaking.
    Re-keying on ``(tenant_id, natural_key)`` is the proper fix and needs a
    migration.

    Returns ``{"nodes": [...], "edges": [...], "truncated": bool}``. An empty
    node list means the tenant genuinely has no graph — callers must not
    conflate it with a failed lookup, which raises instead.
    """
    # Interpolated because Cypher does not accept a parameter as a
    # variable-length bound. Coerced and clamped here so the query string can
    # only ever contain an integer, whatever the caller passed.
    hops = max(0, min(int(depth), 6))

    entity_clause = ""
    if entity:
        matches = " OR ".join(f"toLower(toString(seed.{prop})) = toLower($entity)" for prop in _ENTITY_MATCH_PROPS)
        entity_clause = f"AND ({matches})"

    nodes_cypher = f"""
    MATCH (seed)
    WHERE {_scoped("seed")} AND NOT {_is_global("seed")} {entity_clause}
    WITH seed
    ORDER BY coalesce(seed.risk_score, 0) DESC, elementId(seed)
    LIMIT $seed_limit
    MATCH path = (seed)-[*0..{hops}]-(n)
    WHERE all(pn IN nodes(path) WHERE {_scoped("pn")})
    WITH n, min(length(path)) AS hop
    ORDER BY hop ASC, coalesce(n.risk_score, 0) DESC, elementId(n)
    LIMIT $node_limit
    RETURN collect({{
        ref: elementId(n),
        id: {_overview_id_expr("n")},
        labels: labels(n),
        properties: properties(n)
    }}) AS nodes
    """

    # Both endpoints are constrained to `$refs`, which step 1 already proved
    # tenant-scoped. Re-deriving the predicate here would be a second place
    # for it to be got wrong.
    edges_cypher = """
    MATCH (a)-[r]->(b)
    WHERE elementId(a) IN $refs AND elementId(b) IN $refs
    RETURN
        elementId(r) AS ref,
        elementId(a) AS source,
        elementId(b) AS target,
        type(r) AS type,
        properties(r) AS properties
    ORDER BY ref
    LIMIT $edge_limit
    """

    async with get_session() as s:
        node_result = await s.run(
            nodes_cypher,
            tenant_id=tenant_id,
            entity=entity,
            global_labels=list(_GLOBAL_LABELS),
            seed_limit=OVERVIEW_SEED_LIMIT,
            node_limit=OVERVIEW_NODE_LIMIT,
        )
        node_record = await node_result.single()
        nodes = list(node_record["nodes"]) if node_record else []

        edges: list[dict[str, Any]] = []
        if nodes:
            edge_result = await s.run(
                edges_cypher,
                refs=[n["ref"] for n in nodes],
                edge_limit=OVERVIEW_EDGE_LIMIT,
            )
            edges = [dict(record) async for record in edge_result]

    return {
        "nodes": nodes,
        "edges": edges,
        "truncated": len(nodes) >= OVERVIEW_NODE_LIMIT or len(edges) >= OVERVIEW_EDGE_LIMIT,
    }


async def get_mitre_coverage(tenant_id: str) -> list[dict[str, Any]]:
    """Return MITRE ATT&CK technique coverage: alert counts per technique."""
    cypher = """
    MATCH (a:Alert {tenant_id: $tenant_id})-[:MAPS_TO]->(t:Technique)
    RETURN
        t.technique_id AS technique_id,
        t.name AS name,
        t.tactic AS tactic,
        COUNT(a) AS alert_count
    ORDER BY alert_count DESC
    """
    async with get_session() as s:
        result = await s.run(cypher, tenant_id=tenant_id)
        records = await result.data()

    return records
