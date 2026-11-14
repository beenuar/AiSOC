"""Auto-populate the threat graph from alerts and IOCs (t1m-autopop).

Ingestion points (``app.api.routes.ingest_alert``, ``app.seed.seed_if_empty``,
the various Cyble-native pulls) currently only persist rows to SQL. The
threat graph stayed empty until an agent explicitly upserted into it —
which meant cross-case pivots ("show me everything that talked to this
C2", "what other assets has this user touched?") only worked once a
human walked the graph by hand.

This module closes that gap by translating raw ingest payloads into
``GraphNode`` / ``GraphEdge`` upserts. It is deliberately:

* **Best-effort** — wrapping each upsert in ``try/except`` so a graph
  backend hiccup (Neo4j down, SQLite locked, malformed field) can never
  break the user-visible ingestion path.
* **Idempotent** — backed by ``graph_upsert_node`` /
  ``graph_upsert_edge`` which use ``(tenant_id, type, key)`` and
  ``(tenant_id, src_id, dst_id, type)`` as primary identity.
* **Tenant-strict** — every upsert carries the alert's / IOC's
  ``tenant_id``. Nothing here writes to ``__global__``; CTI feeds with
  their own global facts use a separate path.

Public API
----------

``populate_from_alert(alert)`` → ``dict`` summary of what was upserted.
``populate_from_ioc(ioc)`` → ``dict`` summary of what was upserted.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Iterable, Optional

from app.memory.graph import graph_upsert_edge, graph_upsert_node
from app.models.alert import Alert
from app.models.graph import EdgeType, NodeType
from app.models.ioc import IOC, IOCType

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# heuristics
# ---------------------------------------------------------------------------

# Hash length → IOCType. Used when the alert payload only carries a raw
# hex string in ``file_hash`` and we have to guess the algorithm.
_HASH_LEN_TO_TYPE: dict[int, IOCType] = {
    32: IOCType.HASH_MD5,
    40: IOCType.HASH_SHA1,
    64: IOCType.HASH_SHA256,
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _classify_hash(value: str) -> Optional[IOCType]:
    v = (value or "").strip()
    if not v or not _HEX_RE.match(v):
        return None
    return _HASH_LEN_TO_TYPE.get(len(v))


def _ioc_key(ioc_type: IOCType | str, value: str) -> str:
    """Build the canonical IOC node key, ``"<ioc_type>:<value>"``."""
    t = ioc_type.value if isinstance(ioc_type, IOCType) else str(ioc_type)
    return f"{t}:{value}"


def _safe_upsert_node(**kwargs: Any) -> Optional[int]:
    """Upsert a node, swallowing failures so ingestion never breaks."""
    try:
        return graph_upsert_node(**kwargs)
    except Exception as e:  # noqa: BLE001
        log.warning("graph autopop: upsert_node failed: %s (%s)", e, kwargs.get("key"))
        return None


def _safe_upsert_edge(**kwargs: Any) -> Optional[int]:
    """Upsert an edge, swallowing failures so ingestion never breaks."""
    try:
        return graph_upsert_edge(**kwargs)
    except Exception as e:  # noqa: BLE001
        log.warning(
            "graph autopop: upsert_edge failed: %s (src=%s dst=%s type=%s)",
            e,
            kwargs.get("src"),
            kwargs.get("dst"),
            kwargs.get("type"),
        )
        return None


# ---------------------------------------------------------------------------
# IOC → graph
# ---------------------------------------------------------------------------


def populate_from_ioc(ioc: IOC) -> dict[str, Any]:
    """Mirror a freshly ingested :class:`IOC` row into the threat graph.

    Produces a single ``NodeType.IOC`` node. Tags carry the IOC's own
    tags plus its ``sources`` so downstream queries like "everything
    Cyble-native" or "everything from ransomwatch" stay one filter away.

    Returns a small summary dict useful for tests and audit logging.
    """
    out: dict[str, Any] = {"nodes": [], "errors": []}
    if not ioc or not ioc.value:
        return out

    tags: list[str] = []
    tags.extend(ioc.tags or [])
    tags.extend(f"src:{s}" for s in (ioc.sources or []))
    if ioc.cyble_native:
        tags.append("cyble_native")

    props: dict[str, Any] = {
        "threat_score": int(ioc.threat_score or 0),
        "confidence": float(ioc.confidence or 0.0),
        "sources": list(ioc.sources or []),
        "ioc_type": ioc.type.value if isinstance(ioc.type, IOCType) else str(ioc.type),
    }
    if ioc.description:
        props["description"] = ioc.description

    node_id = _safe_upsert_node(
        tenant_id=ioc.tenant_id,
        type=NodeType.IOC,
        key=_ioc_key(ioc.type, ioc.value),
        label=ioc.value,
        props=props,
        tags=tags,
    )
    if node_id is None:
        out["errors"].append({"kind": "ioc_node", "value": ioc.value})
    else:
        out["nodes"].append({"id": node_id, "type": "ioc", "key": _ioc_key(ioc.type, ioc.value)})
    return out


# ---------------------------------------------------------------------------
# Alert → graph
# ---------------------------------------------------------------------------


def _add_node(
    summary: dict[str, Any],
    *,
    tenant_id: str,
    type: NodeType,
    key: str,
    label: str = "",
    props: Optional[dict[str, Any]] = None,
    tags: Optional[Iterable[str]] = None,
) -> Optional[tuple[NodeType, str]]:
    node_id = _safe_upsert_node(
        tenant_id=tenant_id,
        type=type,
        key=key,
        label=label or key,
        props=props or {},
        tags=list(tags or []),
    )
    if node_id is None:
        summary["errors"].append({"kind": f"{type.value}_node", "key": key})
        return None
    summary["nodes"].append({"id": node_id, "type": type.value, "key": key})
    return (type, key)


def _add_edge(
    summary: dict[str, Any],
    *,
    tenant_id: str,
    src: tuple[NodeType, str],
    dst: tuple[NodeType, str],
    type: EdgeType,
    weight: float = 1.0,
    props: Optional[dict[str, Any]] = None,
) -> None:
    edge_id = _safe_upsert_edge(
        tenant_id=tenant_id,
        src=src,
        dst=dst,
        type=type,
        weight=weight,
        props=props or {},
    )
    if edge_id is None:
        summary["errors"].append(
            {"kind": "edge", "src": src[1], "dst": dst[1], "type": type.value}
        )
    else:
        summary["edges"].append(
            {"id": edge_id, "src": src[1], "dst": dst[1], "type": type.value}
        )


def populate_from_alert(alert: Alert) -> dict[str, Any]:
    """Translate an alert into graph nodes + edges.

    Mapping (only present fields create nodes/edges):

    * ``case_id``       → ``case`` node (the investigation anchor)
    * ``src_host``      → ``asset`` node
    * ``src_user``      → ``user`` node, and ``asset --authenticated_as--> user``
    * ``src_ip``        → ``ioc(ip:<value>)`` node, ``ioc --observed_on--> asset``
    * ``dst_ip``        → ``ioc(ip:<value>)`` node, ``asset --communicates_with--> ioc``
    * ``file_hash``     → ``ioc(<md5|sha1|sha256>:<value>)`` node, ``ioc --observed_on--> asset``
    * ``process_name``  → ``tool`` node, ``tool --observed_on--> asset``
    * each mitre technique → ``technique`` node, ``case --part_of--> technique`` (proxy for "case
      involves technique"; PART_OF is the closest available verb without
      polluting the small edge set)

    Every entity that was created is also linked to the case via
    ``involved_in`` so a single ``graph_neighbors(case)`` query rebuilds
    the alert's blast radius.

    Best-effort: any single upsert failure is logged and recorded in the
    ``errors`` list but never raised.
    """
    summary: dict[str, Any] = {"nodes": [], "edges": [], "errors": []}
    if alert is None:
        return summary

    tenant_id = alert.tenant_id

    # The case node anchors every other node back to the investigation.
    case_node: Optional[tuple[NodeType, str]] = None
    if alert.case_id is not None:
        case_node = _add_node(
            summary,
            tenant_id=tenant_id,
            type=NodeType.CASE,
            key=str(alert.case_id),
            label=alert.title or f"case-{alert.case_id}",
            props={
                "severity": alert.severity,
                "source": alert.source,
                "detection_rule": alert.detection_rule,
            },
            tags=["alert"],
        )

    # asset = src_host
    asset_node: Optional[tuple[NodeType, str]] = None
    if alert.src_host:
        asset_node = _add_node(
            summary,
            tenant_id=tenant_id,
            type=NodeType.ASSET,
            key=alert.src_host,
            label=alert.src_host,
            tags=["alert_source"],
        )

    # user = src_user
    user_node: Optional[tuple[NodeType, str]] = None
    if alert.src_user:
        user_node = _add_node(
            summary,
            tenant_id=tenant_id,
            type=NodeType.USER,
            key=alert.src_user,
            label=alert.src_user,
            tags=["alert_source"],
        )
        if asset_node:
            _add_edge(
                summary,
                tenant_id=tenant_id,
                src=asset_node,
                dst=user_node,
                type=EdgeType.AUTHENTICATED_AS,
            )

    # src_ip → IOC observed_on asset
    if alert.src_ip:
        src_ip_node = _add_node(
            summary,
            tenant_id=tenant_id,
            type=NodeType.IOC,
            key=_ioc_key(IOCType.IP, alert.src_ip),
            label=alert.src_ip,
            props={"ioc_type": "ip", "role": "src"},
            tags=["from_alert"],
        )
        if src_ip_node and asset_node:
            _add_edge(
                summary,
                tenant_id=tenant_id,
                src=src_ip_node,
                dst=asset_node,
                type=EdgeType.OBSERVED_ON,
            )

    # dst_ip → asset communicates_with IOC
    if alert.dst_ip:
        dst_ip_node = _add_node(
            summary,
            tenant_id=tenant_id,
            type=NodeType.IOC,
            key=_ioc_key(IOCType.IP, alert.dst_ip),
            label=alert.dst_ip,
            props={"ioc_type": "ip", "role": "dst"},
            tags=["from_alert", "c2_candidate"],
        )
        if dst_ip_node and asset_node:
            _add_edge(
                summary,
                tenant_id=tenant_id,
                src=asset_node,
                dst=dst_ip_node,
                type=EdgeType.COMMUNICATES_WITH,
            )

    # file_hash → IOC observed_on asset
    if alert.file_hash:
        hash_kind = _classify_hash(alert.file_hash) or IOCType.HASH_SHA256
        hash_node = _add_node(
            summary,
            tenant_id=tenant_id,
            type=NodeType.IOC,
            key=_ioc_key(hash_kind, alert.file_hash),
            label=alert.file_hash[:12] + ("…" if len(alert.file_hash) > 12 else ""),
            props={"ioc_type": hash_kind.value},
            tags=["from_alert", "file_hash"],
        )
        if hash_node and asset_node:
            _add_edge(
                summary,
                tenant_id=tenant_id,
                src=hash_node,
                dst=asset_node,
                type=EdgeType.OBSERVED_ON,
            )

    # process_name → tool observed_on asset
    if alert.process_name:
        tool_node = _add_node(
            summary,
            tenant_id=tenant_id,
            type=NodeType.TOOL,
            key=alert.process_name,
            label=alert.process_name,
            tags=["from_alert"],
        )
        if tool_node and asset_node:
            _add_edge(
                summary,
                tenant_id=tenant_id,
                src=tool_node,
                dst=asset_node,
                type=EdgeType.OBSERVED_ON,
            )

    # mitre techniques → technique nodes, linked to the case
    for technique_id in alert.mitre_techniques or []:
        if not technique_id:
            continue
        tech_node = _add_node(
            summary,
            tenant_id=tenant_id,
            type=NodeType.TECHNIQUE,
            key=technique_id,
            label=technique_id,
            tags=["mitre"],
        )
        if tech_node and case_node:
            # PART_OF is the closest verb we have for "this case observed
            # this technique"; INVOLVED_IN runs the other direction.
            _add_edge(
                summary,
                tenant_id=tenant_id,
                src=tech_node,
                dst=case_node,
                type=EdgeType.PART_OF,
            )

    # Link every entity we touched back to the case via INVOLVED_IN so
    # `graph_neighbors(case)` rebuilds the alert's blast radius.
    if case_node:
        for entity in (asset_node, user_node):
            if entity:
                _add_edge(
                    summary,
                    tenant_id=tenant_id,
                    src=entity,
                    dst=case_node,
                    type=EdgeType.INVOLVED_IN,
                )
        # Also pull the IOCs/tool into the case so the case neighbour
        # query is one hop, not two. We re-derive them from `summary`
        # so we don't duplicate the key-construction logic above.
        for n in summary["nodes"]:
            ntype = n["type"]
            nkey = n["key"]
            if ntype in (NodeType.IOC.value, NodeType.TOOL.value):
                _add_edge(
                    summary,
                    tenant_id=tenant_id,
                    src=(NodeType(ntype), nkey),
                    dst=case_node,
                    type=EdgeType.INVOLVED_IN,
                )

    return summary
