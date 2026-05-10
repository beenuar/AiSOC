"""
Graph API endpoints: attack paths, blast radius, entity neighbors, MITRE coverage.
AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import CurrentUser, DBSession, get_current_user
from app.services import graph_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/graph", tags=["graph"])


# ─── Graph backend availability ───────────────────────────────────────────────
#
# In the public demo (and in any deployment without a Neo4j sidecar) the
# knowledge graph backend is unreachable. Rather than 503-ing the whole
# Attack Path UI in that scenario, we detect connection-class errors and fall
# back to a relational reconstruction built from the case row itself
# (alert_ids + mitre_techniques). This keeps the Attack Path tab functional
# in demos while still surfacing the rich Neo4j path when one is configured.

_GRAPH_OFFLINE_MARKERS: tuple[str, ...] = (
    "ServiceUnavailable",
    "AuthError",
    "Couldn't connect",
    "Connect call failed",
    "Connection refused",
    "Name or service not known",
    "getaddrinfo",
    "Cannot resolve address",
)


def _is_graph_unavailable(exc: BaseException) -> bool:
    """Heuristic: did the failure come from the Neo4j driver being offline?"""
    cls = type(exc).__name__
    if cls in {"ServiceUnavailable", "AuthError", "ConfigurationError"}:
        return True
    msg = str(exc)
    return any(marker in msg for marker in _GRAPH_OFFLINE_MARKERS)


# ─── Request / Response Schemas ───────────────────────────────────────────────


class GraphNode(BaseModel):
    id: str
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    type: str


class AttackPathResponse(BaseModel):
    case_id: str
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    node_count: int
    edge_count: int


class BlastRadiusResponse(BaseModel):
    entity_id: str
    entity_type: str
    hops: int
    affected_nodes: list[GraphNode]
    total_affected: int
    type_breakdown: dict[str, int]
    blast_radius_score: float


class EntityNeighborsResponse(BaseModel):
    entity_id: str
    entity_type: str
    source: GraphNode | None
    neighbors: list[dict[str, Any]]
    neighbor_count: int = 0


class MitreCoverageItem(BaseModel):
    technique_id: str
    name: str | None
    tactic: str | None
    alert_count: int


# ── Frontend-shape coverage payload ─────────────────────────────────────────
# Matches `MitreCoverage` in apps/web/src/lib/api.ts so the analyst console's
# /api/v1/graph/mitre/coverage call hydrates without a 404 + client-side
# remap. Intensity is normalized to [0, 1] across the returned cell set.


class MitreCoverageCell(BaseModel):
    techniqueId: str
    techniqueName: str
    tactic: str
    detections: int
    alerts: int
    intensity: float


class MitreCoverageResponse(BaseModel):
    tactics: list[str]
    cells: list[MitreCoverageCell]
    generatedAt: str


class UpsertHostRequest(BaseModel):
    host_id: str
    hostname: str
    ip_address: str = ""
    os: str = ""
    criticality: str = "medium"


class UpsertUserRequest(BaseModel):
    user_id: str
    username: str
    email: str = ""
    department: str = ""
    risk_score: float = 0.0


class UpsertAlertGraphRequest(BaseModel):
    alert_id: str
    title: str
    severity: str
    mitre_techniques: list[str] = Field(default_factory=list)
    host_id: str | None = None
    user_id: str | None = None
    ioc_values: list[str] = Field(default_factory=list)


class UpsertCaseGraphRequest(BaseModel):
    case_id: str
    title: str
    severity: str
    alert_ids: list[str] = Field(default_factory=list)


# ─── Endpoints ────────────────────────────────────────────────────────────────


async def _attack_path_from_relational(
    db: Any,
    case_id: str,
) -> dict[str, Any] | None:
    """Reconstruct an attack path graph from the relational case row.

    Used as a fallback when the Neo4j knowledge graph is unreachable so the
    Attack Path tab still renders something meaningful in demo deployments
    that don't ship a graph database. Returns ``None`` if the case can't be
    located so the caller can decide whether to 404.
    """
    row = (
        await db.execute(
            text("SELECT id, title, severity, mitre_techniques, alert_ids FROM aisoc_cases WHERE id = CAST(:cid AS UUID)").bindparams(
                cid=case_id
            )
        )
    ).fetchone()
    if not row:
        return None

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []

    case_node_id = f"case:{row.id}"
    nodes.append(
        {
            "id": case_node_id,
            "label": "Case",
            "properties": {
                "title": row.title,
                "severity": row.severity,
            },
        }
    )

    # mitre_techniques may be list[str] or list[dict] depending on seed era
    techniques: list[str] = []
    for item in row.mitre_techniques or []:
        if isinstance(item, str):
            techniques.append(item)
        elif isinstance(item, dict):
            tid = item.get("id") or item.get("technique_id")
            if tid:
                techniques.append(str(tid))

    technique_node_ids: list[str] = []
    for tid in techniques:
        nid = f"technique:{tid}"
        technique_node_ids.append(nid)
        nodes.append(
            {
                "id": nid,
                "label": "Technique",
                "properties": {"technique_id": tid},
            }
        )

    for alert_id in row.alert_ids or []:
        alert_node_id = f"alert:{alert_id}"
        nodes.append(
            {
                "id": alert_node_id,
                "label": "Alert",
                "properties": {"alert_id": str(alert_id)},
            }
        )
        edges.append({"source": case_node_id, "target": alert_node_id, "type": "INCLUDES"})
        # Best-effort attribution: each alert links to all case techniques.
        for tnid in technique_node_ids:
            edges.append({"source": alert_node_id, "target": tnid, "type": "USES_TECHNIQUE"})

    return {
        "case_id": str(row.id),
        "nodes": nodes,
        "edges": edges,
        "node_count": len(nodes),
        "edge_count": len(edges),
    }


@router.get(
    "/attack-path/{case_id}",
    response_model=AttackPathResponse,
    summary="Get attack path graph for a case",
)
async def get_attack_path(
    case_id: str,
    db: DBSession,
    max_depth: Annotated[int, Query(ge=1, le=10)] = 6,
    current_user: CurrentUser = Depends(get_current_user),
) -> AttackPathResponse:
    """
    Traverse the knowledge graph from a Case node to reconstruct the full
    attack path: Case → Alerts → Hosts/Users → IOCs → MITRE Techniques.

    Falls back to a relational reconstruction (Case → Alerts → Techniques)
    when the Neo4j graph backend is offline so the demo Attack Path UI
    keeps working without a graph database deployed.
    """
    data: dict[str, Any] | None = None
    graph_offline = False
    try:
        data = await graph_service.get_attack_path(
            case_id=case_id,
            tenant_id=str(current_user.tenant_id),
            max_depth=max_depth,
        )
    except Exception as exc:
        if not _is_graph_unavailable(exc):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Graph query failed: {exc}",
            ) from exc
        logger.info(
            "attack-path: graph backend unavailable, using relational fallback (%s: %s)",
            type(exc).__name__,
            exc,
        )
        graph_offline = True

    if graph_offline or not data or not data.get("nodes"):
        fallback = await _attack_path_from_relational(db, case_id)
        if fallback is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case {case_id} not found",
            )
        if not fallback["nodes"]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Case {case_id} has no linked entities",
            )
        return AttackPathResponse(**fallback)

    return AttackPathResponse(**data)


@router.get(
    "/blast-radius/{entity_type}/{entity_id}",
    response_model=BlastRadiusResponse,
    summary="Compute blast radius from an entity",
)
async def get_blast_radius(
    entity_type: str,
    entity_id: str,
    hops: Annotated[int, Query(ge=1, le=6)] = 3,
    current_user: CurrentUser = Depends(get_current_user),
) -> BlastRadiusResponse:
    """
    Compute the blast radius starting from a Host, User, or IOC node.
    Returns all entities reachable within `hops` and a severity score.
    """
    valid_types = {"host", "user", "ioc", "alert"}
    if entity_type.lower() not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"entity_type must be one of: {sorted(valid_types)}",
        )

    try:
        data = await graph_service.get_blast_radius(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=str(current_user.tenant_id),
            hops=hops,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Graph query failed: {exc}",
        ) from exc

    return BlastRadiusResponse(**data)


@router.get(
    "/neighbors/{entity_type}/{entity_id}",
    response_model=EntityNeighborsResponse,
    summary="Get immediate graph neighbors of an entity",
)
async def get_entity_neighbors(
    entity_type: str,
    entity_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> EntityNeighborsResponse:
    """Return all nodes directly connected (depth 1) to the specified entity."""
    try:
        data = await graph_service.get_entity_neighbors(
            entity_id=entity_id,
            entity_type=entity_type,
            tenant_id=str(current_user.tenant_id),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Graph query failed: {exc}",
        ) from exc

    return EntityNeighborsResponse(**data)


@router.get(
    "/mitre-coverage",
    response_model=list[MitreCoverageItem],
    summary="MITRE ATT&CK technique coverage for tenant",
)
async def get_mitre_coverage(
    current_user: CurrentUser = Depends(get_current_user),
) -> list[MitreCoverageItem]:
    """Return MITRE ATT&CK technique coverage aggregated from all tenant alerts.

    When the Neo4j knowledge graph is unreachable (e.g. in the public demo),
    this endpoint returns an empty list rather than 503-ing, so the Coverage
    UI degrades gracefully instead of breaking the whole page.
    """
    try:
        records = await graph_service.get_mitre_coverage(
            tenant_id=str(current_user.tenant_id),
        )
    except Exception as exc:
        if _is_graph_unavailable(exc):
            logger.info(
                "MITRE coverage: graph backend unavailable, returning empty set",
                exc_info=False,
            )
            return []
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Graph query failed: {exc}",
        ) from exc

    return [
        MitreCoverageItem(
            technique_id=r.get("technique_id", ""),
            name=r.get("name"),
            tactic=r.get("tactic"),
            alert_count=r.get("alert_count", 0),
        )
        for r in records
    ]


@router.get(
    "/mitre/coverage",
    response_model=MitreCoverageResponse,
    summary="MITRE ATT&CK coverage (frontend shape)",
)
async def get_mitre_coverage_compat(
    current_user: CurrentUser = Depends(get_current_user),
) -> MitreCoverageResponse:
    """Aggregated MITRE coverage in the shape the analyst console expects.

    The console's :code:`graph.getMitreCoverage()` call hits this URL and
    expects ``{ tactics, cells, generatedAt }``.  We aggregate the
    per-technique records returned by the same Neo4j-backed service used by
    ``/graph/mitre-coverage`` and degrade gracefully (empty set) when the
    knowledge graph is offline, mirroring that endpoint's behaviour.
    """
    from datetime import UTC as _UTC
    from datetime import datetime as _dt

    try:
        records = await graph_service.get_mitre_coverage(
            tenant_id=str(current_user.tenant_id),
        )
    except Exception as exc:
        if _is_graph_unavailable(exc):
            logger.info(
                "MITRE coverage (compat): graph backend unavailable; empty",
                exc_info=False,
            )
            return MitreCoverageResponse(
                tactics=[],
                cells=[],
                generatedAt=_dt.now(_UTC).isoformat(),
            )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Graph query failed: {exc}",
        ) from exc

    cells: list[MitreCoverageCell] = []
    tactics: set[str] = set()
    max_alerts = 1
    for r in records:
        max_alerts = max(max_alerts, int(r.get("alert_count", 0) or 0))

    for r in records:
        technique_id = r.get("technique_id") or ""
        tactic = r.get("tactic") or "unknown"
        alerts = int(r.get("alert_count", 0) or 0)
        # detections per technique aren't tracked in the graph schema yet;
        # treat coverage as a 1:1 proxy of alert evidence so the heatmap has
        # something to shade. When richer data lands, swap in a separate
        # aggregation here.
        detections = 1 if alerts > 0 else 0
        intensity = round(alerts / max_alerts, 4) if max_alerts else 0.0

        tactics.add(tactic)
        cells.append(
            MitreCoverageCell(
                techniqueId=technique_id,
                techniqueName=r.get("name") or technique_id,
                tactic=tactic,
                detections=detections,
                alerts=alerts,
                intensity=intensity,
            )
        )

    return MitreCoverageResponse(
        tactics=sorted(tactics),
        cells=cells,
        generatedAt=_dt.now(_UTC).isoformat(),
    )


# ─── Write Endpoints ──────────────────────────────────────────────────────────


@router.post(
    "/entities/host",
    status_code=status.HTTP_201_CREATED,
    summary="Upsert a Host node in the graph",
)
async def upsert_host(
    payload: UpsertHostRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    """Create or update a Host node in the knowledge graph."""
    await graph_service.upsert_host(
        host_id=payload.host_id,
        hostname=payload.hostname,
        tenant_id=str(current_user.tenant_id),
        ip_address=payload.ip_address,
        os=payload.os,
        criticality=payload.criticality,
    )
    return {"status": "ok", "host_id": payload.host_id}


@router.post(
    "/entities/user",
    status_code=status.HTTP_201_CREATED,
    summary="Upsert a User node in the graph",
)
async def upsert_user(
    payload: UpsertUserRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    """Create or update a User node in the knowledge graph."""
    await graph_service.upsert_user(
        user_id=payload.user_id,
        username=payload.username,
        tenant_id=str(current_user.tenant_id),
        email=payload.email,
        department=payload.department,
        risk_score=payload.risk_score,
    )
    return {"status": "ok", "user_id": payload.user_id}


@router.post(
    "/entities/alert",
    status_code=status.HTTP_201_CREATED,
    summary="Upsert an Alert node and its relationships in the graph",
)
async def upsert_alert_graph(
    payload: UpsertAlertGraphRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    """
    Create or update an Alert node and link it to Host, User, IOC, and Technique nodes.
    Called automatically after alert creation to keep the graph in sync.
    """
    await graph_service.upsert_alert_node(
        alert_id=payload.alert_id,
        tenant_id=str(current_user.tenant_id),
        title=payload.title,
        severity=payload.severity,
        mitre_techniques=payload.mitre_techniques,
        host_id=payload.host_id,
        user_id=payload.user_id,
        ioc_values=payload.ioc_values,
    )
    return {"status": "ok", "alert_id": payload.alert_id}


@router.post(
    "/entities/case",
    status_code=status.HTTP_201_CREATED,
    summary="Upsert a Case node and link to alerts in the graph",
)
async def upsert_case_graph(
    payload: UpsertCaseGraphRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, str]:
    """Create or update a Case node and link it to Alert nodes."""
    await graph_service.upsert_case_node(
        case_id=payload.case_id,
        tenant_id=str(current_user.tenant_id),
        title=payload.title,
        severity=payload.severity,
        alert_ids=payload.alert_ids,
    )
    return {"status": "ok", "case_id": payload.case_id}
