"""
Graph API endpoints: attack paths, blast radius, entity neighbors, MITRE coverage.
Cyble Open-Source AI Security Operations Center - MIT License
"""
from __future__ import annotations

from typing import Any, Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.api.v1.deps import get_current_user, CurrentUser
from app.services import graph_service

router = APIRouter(prefix="/graph", tags=["graph"])


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

@router.get(
    "/attack-path/{case_id}",
    response_model=AttackPathResponse,
    summary="Get attack path graph for a case",
)
async def get_attack_path(
    case_id: str,
    max_depth: Annotated[int, Query(ge=1, le=10)] = 6,
    current_user: CurrentUser = Depends(get_current_user),
) -> AttackPathResponse:
    """
    Traverse the knowledge graph from a Case node to reconstruct the full
    attack path: Case → Alerts → Hosts/Users → IOCs → MITRE Techniques.
    """
    try:
        data = await graph_service.get_attack_path(
            case_id=case_id,
            tenant_id=str(current_user.tenant_id),
            max_depth=max_depth,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Graph query failed: {exc}",
        )

    if not data["nodes"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case {case_id} not found in graph or has no linked entities",
        )

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
        )

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
        )

    return EntityNeighborsResponse(**data)


@router.get(
    "/mitre-coverage",
    response_model=list[MitreCoverageItem],
    summary="MITRE ATT&CK technique coverage for tenant",
)
async def get_mitre_coverage(
    current_user: CurrentUser = Depends(get_current_user),
) -> list[MitreCoverageItem]:
    """Return MITRE ATT&CK technique coverage aggregated from all tenant alerts."""
    try:
        records = await graph_service.get_mitre_coverage(
            tenant_id=str(current_user.tenant_id),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Graph query failed: {exc}",
        )

    return [
        MitreCoverageItem(
            technique_id=r.get("technique_id", ""),
            name=r.get("name"),
            tactic=r.get("tactic"),
            alert_count=r.get("alert_count", 0),
        )
        for r in records
    ]


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
