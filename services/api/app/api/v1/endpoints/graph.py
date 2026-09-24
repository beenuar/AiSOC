"""
Graph API endpoints: attack paths, blast radius, entity neighbors, MITRE coverage.
AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import CurrentUser, DBSession, get_current_user, require_permission
from app.services import graph_service
from app.services.context_import import import_context
from app.services.incident_context import get_incident_context
from app.services.investigation_tools import BACKED_TOOLS, TOOLS, dispatch

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


# ── Tenant-level overview payload ───────────────────────────────────────────
# Matches `AttackGraph` in apps/web/src/lib/api.ts. `graphApi.getOverview()`
# hands the body straight to the Cytoscape canvas with no key remapping, so
# these field names are camelCase on purpose — the same reason
# `MitreCoverageResponse` above is.


class OverviewNode(BaseModel):
    id: str
    label: str
    kind: str
    riskScore: float | None = None
    severity: str | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)


class OverviewEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    attributes: dict[str, Any] = Field(default_factory=dict)


class GraphOverviewResponse(BaseModel):
    """The tenant's entity graph, bounded for one canvas render.

    ``truncated`` is part of the contract rather than a diagnostic. A graph
    cut at the node ceiling and a graph that is genuinely this size render
    identically, and a viewer who cannot tell them apart reads a partial
    picture as the whole estate.

    ``nodeLimit`` and ``edgeLimit`` travel with it so the ceiling a caller
    reports is the ceiling this service applied. They are the same two
    constants the traversal is bounded by, read from
    ``graph_service`` rather than restated: a console that hardcoded 400 and
    900 would keep printing those numbers after someone moved them here, and
    a client telling an analyst the wrong limit is a smaller version of the
    bug ``truncated`` exists to fix.
    """

    nodes: list[OverviewNode]
    edges: list[OverviewEdge]
    generatedAt: str
    truncated: bool = False
    nodeLimit: int = graph_service.OVERVIEW_NODE_LIMIT
    edgeLimit: int = graph_service.OVERVIEW_EDGE_LIMIT


#: Neo4j label → the node kind the console has a colour and a glyph for.
#:
#: The console's `GraphNodeKind` union is ten members wide and the graph
#: schema declares 29 labels, so this is a projection, not a rename. What it
#: must not do is *lose* the distinction: every node carries its real labels
#: in ``attributes.labels``, so a label that projects onto the generic
#: ``asset`` glyph is still identifiable in the payload.
_LABEL_KIND: dict[str, str] = {
    "Host": "host",
    "Endpoint": "host",
    "User": "user",
    "Identity": "user",
    "ServiceAccount": "user",
    "Employee": "user",
    "Process": "process",
    "Container": "process",
    "Alert": "alert",
    "Technique": "technique",
    "Tactic": "tactic",
}

#: IOC nodes carry their own type, so they resolve more precisely than their
#: label alone allows. Keys are matched against a lowercased ``ioc_type``.
_IOC_KIND: dict[str, str] = {
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "ip_address": "ip",
    "domain": "domain",
    "fqdn": "domain",
    "hostname": "domain",
    "url": "domain",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "hash": "hash",
    "file_hash": "hash",
}

#: The five-tier ladder, and the only values allowed onto `severity`. A
#: vendor-specific string is dropped rather than coerced: the console shades
#: by severity, and guessing one would shade a node by a fact nobody
#: established.
_SEVERITY_TIERS = frozenset({"info", "low", "medium", "high", "critical"})

#: Properties that can carry a human-readable name, most specific first.
_LABEL_PROPS = ("hostname", "username", "name", "title", "value", "technique_id", "email", "natural_key", "id")


def _node_kind(labels: list[str], properties: dict[str, Any]) -> str:
    """Project a node's Neo4j labels onto a kind the canvas can draw."""
    if "IOC" in labels:
        ioc_type = str(properties.get("ioc_type") or "").strip().lower()
        return _IOC_KIND.get(ioc_type, "asset")
    for label in labels:
        kind = _LABEL_KIND.get(label)
        if kind:
            return kind
    return "asset"


def _node_label(node_id: str, properties: dict[str, Any]) -> str:
    """The name to draw on the node, falling back to its identifier."""
    for prop in _LABEL_PROPS:
        value = properties.get(prop)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return node_id


def _risk_score(properties: dict[str, Any]) -> float | None:
    """``risk_score`` when the node carries a usable number, else None.

    None and 0.0 are different claims — "not scored" against "scored zero" —
    and the console renders the first as an em dash.
    """
    raw = properties.get("risk_score")
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None
    return round(max(0.0, min(100.0, float(raw))), 1)


def _to_overview_node(record: dict[str, Any]) -> OverviewNode | None:
    """Project one graph record onto the console's node shape.

    Returns None for a node with no resolvable identifier: the canvas keys
    elements by id, and a blank one would collapse every such node into a
    single element that claims to be all of them.
    """
    node_id = record.get("id")
    if not isinstance(node_id, str) or not node_id.strip():
        return None
    labels = [str(label) for label in (record.get("labels") or [])]
    properties = dict(record.get("properties") or {})
    severity = str(properties.get("severity") or "").strip().lower()
    return OverviewNode(
        id=node_id,
        label=_node_label(node_id, properties),
        kind=_node_kind(labels, properties),
        riskScore=_risk_score(properties),
        severity=severity if severity in _SEVERITY_TIERS else None,
        attributes={"labels": labels},
    )


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
    tenant_id: uuid.UUID | str,
) -> dict[str, Any] | None:
    """Reconstruct an attack path graph from the relational case row.

    Used as a fallback when the Neo4j knowledge graph is unreachable so the
    Attack Path tab still renders something meaningful in demo deployments
    that don't ship a graph database. Returns ``None`` if the case can't be
    located so the caller can decide whether to 404.

    The tenant predicate is not optional here even though the caller is
    authenticated. The graph path above is tenant-scoped, but this fallback
    runs precisely when that path failed, so it is the only filter standing
    between two customers' cases — and ``aisoc_cases`` carries no RLS policy,
    so nothing behind it would catch the omission.
    """
    row = (
        await db.execute(
            text(
                "SELECT id, title, severity, mitre_techniques, alert_ids FROM aisoc_cases "
                "WHERE id = CAST(:cid AS UUID) AND tenant_id = CAST(:tid AS UUID)"
            ).bindparams(cid=case_id, tid=str(tenant_id))
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
    "",
    response_model=GraphOverviewResponse,
    summary="Tenant-level entity graph for the Attack Graph console",
)
async def get_graph_overview(
    depth: Annotated[int, Query(ge=1, le=6)] = 3,
    entity: Annotated[str | None, Query(max_length=256)] = None,
    current_user: CurrentUser = Depends(get_current_user),
) -> GraphOverviewResponse:
    """The caller's own entity graph, bounded for one canvas render.

    Scoping is the whole of this endpoint's security surface. Every node of
    every traversed path must satisfy the tenant predicate — not just the
    node the walk started from — and a node with no ``tenant_id`` is not
    readable, because an untagged node that *were* readable would bridge two
    tenants through any entity they happen to share. The narrow exemption is
    the global MITRE labels, which belong to no tenant by design.

    Two failure modes that must not look alike:

    ``empty``
        200 with no nodes. The tenant really has no graph yet — nothing has
        been ingested, or nothing ingested produced entities. The console
        renders its empty state.
    ``unavailable``
        503. The graph backend could not be reached, so we do not know what
        the tenant has. This deliberately does *not* degrade to an empty
        graph the way ``/graph/mitre-coverage`` does: an empty attack graph
        reads as "no attack relationships exist in your estate", which is a
        security claim, and making it on evidence we never retrieved is the
        failure this codebase keeps finding. The console's error state names
        the endpoint and the status, which is the honest answer.
    """
    try:
        data = await graph_service.get_graph_overview(
            tenant_id=str(current_user.tenant_id),
            depth=depth,
            entity=entity,
        )
    except Exception as exc:
        logger.warning(
            "graph overview: backend unavailable (%s: %s)",
            type(exc).__name__,
            str(exc).replace("\r", "").replace("\n", " ")[:200],
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"graph backend unavailable: {type(exc).__name__}",
        ) from exc

    nodes = [n for n in (_to_overview_node(r) for r in data["nodes"]) if n is not None]
    known_ids = {n.id for n in nodes}
    ref_to_id = {r["ref"]: r["id"] for r in data["nodes"] if isinstance(r.get("id"), str)}

    edges: list[OverviewEdge] = []
    seen_edges: set[str] = set()
    for record in data["edges"]:
        source = ref_to_id.get(record["source"])
        target = ref_to_id.get(record["target"])
        # An edge to a node that was dropped (no identifier, or past the node
        # ceiling) would render as a line into nothing.
        if source not in known_ids or target not in known_ids:
            continue
        edge_id = f"{source}|{record['type']}|{target}"
        if edge_id in seen_edges:
            continue
        seen_edges.add(edge_id)
        edges.append(
            OverviewEdge(
                id=edge_id,
                source=str(source),
                target=str(target),
                label=str(record["type"]),
                attributes={},
            )
        )

    return GraphOverviewResponse(
        nodes=nodes,
        edges=edges,
        generatedAt=datetime.now(UTC).isoformat(),
        truncated=bool(data.get("truncated")),
    )


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
        fallback = await _attack_path_from_relational(db, case_id, current_user.tenant_id)
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


class IncidentContextResponse(BaseModel):
    """The five context dimensions for one alert.

    ``partial`` and ``errors`` are part of the contract, not diagnostics. An
    empty bundle from an unreachable graph and an empty bundle from an alert
    with genuinely no context look identical otherwise, and a consumer that
    cannot tell them apart will treat "we could not look" as "there is
    nothing to find".
    """

    alert_id: str
    tenant_id: str
    identities: list[dict[str, Any]] = Field(default_factory=list)
    assets: list[dict[str, Any]] = Field(default_factory=list)
    cloud: list[dict[str, Any]] = Field(default_factory=list)
    business: list[dict[str, Any]] = Field(default_factory=list)
    threat: list[dict[str, Any]] = Field(default_factory=list)
    dimensions_resolved: int = 0
    partial: bool = False
    errors: list[str] = Field(default_factory=list)
    narrative: list[str] = Field(default_factory=list)


@router.get(
    "/incident-context/{alert_id}",
    response_model=IncidentContextResponse,
    summary="Traverse an alert into identity, asset, cloud, business and threat context",
)
async def incident_context(
    alert_id: str,
    current_user: CurrentUser = Depends(get_current_user),
) -> IncidentContextResponse:
    """Resolve one alert into the five dimensions an investigation needs.

    Each dimension runs as its own bounded, tenant-scoped traversal, and they
    run concurrently. A dimension that fails or times out names itself in
    ``errors`` while the rest still return: this is on the hot path of every
    escalated alert, so one slow leg must not take the bundle with it.

    Returns 200 with ``partial: true`` rather than an error status when some
    dimensions failed — the caller asked for context and got some.
    """
    context = await get_incident_context(alert_id, str(current_user.tenant_id))
    payload = context.as_dict()
    payload["narrative"] = context.narrative_lines()
    return IncidentContextResponse(**payload)


class InvestigationToolRequest(BaseModel):
    """One typed investigation pivot.

    ``tool`` names a primitive; ``args`` are its typed arguments. Deliberately
    not SQL: handing a model the lake query endpoint puts prompt-injectable
    text one step from the query planner, and the tenant predicate is the only
    thing between two customers' data. ``tenant_id`` is taken from the
    authenticated session and any value supplied here is discarded.
    """

    tool: str
    args: dict[str, Any] = Field(default_factory=dict)


@router.get(
    "/investigate/tools",
    summary="List the investigation primitives and which are backed by data",
)
async def list_investigation_tools(
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Enumerate the toolset, separating what can answer from what cannot.

    The split is part of the contract. A tool whose data class is not
    ingested reports that rather than returning an empty result, because an
    empty result reads as "I checked and found nothing" — which is how an
    investigation concludes benign on evidence it never had.
    """
    return {
        "tools": sorted(TOOLS),
        "backed_by_data": sorted(BACKED_TOOLS),
        "not_ingested": sorted(set(TOOLS) - BACKED_TOOLS),
    }


@router.post(
    "/investigate/query",
    summary="Run one typed investigation primitive against the event lake",
)
async def run_investigation_tool(
    request: InvestigationToolRequest,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """Execute one pivot. Tenant comes from the session, never the request."""
    result = await dispatch(request.tool, str(current_user.tenant_id), request.args)
    return result.as_dict()


class ContextImportRequest(BaseModel):
    """Directory, HR and CMDB context the event stream cannot carry.

    An event can say an account authenticated. It cannot say which person
    holds that account, whether they still work here, which business
    application the host serves, or what an outage of it costs. That is the
    difference between "unusual login for svc_deploy" and "unusual login for
    svc_deploy, owned by a contractor whose last day was Friday, on the host
    running the tier-1 payments service".
    """

    departments: list[dict[str, Any]] = Field(default_factory=list)
    employees: list[dict[str, Any]] = Field(default_factory=list)
    applications: list[dict[str, Any]] = Field(default_factory=list)
    cloud_accounts: list[dict[str, Any]] = Field(default_factory=list)


@router.post(
    "/context/import",
    summary="Import identity, organisational and business context into the graph",
)
async def import_graph_context(
    request: ContextImportRequest,
    current_user: Annotated[CurrentUser, Depends(require_permission("settings:write"))],
) -> dict[str, Any]:
    """Upsert context records. Safe to run repeatedly on a schedule.

    Records are merged rather than replaced: an import runs against a source
    of record that may be partial, and replacing the tenant's context with
    whatever one run produced would delete a department because an HR export
    timed out.

    Every rejected record is returned with its reason. A partially-applied
    import reporting success is worse than a rejected one, because afterwards
    the gaps are invisible.
    """
    report = await import_context(str(current_user.tenant_id), request.model_dump())
    return report.as_dict()


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
                generatedAt=datetime.now(UTC).isoformat(),
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
        generatedAt=datetime.now(UTC).isoformat(),
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
