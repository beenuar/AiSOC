"""First-class case management (tier2-cases).

Implements the full case lifecycle: new → triaged → investigating → contained →
resolved → closed.  Each case aggregates multiple alerts, maintains an observable
graph, evidence chain, and MITRE ATT&CK coverage map.

Endpoints
---------
* ``GET  /cases``                  List cases (filterable by status/severity/assignee).
* ``POST /cases``                  Create a new case.
* ``GET  /cases/{id}``             Retrieve a case.
* ``PATCH /cases/{id}``            Update case fields (status, severity, assignee, …).
* ``POST /cases/{id}/alerts``      Link alerts to a case.
* ``POST /cases/{id}/observables`` Add / update observable graph nodes/edges.
* ``POST /cases/{id}/comments``    Add a comment / timeline entry.
* ``GET  /cases/{id}/comments``    List comments for a case.
* ``GET  /cases/{id}/evidence``    Export the evidence chain as a structured report.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession

router = APIRouter(prefix="/cases", tags=["cases"])

# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────

CaseStatus = Literal["new", "triaged", "investigating", "contained", "resolved", "closed"]
CaseSeverity = Literal["info", "low", "medium", "high", "critical"]

# Valid forward-only state transitions
_TRANSITIONS: dict[str, set[str]] = {
    "new": {"triaged"},
    "triaged": {"investigating"},
    "investigating": {"contained", "resolved"},
    "contained": {"resolved"},
    "resolved": {"closed"},
    "closed": set(),
}


class CreateCaseRequest(BaseModel):
    title: str = Field(..., min_length=3)
    description: str | None = None
    severity: CaseSeverity = "medium"
    assignee: str | None = None
    alert_ids: list[uuid.UUID] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    compliance_frameworks: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)
    sla_due_at: datetime | None = None


class UpdateCaseRequest(BaseModel):
    title: str | None = None
    description: str | None = None
    severity: CaseSeverity | None = None
    status: CaseStatus | None = None
    assignee: str | None = None
    mitre_techniques: list[str] | None = None
    compliance_frameworks: list[str] | None = None
    tags: dict[str, str] | None = None
    sla_due_at: datetime | None = None


class AddAlertsRequest(BaseModel):
    alert_ids: list[uuid.UUID]


class ObservableNode(BaseModel):
    id: str
    kind: Literal["ip", "user", "host", "domain", "hash", "file", "process", "alert"]
    value: str
    tags: list[str] = Field(default_factory=list)


class ObservableEdge(BaseModel):
    source: str
    target: str
    relation: str


class UpdateObservablesRequest(BaseModel):
    nodes: list[ObservableNode] = Field(default_factory=list)
    edges: list[ObservableEdge] = Field(default_factory=list)


class AddCommentRequest(BaseModel):
    body: str = Field(..., min_length=1)
    is_system: bool = False


class CaseResponse(BaseModel):
    id: uuid.UUID
    title: str
    description: str | None
    severity: str
    status: str
    assignee: str | None
    mitre_techniques: list[str]
    alert_ids: list[uuid.UUID]
    observable_graph: dict[str, Any]
    evidence_chain: list[dict[str, Any]]
    compliance_frameworks: list[str]
    opened_at: datetime
    triaged_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    created_at: datetime
    updated_at: datetime
    created_by: str | None
    tags: dict[str, Any]
    sla_due_at: datetime | None


class CommentResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    author: str | None
    body: str
    is_system: bool
    created_at: datetime


class EvidenceReport(BaseModel):
    case_id: uuid.UUID
    title: str
    severity: str
    status: str
    alert_count: int
    mitre_techniques: list[str]
    compliance_frameworks: list[str]
    evidence_chain: list[dict[str, Any]]
    generated_at: datetime


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _row_to_case(row: Any) -> CaseResponse:
    return CaseResponse(
        id=row.id,
        title=row.title,
        description=row.description,
        severity=row.severity,
        status=row.status,
        assignee=row.assignee,
        mitre_techniques=list(row.mitre_techniques or []),
        alert_ids=list(row.alert_ids or []),
        observable_graph=dict(row.observable_graph or {}),
        evidence_chain=list(row.evidence_chain or []),
        compliance_frameworks=list(row.compliance_frameworks or []),
        opened_at=row.opened_at,
        triaged_at=row.triaged_at,
        resolved_at=row.resolved_at,
        closed_at=row.closed_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
        created_by=row.created_by,
        tags=dict(row.tags or {}),
        sla_due_at=row.sla_due_at,
    )


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.get("", response_model=list[CaseResponse], summary="List cases")
async def list_cases(
    db: DBSession,
    user: AuthUser,
    status_filter: str | None = Query(None, alias="status"),
    severity: str | None = Query(None),
    assignee: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[CaseResponse]:
    where_clauses = ["1=1"]
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if status_filter:
        where_clauses.append("status = :status")
        params["status"] = status_filter
    if severity:
        where_clauses.append("severity = :severity")
        params["severity"] = severity
    if assignee:
        where_clauses.append("assignee = :assignee")
        params["assignee"] = assignee

    q = f"""
        SELECT * FROM aisoc_cases
        WHERE {' AND '.join(where_clauses)}
        ORDER BY created_at DESC
        LIMIT :limit OFFSET :offset
    """
    try:
        rows = await db.execute(text(q).bindparams(**params))
        return [_row_to_case(r) for r in rows.fetchall()]
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED, summary="Create case")
async def create_case(body: CreateCaseRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    import json as _json

    case_id = uuid.uuid4()
    now = datetime.now(UTC)
    q = text("""
        INSERT INTO aisoc_cases (
            id, title, description, severity, status, assignee,
            mitre_techniques, alert_ids, compliance_frameworks, tags,
            sla_due_at, opened_at, created_at, updated_at, created_by
        ) VALUES (
            :id, :title, :description, :severity, 'new', :assignee,
            :mitre::jsonb, :alert_ids::uuid[], :frameworks::text[], :tags::jsonb,
            :sla, :now, :now, :now, :user
        ) RETURNING *
    """).bindparams(
        id=case_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        assignee=body.assignee,
        mitre=_json.dumps(body.mitre_techniques),
        alert_ids=list(map(str, body.alert_ids)) or [],
        frameworks=body.compliance_frameworks or [],
        tags=_json.dumps(body.tags),
        sla=body.sla_due_at,
        now=now,
        user=str(user) if user else "system",
    )
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return _row_to_case(row)
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


@router.get("/{case_id}", response_model=CaseResponse, summary="Get case")
async def get_case(case_id: uuid.UUID, db: DBSession, user: AuthUser) -> CaseResponse:
    row = (await db.execute(text("SELECT * FROM aisoc_cases WHERE id = :id").bindparams(id=case_id))).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")
    return _row_to_case(row)


@router.patch("/{case_id}", response_model=CaseResponse, summary="Update case")
async def update_case(case_id: uuid.UUID, body: UpdateCaseRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    import json as _json

    existing = (await db.execute(text("SELECT status FROM aisoc_cases WHERE id = :id").bindparams(id=case_id))).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found.")

    if body.status and body.status != existing.status:
        allowed = _TRANSITIONS.get(existing.status, set())
        if body.status not in allowed:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid status transition: {existing.status} → {body.status}. Allowed: {sorted(allowed) or 'none'}",
            )

    now = datetime.now(UTC)
    sets = ["updated_at = :now"]
    params: dict[str, Any] = {"id": case_id, "now": now}

    if body.title is not None:
        sets.append("title = :title"); params["title"] = body.title
    if body.description is not None:
        sets.append("description = :description"); params["description"] = body.description
    if body.severity is not None:
        sets.append("severity = :severity"); params["severity"] = body.severity
    if body.assignee is not None:
        sets.append("assignee = :assignee"); params["assignee"] = body.assignee
    if body.sla_due_at is not None:
        sets.append("sla_due_at = :sla"); params["sla"] = body.sla_due_at
    if body.mitre_techniques is not None:
        sets.append("mitre_techniques = :mitre::jsonb"); params["mitre"] = _json.dumps(body.mitre_techniques)
    if body.compliance_frameworks is not None:
        sets.append("compliance_frameworks = :frameworks::text[]"); params["frameworks"] = body.compliance_frameworks
    if body.tags is not None:
        sets.append("tags = :tags::jsonb"); params["tags"] = _json.dumps(body.tags)

    if body.status:
        sets.append("status = :status"); params["status"] = body.status
        ts_col = {"triaged": "triaged_at", "resolved": "resolved_at", "closed": "closed_at"}.get(body.status)
        if ts_col:
            sets.append(f"{ts_col} = :now")

    q = text(f"UPDATE aisoc_cases SET {', '.join(sets)} WHERE id = :id RETURNING *").bindparams(**params)
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return _row_to_case(row)
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


@router.post("/{case_id}/alerts", response_model=CaseResponse, summary="Link alerts to a case")
async def add_alerts(case_id: uuid.UUID, body: AddAlertsRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    ids_str = [str(a) for a in body.alert_ids]
    q = text("""
        UPDATE aisoc_cases
        SET alert_ids = array(SELECT DISTINCT unnest(alert_ids || :new_ids::uuid[])),
            updated_at = now()
        WHERE id = :id
        RETURNING *
    """).bindparams(id=case_id, new_ids=ids_str)
    try:
        row = (await db.execute(q)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Case not found.")
        await db.commit()
        return _row_to_case(row)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


@router.post("/{case_id}/observables", response_model=CaseResponse, summary="Update observable graph")
async def update_observables(case_id: uuid.UUID, body: UpdateObservablesRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    import json as _json

    existing = (await db.execute(text("SELECT observable_graph FROM aisoc_cases WHERE id = :id").bindparams(id=case_id))).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Case not found.")

    graph: dict[str, Any] = dict(existing.observable_graph or {})
    nodes = graph.get("nodes", [])
    edges = graph.get("edges", [])

    existing_ids = {n["id"] for n in nodes}
    for n in body.nodes:
        if n.id not in existing_ids:
            nodes.append(n.model_dump())
        else:
            nodes = [n.model_dump() if x["id"] == n.id else x for x in nodes]

    edge_keys = {(e["source"], e["target"]) for e in edges}
    for e in body.edges:
        if (e.source, e.target) not in edge_keys:
            edges.append(e.model_dump())

    graph = {"nodes": nodes, "edges": edges}
    q = text("""
        UPDATE aisoc_cases SET observable_graph = :g::jsonb, updated_at = now() WHERE id = :id RETURNING *
    """).bindparams(id=case_id, g=_json.dumps(graph))
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return _row_to_case(row)
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


@router.post("/{case_id}/comments", response_model=CommentResponse, status_code=201, summary="Add comment")
async def add_comment(case_id: uuid.UUID, body: AddCommentRequest, db: DBSession, user: AuthUser) -> CommentResponse:
    exists = (await db.execute(text("SELECT 1 FROM aisoc_cases WHERE id = :id").bindparams(id=case_id))).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found.")

    comment_id = uuid.uuid4()
    now = datetime.now(UTC)
    q = text("""
        INSERT INTO aisoc_case_comments (id, case_id, author, body, is_system, created_at)
        VALUES (:id, :case_id, :author, :body, :sys, :now) RETURNING *
    """).bindparams(id=comment_id, case_id=case_id, author=str(user) if user else "system", body=body.body, sys=body.is_system, now=now)
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return CommentResponse(
            id=row.id, case_id=row.case_id, author=row.author,
            body=row.body, is_system=row.is_system, created_at=row.created_at,
        )
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


@router.get("/{case_id}/comments", response_model=list[CommentResponse], summary="List case comments")
async def list_comments(case_id: uuid.UUID, db: DBSession, user: AuthUser) -> list[CommentResponse]:
    rows = (await db.execute(text("SELECT * FROM aisoc_case_comments WHERE case_id = :id ORDER BY created_at").bindparams(id=case_id))).fetchall()
    return [CommentResponse(id=r.id, case_id=r.case_id, author=r.author, body=r.body, is_system=r.is_system, created_at=r.created_at) for r in rows]


@router.get("/{case_id}/evidence", response_model=EvidenceReport, summary="Export evidence chain report")
async def evidence_report(case_id: uuid.UUID, db: DBSession, user: AuthUser) -> EvidenceReport:
    row = (await db.execute(text("SELECT * FROM aisoc_cases WHERE id = :id").bindparams(id=case_id))).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")
    return EvidenceReport(
        case_id=row.id,
        title=row.title,
        severity=row.severity,
        status=row.status,
        alert_count=len(row.alert_ids or []),
        mitre_techniques=list(row.mitre_techniques or []),
        compliance_frameworks=list(row.compliance_frameworks or []),
        evidence_chain=list(row.evidence_chain or []),
        generated_at=datetime.now(UTC),
    )
