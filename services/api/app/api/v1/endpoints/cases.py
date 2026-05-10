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

import logging
import os
import re
import uuid
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import quote

import httpx
from fastapi import APIRouter, HTTPException, Query, Response, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession
from app.core.logging import safe_log_value
from app.services.case_fanout import (
    FanoutResult,
    fanout_create_case,
    fanout_status_change,
)
from app.services.case_summary import build_case_summary
from app.services.case_summary_html import render_case_summary_html

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["cases"])

# The agents service owns the actual investigation orchestrator (Pillar-1).
# We keep the route surface on `/cases/{id}/investigate` and
# `/cases/{id}/investigations/{run_id}` for the web console and proxy through
# to the agents service so the front end has a single, stable API origin.
_AGENTS_URL = (os.getenv("AGENTS_SERVICE_URL") or os.getenv("AGENTS_API_URL") or "http://agents:8084").rstrip("/")

# Tight allowlist for proxied request paths. We only ever proxy to a fixed
# upstream (`_AGENTS_URL`) on a known set of investigation routes, so the
# path must be a pure relative path — no scheme, no host, no control bytes,
# no traversal sequences. This neutralises partial-SSRF (an attacker cannot
# redirect the request to a different host) and log-injection (the path
# can never contain CR/LF or other control characters).
_SAFE_PROXY_PATH_RE = re.compile(r"^/[A-Za-z0-9_\-./%]*$")


def _validate_agents_path(path: str) -> str:
    """Reject any proxied path that isn't a tightly constrained relative path."""
    if (
        not isinstance(path, str) or not _SAFE_PROXY_PATH_RE.match(path) or ".." in path or path.startswith("//")  # protocol-relative URL
    ):
        raise HTTPException(status_code=400, detail="invalid_request_path")
    return path


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
    # Workstream 8 — bidirectional ITSM. When the operator selects one or
    # more connector instances at create time, the API fans the new case
    # out to those external systems and persists the linkage in
    # ``case_external_refs``. Connector instances must be tenant-owned,
    # enabled, and declare ``Capability.PUSH_CASE`` (e.g. Jira,
    # ServiceNow). Empty list = case stays AiSOC-only.
    push_to_connector_ids: list[uuid.UUID] = Field(default_factory=list)


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
    case_number: str | None = None
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
    # Workstream 8 — populated only by ``POST /cases`` (create-time
    # fan-out) and ``PATCH /cases/{id}`` when ``status`` is changed.
    # The list is per-connector-instance and includes failures so the
    # UI can show "Jira ✓ · ServiceNow ✗ (timeout)" beside the case
    # without a follow-up GET. ``None`` (default) means "no fan-out
    # was attempted on this call" and is distinct from ``[]`` ("fan-out
    # was attempted but no connectors were selected").
    fanout_results: list[FanoutResult] | None = None


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


# Timeline / tasks
TaskStatus = Literal["todo", "in_progress", "done"]


class TimelineEvent(BaseModel):
    id: str
    type: str  # 'created' | 'status_change' | 'comment' | 'alert_linked' | 'task'
    timestamp: datetime
    title: str
    description: str | None = None
    actor: str | None = None


class TimelineResponse(BaseModel):
    events: list[TimelineEvent]


class CreateTaskRequest(BaseModel):
    title: str = Field(..., min_length=1)
    status: TaskStatus = "todo"
    assignee: str | None = None
    due_at: datetime | None = Field(None, alias="dueAt")

    model_config = {"populate_by_name": True}


class UpdateTaskRequest(BaseModel):
    title: str | None = None
    status: TaskStatus | None = None
    assignee: str | None = None
    due_at: datetime | None = Field(None, alias="dueAt")

    model_config = {"populate_by_name": True}


class TaskResponse(BaseModel):
    id: str
    title: str
    status: TaskStatus
    assignee: str | None = None
    due_at: datetime | None = Field(None, alias="dueAt")
    created_at: datetime = Field(..., alias="createdAt")

    model_config = {"populate_by_name": True}


def _row_to_task(row: Any) -> TaskResponse:
    return TaskResponse(
        id=str(row.id),
        title=row.title,
        status=row.status,
        assignee=row.assignee,
        dueAt=row.due_at,
        createdAt=row.created_at,
    )


# Investigation proxy schemas (forwarded to the agents service).
class InvestigateRequest(BaseModel):
    alert_summary: str | None = ""


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────


def _coerce_mitre(values: Any) -> list[str]:
    """Normalize mitre_techniques to a list of technique IDs.

    Accepts list[str] or list[dict] like ``{"id": "T1041", "name": "..."}``.
    Older seed fixtures stored objects; newer ones store flat IDs.
    """
    if not values:
        return []
    out: list[str] = []
    for item in values:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            tid = item.get("id") or item.get("technique_id") or item.get("name")
            if tid:
                out.append(str(tid))
    return out


def _coerce_tags(value: Any) -> dict[str, Any]:
    """aisoc_cases.tags is JSONB which may be an object or array."""
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {"labels": [str(v) for v in value]}
    return {}


def _row_to_case(row: Any) -> CaseResponse:
    return CaseResponse(
        id=row.id,
        case_number=getattr(row, "case_number", None),
        title=row.title,
        description=row.description,
        severity=row.severity,
        status=row.status,
        assignee=row.assignee,
        mitre_techniques=_coerce_mitre(row.mitre_techniques),
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
        tags=_coerce_tags(row.tags),
        sla_due_at=row.sla_due_at,
    )


async def _resolve_case_id(case_id: str, db: Any) -> uuid.UUID:
    """Resolve a case identifier (UUID **or** human-readable case_number) to a UUID.

    The web console and demo deeplinks use short identifiers like ``INC-001``,
    while the database primary key is a UUID. Accepting both forms here keeps
    the API ergonomic without forcing the front end to do a separate lookup.

    Raises ``404`` if the identifier doesn't match either form.
    """
    case_id = (case_id or "").strip()
    if not case_id:
        raise HTTPException(status_code=404, detail="Case not found.")

    # Try UUID first — that's the canonical form.
    try:
        return uuid.UUID(case_id)
    except (ValueError, AttributeError):
        pass

    # Fall back to case_number lookup. Use a parameterized query — never
    # interpolate the raw string into SQL.
    row = (
        await db.execute(
            text("SELECT id FROM aisoc_cases WHERE case_number = :case_number ORDER BY created_at DESC LIMIT 1").bindparams(
                case_number=case_id
            )
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")
    return row.id


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
        WHERE {" AND ".join(where_clauses)}
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
        if row is None:
            raise HTTPException(status_code=503, detail="Database error: INSERT returned no row")
        await db.commit()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc

    response = _row_to_case(row)

    # Workstream 8 — fan out to operator-selected ITSM connectors. The
    # case is already persisted (commit above) so a flaky Jira can't
    # block the create. ``fanout_create_case`` swallows per-backend
    # errors into the FanoutResult.status field; we only need to
    # commit the ``case_external_refs`` writes it staged.
    if body.push_to_connector_ids:
        try:
            results = await fanout_create_case(
                db,
                case_row=row,
                tenant_id=user.tenant_id,
                connector_ids=body.push_to_connector_ids,
                pushed_by=getattr(user, "email", None),
            )
            await db.commit()
            response.fanout_results = results
        except Exception:
            # Persistence of external refs failed but the AiSOC case
            # itself is fine; surface the partial result and move on.
            logger.exception("cases.create.fanout_persistence_failed case=%s", row.id)
            await db.rollback()
            response.fanout_results = []

    return response


@router.get("/{case_id}", response_model=CaseResponse, summary="Get case")
async def get_case(case_id: str, db: DBSession, user: AuthUser) -> CaseResponse:
    cid = await _resolve_case_id(case_id, db)
    row = (await db.execute(text("SELECT * FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")
    return _row_to_case(row)


@router.patch("/{case_id}", response_model=CaseResponse, summary="Update case")
async def update_case(case_id: str, body: UpdateCaseRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    import json as _json

    cid = await _resolve_case_id(case_id, db)
    existing = (await db.execute(text("SELECT status FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
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
    params: dict[str, Any] = {"id": cid, "now": now}

    if body.title is not None:
        sets.append("title = :title")
        params["title"] = body.title
    if body.description is not None:
        sets.append("description = :description")
        params["description"] = body.description
    if body.severity is not None:
        sets.append("severity = :severity")
        params["severity"] = body.severity
    if body.assignee is not None:
        sets.append("assignee = :assignee")
        params["assignee"] = body.assignee
    if body.sla_due_at is not None:
        sets.append("sla_due_at = :sla")
        params["sla"] = body.sla_due_at
    if body.mitre_techniques is not None:
        sets.append("mitre_techniques = :mitre::jsonb")
        params["mitre"] = _json.dumps(body.mitre_techniques)
    if body.compliance_frameworks is not None:
        sets.append("compliance_frameworks = :frameworks::text[]")
        params["frameworks"] = body.compliance_frameworks
    if body.tags is not None:
        sets.append("tags = :tags::jsonb")
        params["tags"] = _json.dumps(body.tags)

    if body.status:
        sets.append("status = :status")
        params["status"] = body.status
        ts_col = {"triaged": "triaged_at", "resolved": "resolved_at", "closed": "closed_at"}.get(body.status)
        if ts_col:
            sets.append(f"{ts_col} = :now")

    q = text(f"UPDATE aisoc_cases SET {', '.join(sets)} WHERE id = :id RETURNING *").bindparams(**params)
    try:
        row = (await db.execute(q)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Case not found.")
        await db.commit()
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc

    response = _row_to_case(row)

    # Workstream 8 — if the operator changed status, project the
    # transition onto every connector this case is already linked to.
    # ``fanout_status_change`` no-ops when the case has no
    # ``case_external_refs`` rows yet, so the call is cheap for
    # AiSOC-only cases.
    if body.status and body.status != existing.status:
        try:
            results = await fanout_status_change(
                db,
                case_row=row,
                tenant_id=user.tenant_id,
                old_status=existing.status,
                new_status=body.status,
                pushed_by=getattr(user, "email", None),
            )
            if results:
                await db.commit()
                response.fanout_results = results
        except Exception:
            logger.exception("cases.update.fanout_persistence_failed case=%s", row.id)
            await db.rollback()
            response.fanout_results = []

        # WS-D2 — when a case enters its terminal lifecycle stages, drop a
        # system note pointing to the auto-summary artifact. The summary
        # itself is generated on-demand by GET /cases/{id}/summary, so this
        # is a cheap, idempotent breadcrumb rather than a heavy precompute.
        if body.status in {"resolved", "closed"}:
            try:
                await _emit_summary_breadcrumb(db, case_id=row.id, status=body.status)
            except Exception:  # pragma: no cover — defensive: never block status change.
                logger.exception("cases.update.summary_breadcrumb_failed case=%s", row.id)
                await db.rollback()

    return response


@router.post("/{case_id}/alerts", response_model=CaseResponse, summary="Link alerts to a case")
async def add_alerts(case_id: str, body: AddAlertsRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    cid = await _resolve_case_id(case_id, db)
    ids_str = [str(a) for a in body.alert_ids]
    q = text("""
        UPDATE aisoc_cases
        SET alert_ids = array(SELECT DISTINCT unnest(alert_ids || :new_ids::uuid[])),
            updated_at = now()
        WHERE id = :id
        RETURNING *
    """).bindparams(id=cid, new_ids=ids_str)
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
async def update_observables(case_id: str, body: UpdateObservablesRequest, db: DBSession, user: AuthUser) -> CaseResponse:
    import json as _json

    cid = await _resolve_case_id(case_id, db)
    existing = (await db.execute(text("SELECT observable_graph FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
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
    """).bindparams(id=cid, g=_json.dumps(graph))
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return _row_to_case(row)
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


@router.post("/{case_id}/comments", response_model=CommentResponse, status_code=201, summary="Add comment")
async def add_comment(case_id: str, body: AddCommentRequest, db: DBSession, user: AuthUser) -> CommentResponse:
    cid = await _resolve_case_id(case_id, db)
    exists = (await db.execute(text("SELECT 1 FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found.")

    comment_id = uuid.uuid4()
    now = datetime.now(UTC)
    q = text("""
        INSERT INTO aisoc_case_comments (id, case_id, author, body, is_system, created_at)
        VALUES (:id, :case_id, :author, :body, :sys, :now) RETURNING *
    """).bindparams(id=comment_id, case_id=cid, author=str(user) if user else "system", body=body.body, sys=body.is_system, now=now)
    try:
        row = (await db.execute(q)).fetchone()
        if row is None:
            raise HTTPException(status_code=503, detail="Database error: INSERT returned no row")
        await db.commit()
        return CommentResponse(
            id=row.id,
            case_id=row.case_id,
            author=row.author,
            body=row.body,
            is_system=row.is_system,
            created_at=row.created_at,
        )
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


@router.get("/{case_id}/comments", response_model=list[CommentResponse], summary="List case comments")
async def list_comments(case_id: str, db: DBSession, user: AuthUser) -> list[CommentResponse]:
    cid = await _resolve_case_id(case_id, db)
    rows = (
        await db.execute(text("SELECT * FROM aisoc_case_comments WHERE case_id = :id ORDER BY created_at").bindparams(id=cid))
    ).fetchall()
    return [
        CommentResponse(id=r.id, case_id=r.case_id, author=r.author, body=r.body, is_system=r.is_system, created_at=r.created_at)
        for r in rows
    ]


# Alias `/notes` → `/comments` so the web console (which calls `/notes` for the
# "Add Note" affordance) hits the same backing store.  Keeping both routes
# avoids a behavior change for any existing integration that already speaks
# `/comments`.
@router.get("/{case_id}/notes", response_model=list[CommentResponse], summary="List case notes (alias of /comments)")
async def list_notes(case_id: str, db: DBSession, user: AuthUser) -> list[CommentResponse]:
    return await list_comments(case_id, db, user)


@router.post("/{case_id}/notes", response_model=CommentResponse, status_code=201, summary="Add case note (alias of /comments)")
async def add_note(case_id: str, body: AddCommentRequest, db: DBSession, user: AuthUser) -> CommentResponse:
    return await add_comment(case_id, body, db, user)


@router.get("/{case_id}/evidence", response_model=EvidenceReport, summary="Export evidence chain report")
async def evidence_report(case_id: str, db: DBSession, user: AuthUser) -> EvidenceReport:
    cid = await _resolve_case_id(case_id, db)
    row = (await db.execute(text("SELECT * FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")
    return EvidenceReport(
        case_id=row.id,
        title=row.title,
        severity=row.severity,
        status=row.status,
        alert_count=len(row.alert_ids or []),
        mitre_techniques=_coerce_mitre(row.mitre_techniques),
        compliance_frameworks=list(row.compliance_frameworks or []),
        evidence_chain=list(row.evidence_chain or []),
        generated_at=datetime.now(UTC),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Timeline
#
# A flattened activity stream that the case workspace renders on the right.
# We synthesize the timeline from the case's own state transitions, linked
# alerts, comments, and tasks so the front end gets one unified view without
# orchestrating four separate calls.
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/{case_id}/timeline", response_model=TimelineResponse, summary="Case activity timeline")
async def case_timeline(case_id: str, db: DBSession, user: AuthUser) -> TimelineResponse:
    cid = await _resolve_case_id(case_id, db)
    case_row = (await db.execute(text("SELECT * FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
    if not case_row:
        raise HTTPException(status_code=404, detail="Case not found.")

    events: list[TimelineEvent] = []

    # Case creation event
    events.append(
        TimelineEvent(
            id=f"case-{case_row.id}-created",
            type="created",
            timestamp=case_row.created_at,
            title="Case opened",
            description=case_row.title,
            actor=case_row.assignee,
        )
    )

    # Status / severity reflection (we only surface the latest snapshot here;
    # full audit history is available via the audit log endpoints).
    if case_row.updated_at and case_row.updated_at != case_row.created_at:
        events.append(
            TimelineEvent(
                id=f"case-{case_row.id}-status",
                type="status_change",
                timestamp=case_row.updated_at,
                title=f"Status: {case_row.status}",
                description=f"Severity {case_row.severity}",
                actor=case_row.assignee,
            )
        )

    # Comments
    comment_rows = (
        await db.execute(
            text(
                "SELECT id, author, body, is_system, created_at FROM aisoc_case_comments WHERE case_id = :id ORDER BY created_at"
            ).bindparams(id=cid)
        )
    ).fetchall()
    for c in comment_rows:
        events.append(
            TimelineEvent(
                id=f"comment-{c.id}",
                type="comment",
                timestamp=c.created_at,
                title="System note" if c.is_system else "Comment",
                description=(c.body or "")[:280],
                actor=c.author,
            )
        )

    # Linked alerts (best-effort — we tolerate a missing alerts table)
    for alert_id in list(case_row.alert_ids or [])[:25]:
        try:
            a = (
                await db.execute(text("SELECT id, title, severity, created_at FROM aisoc_alerts WHERE id = :id").bindparams(id=alert_id))
            ).fetchone()
            if a:
                events.append(
                    TimelineEvent(
                        id=f"alert-{a.id}",
                        type="alert_linked",
                        timestamp=a.created_at or case_row.created_at,
                        title=f"Alert linked: {a.title}",
                        description=f"Severity {a.severity}",
                        actor=None,
                    )
                )
        except Exception:  # noqa: BLE001 — alerts table may not exist in some demos
            continue

    # Tasks
    try:
        task_rows = (
            await db.execute(
                text(
                    "SELECT id, title, status, assignee, created_at FROM aisoc_case_tasks WHERE case_id = :id ORDER BY created_at"
                ).bindparams(id=cid)
            )
        ).fetchall()
        for t in task_rows:
            events.append(
                TimelineEvent(
                    id=f"task-{t.id}",
                    type="task",
                    timestamp=t.created_at,
                    title=f"Task ({t.status}): {t.title}",
                    description=None,
                    actor=t.assignee,
                )
            )
    except Exception:  # noqa: BLE001 — table created by migration 027; tolerate absence
        logger.exception("aisoc_case_tasks not available; skipping task events")

    events.sort(key=lambda e: e.timestamp)
    return TimelineResponse(events=events)


# ─────────────────────────────────────────────────────────────────────────────
# Tasks
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/{case_id}/tasks", response_model=list[TaskResponse], summary="List case tasks")
async def list_tasks(case_id: str, db: DBSession, user: AuthUser) -> list[TaskResponse]:
    cid = await _resolve_case_id(case_id, db)
    exists = (await db.execute(text("SELECT 1 FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found.")
    rows = (
        await db.execute(
            text(
                "SELECT id, title, status, assignee, due_at, created_at FROM aisoc_case_tasks WHERE case_id = :id ORDER BY created_at"
            ).bindparams(id=cid)
        )
    ).fetchall()
    return [_row_to_task(r) for r in rows]


@router.post("/{case_id}/tasks", response_model=TaskResponse, status_code=201, summary="Create task")
async def create_task(
    case_id: str,
    body: CreateTaskRequest,
    db: DBSession,
    user: AuthUser,
) -> TaskResponse:
    cid = await _resolve_case_id(case_id, db)
    exists = (await db.execute(text("SELECT 1 FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found.")

    task_id = uuid.uuid4()
    now = datetime.now(UTC)
    try:
        row = (
            await db.execute(
                text(
                    """
                    INSERT INTO aisoc_case_tasks
                        (id, case_id, title, status, assignee, due_at, created_at, updated_at, created_by)
                    VALUES
                        (:id, :case_id, :title, :status, :assignee, :due_at, :now, :now, :created_by)
                    RETURNING id, title, status, assignee, due_at, created_at
                    """
                ).bindparams(
                    id=task_id,
                    case_id=cid,
                    title=body.title,
                    status=body.status,
                    assignee=body.assignee,
                    due_at=body.due_at,
                    now=now,
                    created_by=str(user) if user else None,
                )
            )
        ).fetchone()
        await db.commit()
        return _row_to_task(row)
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


@router.patch("/{case_id}/tasks/{task_id}", response_model=TaskResponse, summary="Update task")
async def update_task(
    case_id: str,
    task_id: uuid.UUID,
    body: UpdateTaskRequest,
    db: DBSession,
    user: AuthUser,
) -> TaskResponse:
    cid = await _resolve_case_id(case_id, db)
    sets: list[str] = []
    params: dict[str, Any] = {"id": task_id, "case_id": cid, "now": datetime.now(UTC)}
    if body.title is not None:
        sets.append("title = :title")
        params["title"] = body.title
    if body.status is not None:
        sets.append("status = :status")
        params["status"] = body.status
    if body.assignee is not None:
        sets.append("assignee = :assignee")
        params["assignee"] = body.assignee
    if body.due_at is not None:
        sets.append("due_at = :due_at")
        params["due_at"] = body.due_at
    if not sets:
        raise HTTPException(status_code=400, detail="No fields to update.")
    sets.append("updated_at = :now")

    try:
        row = (
            await db.execute(
                text(
                    f"""
                    UPDATE aisoc_case_tasks
                    SET {", ".join(sets)}
                    WHERE id = :id AND case_id = :case_id
                    RETURNING id, title, status, assignee, due_at, created_at
                    """
                ).bindparams(**params)
            )
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Task not found.")
        await db.commit()
        return _row_to_task(row)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        raise HTTPException(status_code=503, detail=f"Database error: {exc}") from exc


# ─────────────────────────────────────────────────────────────────────────────
# Investigation proxy
#
# The investigation orchestrator lives in the agents service. The web console
# only knows about /api/v1/cases/{id}/..., so we proxy through and keep the
# external API surface stable.
# ─────────────────────────────────────────────────────────────────────────────


async def _agents_proxy(method: str, path: str, **kwargs: Any) -> httpx.Response:
    safe_path = _validate_agents_path(path)
    url = f"{_AGENTS_URL}{safe_path}"
    timeout = kwargs.pop("timeout", 30.0)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            return await client.request(method, url, **kwargs)
    except httpx.HTTPError as exc:
        logger.exception(
            "agents_proxy.request_failed",
            extra={
                "method": safe_log_value(method),
                "path": safe_log_value(safe_path),
            },
        )
        raise HTTPException(
            status_code=503,
            detail=f"Agents service unavailable: {exc}",
        ) from exc


@router.post("/{case_id}/investigate", summary="Launch investigation for case")
async def case_investigate(
    case_id: str,
    body: InvestigateRequest,
    db: DBSession,
    user: AuthUser,
) -> dict[str, Any]:
    cid = await _resolve_case_id(case_id, db)
    exists = (await db.execute(text("SELECT 1 FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="Case not found.")

    resp = await _agents_proxy(
        "POST",
        f"/api/v1/cases/{cid}/investigate",
        json={"alert_summary": body.alert_summary or ""},
    )
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()


@router.get("/{case_id}/investigations", summary="List investigation runs for a case")
async def list_case_investigations(
    case_id: str,
    db: DBSession,
    user: AuthUser,
) -> dict[str, Any]:
    """List all investigation runs for a case.

    The agents service is the source of truth.  When it's unreachable we return
    an empty list rather than 503 so the case detail page still renders.
    """
    cid = await _resolve_case_id(case_id, db)
    try:
        resp = await _agents_proxy("GET", f"/api/v1/cases/{cid}/investigations")
        if resp.status_code == 404:
            return {"runs": []}
        if resp.status_code >= 400:
            return {"runs": []}
        return resp.json()
    except HTTPException:
        # Agents service unavailable — render a soft-empty list instead of 503.
        return {"runs": []}


@router.get("/{case_id}/investigations/{run_id}", summary="Get investigation run")
async def case_investigation_run(
    case_id: str,
    run_id: str,
    user: AuthUser,
) -> dict[str, Any]:
    # URL-encode the user-supplied run_id so it cannot inject `/`, `?`, `#`,
    # CR/LF, or other URL syntax into the proxied path.
    safe_run_id = quote(run_id, safe="")
    resp = await _agents_proxy("GET", f"/api/v1/investigations/{safe_run_id}")
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()


# Filename sanitiser for Content-Disposition: keep only safe ASCII so the
# header cannot be split with CR/LF and the value renders consistently.
_SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_filename_segment(value: str) -> str:
    """Reduce an identifier to a Content-Disposition-safe filename segment."""
    return _SAFE_FILENAME_RE.sub("_", value)[:64] or "unknown"


# ────────────────────────────────────────────────────────────────────────────
# WS-D2 — auto-summary artifact at investigation close.
# ────────────────────────────────────────────────────────────────────────────

# We keep the breadcrumb body in one place so the system note stays uniform
# across deployments — easier to grep, easier to redact in CI exports.
_SUMMARY_BREADCRUMB_BODY = (
    "Case auto-summary generated. Download from "
    "/api/v1/cases/{case_id}/summary?format=html "
    "(or ?format=json for the structured payload). "
    "Print the HTML page (Ctrl/Cmd-P → Save as PDF) for case-file archival."
)


async def _emit_summary_breadcrumb(db: Any, *, case_id: uuid.UUID, status: str) -> None:
    """Drop a system comment pointing to the on-demand summary endpoint.

    Idempotent on repeated status changes — we re-emit only when transitioning
    *into* a terminal state, never on noop updates. The body intentionally
    avoids embedding tenant-specific URLs so the artifact link still works
    behind reverse proxies that rewrite the host.
    """
    body = _SUMMARY_BREADCRUMB_BODY.format(case_id=case_id) + f" (status={status})"
    await db.execute(
        text(
            """
            INSERT INTO aisoc_case_comments
                (id, case_id, author, body, is_system, created_at)
            VALUES (:id, :case_id, :author, :body, true, :now)
            """
        ).bindparams(
            id=uuid.uuid4(),
            case_id=case_id,
            author="aisoc",
            body=body,
            now=datetime.now(UTC),
        )
    )
    await db.commit()


@router.get(
    "/{case_id}/summary",
    summary="Download the per-case auto-summary (JSON or HTML)",
    response_model=None,
)
async def case_auto_summary(
    case_id: str,
    db: DBSession,
    user: AuthUser,
    format: Literal["json", "html"] = Query(
        "json",
        description=(
            "Response format. ``json`` returns the structured CaseAutoSummary; "
            "``html`` returns a print-ready report (use the browser's "
            "Save-as-PDF affordance for archival)."
        ),
    ),
) -> Any:
    cid = await _resolve_case_id(case_id, db)
    summary = await build_case_summary(db, cid)
    if summary is None:
        raise HTTPException(status_code=404, detail="Case not found.")

    if format == "html":
        rendered = render_case_summary_html(summary)
        case_label = summary.case.case_number or str(summary.case.case_id)[:8]
        filename = _safe_filename_segment(f"case-{case_label}-summary") + ".html"
        return HTMLResponse(
            content=rendered,
            headers={"Content-Disposition": f'inline; filename="{filename}"'},
        )

    return summary


@router.get(
    "/{case_id}/investigations/{run_id}/report.pdf",
    summary="Download investigation PDF report",
)
async def case_investigation_pdf(
    case_id: str,
    run_id: str,
    user: AuthUser,
) -> Response:
    safe_run_id = quote(run_id, safe="")
    resp = await _agents_proxy("GET", f"/api/v1/investigations/{safe_run_id}/report.pdf")
    if resp.status_code >= 400:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    safe_case_id = _safe_filename_segment(case_id)
    safe_run_id_filename = _safe_filename_segment(run_id)
    return Response(
        content=resp.content,
        media_type=resp.headers.get("content-type", "application/pdf"),
        headers={
            "Content-Disposition": resp.headers.get(
                "content-disposition",
                f'attachment; filename="case-{safe_case_id}-{safe_run_id_filename}.pdf"',
            ),
        },
    )


@router.get("/{case_id}/related", summary="List related cases (by alert/observable overlap)")
async def list_related_cases(
    case_id: str,
    db: DBSession,
    user: AuthUser,
) -> dict[str, Any]:
    """Return other cases that share alerts or observables with this case.

    This is intentionally a lightweight heuristic — we look for cases that
    overlap on `alert_ids` or share an observable IP/host.  It's the smallest
    thing the case detail page needs to stop 404'ing.
    """
    cid = await _resolve_case_id(case_id, db)
    row = (await db.execute(text("SELECT alert_ids, observable_graph FROM aisoc_cases WHERE id = :id").bindparams(id=cid))).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Case not found.")

    alert_ids = list(row.alert_ids or [])
    related: list[dict[str, Any]] = []

    if alert_ids:
        rows = (
            await db.execute(
                text(
                    """
                    SELECT id, case_number, title, severity, status, created_at
                    FROM aisoc_cases
                    WHERE id <> :id
                      AND alert_ids && CAST(:alerts AS UUID[])
                    ORDER BY created_at DESC
                    LIMIT 20
                    """
                ).bindparams(id=cid, alerts=[str(a) for a in alert_ids])
            )
        ).fetchall()
        for r in rows:
            related.append(
                {
                    "id": str(r.id),
                    "case_number": r.case_number,
                    "title": r.title,
                    "severity": r.severity or "medium",
                    "status": r.status or "new",
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                    "reason": "shared_alerts",
                }
            )

    return {"related": related}
