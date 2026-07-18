"""Hypothesis-driven hunt workbench (tier2-hunting).

SOC analysts author threat-hunting hypotheses, attach multi-platform queries,
and track hunt runs and findings — all version-controlled via the DAC pipeline.

Endpoints
---------
* ``GET  /hunts``                List hunts.
* ``POST /hunts``                Create a hunt hypothesis.
* ``GET  /hunts/{id}``           Get a hunt.
* ``PATCH /hunts/{id}``          Update hypothesis / status / priority.
* ``POST /hunts/{id}/run``       Execute a hunt query (ES|QL live; SPL/KQL templated).
* ``GET  /hunts/{id}/runs``      List run history for a hunt.
* ``POST /hunts/{id}/findings``  Append finding entries to a hunt.

Tenant isolation
----------------
Every query is scoped to ``user.tenant_id``. Rows whose ``tenant_id`` is NULL
remain visible only to the tenant that created them once they are owned.
Legacy rows created before migration 043 with ``tenant_id IS NULL`` are
silently treated as orphans — they are *not* returned to anyone, ensuring no
cross-tenant data leakage during the rollout window.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

import httpx
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession
from app.core.airgap import AirgapViolation, enforce_airgap_for_url
from app.services.model_aliases import resolve_model_alias

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/hunts", tags=["hunts"])

# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────

HuntStatus = Literal["draft", "active", "completed", "archived"]
HuntPriority = Literal["low", "medium", "high", "critical"]
HuntPlatform = Literal["esql", "spl", "kql"]


class CreateHuntRequest(BaseModel):
    title: str = Field(..., min_length=3)
    hypothesis: str = Field(..., min_length=10, description="Plain-English threat hypothesis.")
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    priority: HuntPriority = "medium"
    assigned_to: str | None = None
    tags: list[str] = Field(default_factory=list)


class UpdateHuntRequest(BaseModel):
    title: str | None = None
    hypothesis: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    status: HuntStatus | None = None
    priority: HuntPriority | None = None
    assigned_to: str | None = None
    query_esql: str | None = None
    query_spl: str | None = None
    query_kql: str | None = None
    tags: list[str] | None = None


class AddFindingsRequest(BaseModel):
    findings: list[dict[str, Any]] = Field(..., min_length=1)
    false_positive_rate: float | None = Field(None, ge=0.0, le=1.0)


class RunHuntRequest(BaseModel):
    platform: HuntPlatform = "esql"


class HuntRunResponse(BaseModel):
    id: uuid.UUID
    hunt_id: uuid.UUID
    run_at: datetime
    platform: str
    query_used: str | None
    hit_count: int
    result_sample: list[dict[str, Any]]
    duration_ms: int | None
    error: str | None


class HuntResponse(BaseModel):
    id: uuid.UUID
    title: str
    hypothesis: str
    mitre_tactic: str | None
    mitre_technique: str | None
    status: str
    priority: str
    query_esql: str | None
    query_spl: str | None
    query_kql: str | None
    findings: list[dict[str, Any]]
    false_positive_rate: float | None
    assigned_to: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None
    created_by: str | None


# ────────────────────────────────────────────────────────────────────────────
# LLM query generation helper
# ────────────────────────────────────────────────────────────────────────────

_HUNT_SYSTEM = """You are a senior threat hunter. Given a threat hypothesis, generate
detection queries for the listed platforms.

Return ONLY valid JSON with this structure:
{
  "esql": "<ES|QL query string>",
  "spl": "<Splunk SPL string>",
  "kql": "<KQL string>"
}
No prose. Just JSON."""


async def _generate_queries(hypothesis: str, mitre: str | None) -> dict[str, str] | None:
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
    if not api_key:
        return None
    base_url = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    model = os.getenv("LLM_MODEL") or resolve_model_alias("nl")
    user_msg = f"HYPOTHESIS: {hypothesis}"
    if mitre:
        user_msg += f"\nMITRE TECHNIQUE: {mitre}"
    user_msg += "\nGenerate ES|QL, SPL, and KQL hunt queries."
    completions_url = f"{base_url}/chat/completions"
    enforce_airgap_for_url(completions_url)
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            resp = await client.post(
                completions_url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": model,
                    "messages": [
                        {"role": "system", "content": _HUNT_SYSTEM},
                        {"role": "user", "content": user_msg},
                    ],
                    "temperature": 0.2,
                    "response_format": {"type": "json_object"},
                },
            )
        resp.raise_for_status()
        return json.loads(resp.json()["choices"][0]["message"]["content"])
    except Exception:
        return None


def _fallback_queries(hypothesis: str) -> dict[str, str]:
    escaped = hypothesis.replace('"', '\\"')
    return {
        "esql": f'FROM logs-* | WHERE message LIKE "%{escaped[:60]}%" | LIMIT 100',
        "spl": f'index=* "{escaped[:60]}" | head 100',
        "kql": f'// KQL hunt — adapt field names\nSecurityEvent\n| where Activity has "{escaped[:60]}"\n| limit 100',
    }


# ────────────────────────────────────────────────────────────────────────────
# Row helper
# ────────────────────────────────────────────────────────────────────────────


def _row_to_hunt(row: Any) -> HuntResponse:
    return HuntResponse(
        id=row.id,
        title=row.title,
        hypothesis=row.hypothesis,
        mitre_tactic=row.mitre_tactic,
        mitre_technique=row.mitre_technique,
        status=row.status,
        priority=row.priority,
        query_esql=row.query_esql,
        query_spl=row.query_spl,
        query_kql=row.query_kql,
        findings=list(row.findings or []),
        false_positive_rate=row.false_positive_rate,
        assigned_to=row.assigned_to,
        tags=list(row.tags or []),
        created_at=row.created_at,
        updated_at=row.updated_at,
        completed_at=row.completed_at,
        created_by=row.created_by,
    )


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.get("", response_model=list[HuntResponse], summary="List hunt hypotheses")
async def list_hunts(
    db: DBSession,
    user: AuthUser,
    hunt_status: str | None = Query(None, alias="status"),
    priority: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[HuntResponse]:
    wheres = ["tenant_id = :tenant_id"]
    params: dict[str, Any] = {
        "tenant_id": user.tenant_id,
        "limit": limit,
        "offset": offset,
    }
    if hunt_status:
        wheres.append("status = :status")
        params["status"] = hunt_status
    if priority:
        wheres.append("priority = :priority")
        params["priority"] = priority

    q = text(f"SELECT * FROM aisoc_hunts WHERE {' AND '.join(wheres)} ORDER BY created_at DESC LIMIT :limit OFFSET :offset").bindparams(
        **params
    )
    try:
        rows = (await db.execute(q)).fetchall()
        return [_row_to_hunt(r) for r in rows]
    except Exception as exc:
        logger.exception("Database error in hunts endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.post("", response_model=HuntResponse, status_code=status.HTTP_201_CREATED, summary="Create hunt hypothesis")
async def create_hunt(body: CreateHuntRequest, db: DBSession, user: AuthUser) -> HuntResponse:
    mitre = body.mitre_technique or body.mitre_tactic
    # In air-gapped mode the LLM call is refused (AirgapViolation); fall back to
    # the deterministic query templates so hunt creation still succeeds offline
    # rather than surfacing a 500. Mirrors the phishing submit/retriage pattern.
    try:
        queries = await _generate_queries(body.hypothesis, mitre) or _fallback_queries(body.hypothesis)
    except AirgapViolation:
        queries = _fallback_queries(body.hypothesis)
    hunt_id = uuid.uuid4()
    now = datetime.now(UTC)
    q = text("""
        INSERT INTO aisoc_hunts (
            id, tenant_id, title, hypothesis, mitre_tactic, mitre_technique,
            priority, assigned_to, tags, query_esql, query_spl, query_kql,
            created_at, updated_at, created_by
        ) VALUES (
            :id, :tenant_id, :title, :hypothesis, :tactic, :technique,
            :priority, :assigned, CAST(:tags AS TEXT[]), :esql, :spl, :kql,
            :now, :now, :user
        ) RETURNING *
    """).bindparams(
        id=hunt_id,
        tenant_id=user.tenant_id,
        title=body.title,
        hypothesis=body.hypothesis,
        tactic=body.mitre_tactic,
        technique=body.mitre_technique,
        priority=body.priority,
        assigned=body.assigned_to,
        tags=body.tags or [],
        esql=queries.get("esql"),
        spl=queries.get("spl"),
        kql=queries.get("kql"),
        now=now,
        user=user.email or "system",
    )
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return _row_to_hunt(row)
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in hunts endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.get("/{hunt_id}", response_model=HuntResponse, summary="Get hunt")
async def get_hunt(hunt_id: uuid.UUID, db: DBSession, user: AuthUser) -> HuntResponse:
    row = (
        await db.execute(
            text("SELECT * FROM aisoc_hunts WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=hunt_id, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Hunt not found.")
    return _row_to_hunt(row)


@router.patch("/{hunt_id}", response_model=HuntResponse, summary="Update hunt")
async def update_hunt(hunt_id: uuid.UUID, body: UpdateHuntRequest, db: DBSession, user: AuthUser) -> HuntResponse:
    sets = ["updated_at = :now"]
    params: dict[str, Any] = {
        "id": hunt_id,
        "tenant_id": user.tenant_id,
        "now": datetime.now(UTC),
    }

    if body.title is not None:
        sets.append("title = :title")
        params["title"] = body.title
    if body.hypothesis is not None:
        sets.append("hypothesis = :hypothesis")
        params["hypothesis"] = body.hypothesis
    if body.mitre_tactic is not None:
        sets.append("mitre_tactic = :tactic")
        params["tactic"] = body.mitre_tactic
    if body.mitre_technique is not None:
        sets.append("mitre_technique = :technique")
        params["technique"] = body.mitre_technique
    if body.status is not None:
        sets.append("status = :status")
        params["status"] = body.status
        if body.status == "completed":
            sets.append("completed_at = :now")
    if body.priority is not None:
        sets.append("priority = :priority")
        params["priority"] = body.priority
    if body.assigned_to is not None:
        sets.append("assigned_to = :assigned")
        params["assigned"] = body.assigned_to
    if body.query_esql is not None:
        sets.append("query_esql = :esql")
        params["esql"] = body.query_esql
    if body.query_spl is not None:
        sets.append("query_spl = :spl")
        params["spl"] = body.query_spl
    if body.query_kql is not None:
        sets.append("query_kql = :kql")
        params["kql"] = body.query_kql
    if body.tags is not None:
        sets.append("tags = CAST(:tags AS TEXT[])")
        params["tags"] = body.tags

    q = text(f"UPDATE aisoc_hunts SET {', '.join(sets)} WHERE id = :id AND tenant_id = :tenant_id RETURNING *").bindparams(**params)
    try:
        row = (await db.execute(q)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Hunt not found.")
        await db.commit()
        return _row_to_hunt(row)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in hunts endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.post("/{hunt_id}/run", response_model=HuntRunResponse, status_code=status.HTTP_200_OK, summary="Execute hunt query")
async def run_hunt(hunt_id: uuid.UUID, body: RunHuntRequest, db: DBSession, user: AuthUser) -> HuntRunResponse:
    hunt_row = (
        await db.execute(
            text("SELECT * FROM aisoc_hunts WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=hunt_id, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not hunt_row:
        raise HTTPException(status_code=404, detail="Hunt not found.")

    query_map = {"esql": hunt_row.query_esql, "spl": hunt_row.query_spl, "kql": hunt_row.query_kql}
    query = query_map.get(body.platform)
    hit_count = 0
    result_sample: list[dict[str, Any]] = []
    error_msg: str | None = None
    start = datetime.now(UTC)

    if body.platform == "esql" and query:
        es_url = os.getenv("ELASTICSEARCH_URL")
        es_key = os.getenv("ELASTICSEARCH_API_KEY")
        if es_url and es_key:
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(
                        f"{es_url.rstrip('/')}/_query",
                        headers={"Authorization": f"ApiKey {es_key}", "Content-Type": "application/json"},
                        json={"query": query},
                    )
                if resp.status_code == 200:
                    data = resp.json()
                    rows = data.get("rows", [])
                    cols = [c["name"] for c in data.get("columns", [])]
                    hit_count = len(rows)
                    result_sample = [{cols[i]: row[i] for i in range(len(cols))} for row in rows[:20]]
                else:
                    error_msg = f"ES returned {resp.status_code}: {resp.text[:200]}"
            except Exception as exc:
                error_msg = str(exc)[:300]
        else:
            error_msg = "ELASTICSEARCH_URL or ELASTICSEARCH_API_KEY not configured."
    elif not query:
        error_msg = f"No {body.platform} query set for this hunt."
    else:
        error_msg = f"{body.platform} live execution not supported — query stored for manual use."

    duration_ms = int((datetime.now(UTC) - start).total_seconds() * 1000)
    run_id = uuid.uuid4()
    q = text("""
        INSERT INTO aisoc_hunt_runs (
            id, tenant_id, hunt_id, platform, query_used, hit_count,
            result_sample, duration_ms, error
        )
        VALUES (
            :id, :tenant_id, :hunt_id, :platform, :query, :hits,
            CAST(:sample AS JSONB), :dur, :err
        ) RETURNING *
    """).bindparams(
        id=run_id,
        tenant_id=user.tenant_id,
        hunt_id=hunt_id,
        platform=body.platform,
        query=query,
        hits=hit_count,
        sample=json.dumps(result_sample),
        dur=duration_ms,
        err=error_msg,
    )
    try:
        row = (await db.execute(q)).fetchone()
        await db.commit()
        return HuntRunResponse(
            id=row.id,
            hunt_id=row.hunt_id,
            run_at=row.run_at,
            platform=row.platform,
            query_used=row.query_used,
            hit_count=row.hit_count,
            result_sample=list(row.result_sample or []),
            duration_ms=row.duration_ms,
            error=row.error,
        )
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in hunts endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc


@router.get("/{hunt_id}/runs", response_model=list[HuntRunResponse], summary="List hunt runs")
async def list_runs(hunt_id: uuid.UUID, db: DBSession, user: AuthUser) -> list[HuntRunResponse]:
    # Authorize: ensure the parent hunt belongs to the caller's tenant before
    # listing runs (covers historical runs whose own tenant_id might be NULL).
    parent = (
        await db.execute(
            text("SELECT 1 FROM aisoc_hunts WHERE id = :id AND tenant_id = :tenant_id").bindparams(id=hunt_id, tenant_id=user.tenant_id)
        )
    ).fetchone()
    if not parent:
        raise HTTPException(status_code=404, detail="Hunt not found.")

    rows = (
        await db.execute(
            text("SELECT * FROM aisoc_hunt_runs WHERE hunt_id = :id AND tenant_id = :tenant_id ORDER BY run_at DESC LIMIT 100").bindparams(
                id=hunt_id, tenant_id=user.tenant_id
            )
        )
    ).fetchall()
    return [
        HuntRunResponse(
            id=r.id,
            hunt_id=r.hunt_id,
            run_at=r.run_at,
            platform=r.platform,
            query_used=r.query_used,
            hit_count=r.hit_count,
            result_sample=list(r.result_sample or []),
            duration_ms=r.duration_ms,
            error=r.error,
        )
        for r in rows
    ]


@router.post("/{hunt_id}/findings", response_model=HuntResponse, summary="Append findings")
async def add_findings(hunt_id: uuid.UUID, body: AddFindingsRequest, db: DBSession, user: AuthUser) -> HuntResponse:
    existing = (
        await db.execute(
            text("SELECT findings FROM aisoc_hunts WHERE id = :id AND tenant_id = :tenant_id").bindparams(
                id=hunt_id, tenant_id=user.tenant_id
            )
        )
    ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Hunt not found.")

    merged = list(existing.findings or []) + body.findings
    params: dict[str, Any] = {
        "id": hunt_id,
        "tenant_id": user.tenant_id,
        "findings": json.dumps(merged),
        "now": datetime.now(UTC),
    }
    extra_set = ""
    if body.false_positive_rate is not None:
        extra_set = ", false_positive_rate = :fpr"
        params["fpr"] = body.false_positive_rate

    q = text(
        f"UPDATE aisoc_hunts SET findings = CAST(:findings AS JSONB), updated_at = :now{extra_set} "
        "WHERE id = :id AND tenant_id = :tenant_id RETURNING *"
    ).bindparams(**params)
    try:
        row = (await db.execute(q)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Hunt not found.")
        await db.commit()
        return _row_to_hunt(row)
    except HTTPException:
        raise
    except Exception as exc:
        await db.rollback()
        logger.exception("Database error in hunts endpoint")
        raise HTTPException(status_code=503, detail="Database error") from exc
