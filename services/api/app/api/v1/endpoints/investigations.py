"""Investigation Ledger API.

The agents service writes runs/events/artifacts directly to Postgres
(see ``services/agents/app/investigator/ledger.py`` and migration
``008_investigation_ledger.sql``). This module exposes the read side over
the tenant-scoped REST API so the web console and external auditors can
replay every agent decision.

Endpoints:

* ``GET /v1/investigations``                    - list runs for this tenant
* ``GET /v1/investigations/{run_id}``           - run summary + counts
* ``GET /v1/investigations/{run_id}/events``    - paginated event timeline
* ``GET /v1/investigations/{run_id}/replay``    - full ordered event list
* ``GET /v1/investigations/{run_id}/explain``   - per-step deep-dive: prompt,
                                                   response, evidence, downstream
                                                   effects for a single ``seq``
* ``GET /v1/investigations/{run_id}/artifacts/{artifact_id}`` - blob payload

All endpoints respect tenant RLS via ``TenantDBSession``.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.v1.deps import AuthUser, require_permission
from app.db.rls import TenantDBSession
from app.models.investigation import (
    InvestigationArtifact,
    InvestigationEvent,
    InvestigationRun,
)

router = APIRouter(prefix="/investigations", tags=["investigations"])


# ---------------------------------------------------------------------------
# Output schemas
# ---------------------------------------------------------------------------


class RunSummary(BaseModel):
    """Compact view of a run for list endpoints."""

    id: uuid.UUID
    case_id: str
    status: str
    model_used: str | None
    iterations: int
    total_tokens: int
    total_cost_usd: float
    started_at: datetime
    completed_at: datetime | None
    error: str | None


class RunDetail(RunSummary):
    """Full run view including counts of attached children."""

    alert_summary: str | None
    event_count: int
    artifact_count: int


class EventOut(BaseModel):
    id: uuid.UUID
    run_id: uuid.UUID
    seq: int
    ts: datetime
    kind: str
    agent: str
    summary: str
    payload: dict | None
    input_hash: str | None
    output_hash: str | None
    duration_ms: int


class EventListResponse(BaseModel):
    items: list[EventOut]
    total: int
    since: int | None
    next_seq: int | None


class ArtifactSummary(BaseModel):
    id: uuid.UUID
    kind: str
    sha256: str
    size_bytes: int
    event_id: uuid.UUID | None
    created_at: datetime


class ArtifactDetail(ArtifactSummary):
    content: str | None
    blob_ref: str | None


class ExplainResponse(BaseModel):
    """Why-did-the-agent-do-this view for a single step.

    Includes the focal event plus the immediately preceding event (the
    decision that led into this step) and the immediately following event
    (the decision the agent made afterwards). Artifacts attached to the
    focal event are inlined so the auditor sees the literal LLM transcript.
    """

    run: RunSummary
    previous: EventOut | None
    focus: EventOut
    next: EventOut | None
    artifacts: list[ArtifactDetail]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_to_summary(run: InvestigationRun) -> RunSummary:
    return RunSummary(
        id=run.id,
        case_id=run.case_id,
        status=run.status,
        model_used=run.model_used,
        iterations=run.iterations,
        total_tokens=run.total_tokens,
        total_cost_usd=float(run.total_cost_usd),
        started_at=run.started_at,
        completed_at=run.completed_at,
        error=run.error,
    )


def _event_to_out(event: InvestigationEvent) -> EventOut:
    return EventOut(
        id=event.id,
        run_id=event.run_id,
        seq=event.seq,
        ts=event.ts,
        kind=event.kind,
        agent=event.agent,
        summary=event.summary,
        payload=event.payload,
        input_hash=event.input_hash,
        output_hash=event.output_hash,
        duration_ms=event.duration_ms,
    )


async def _fetch_run(
    db: TenantDBSession,
    run_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> InvestigationRun:
    result = await db.execute(
        select(InvestigationRun).where(
            InvestigationRun.id == run_id,
            InvestigationRun.tenant_id == tenant_id,
        )
    )
    run = result.scalar_one_or_none()
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation run not found",
        )
    return run


# ---------------------------------------------------------------------------
# List + detail
# ---------------------------------------------------------------------------


@router.get("", response_model=list[RunSummary])
async def list_runs(
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
    case_id: str | None = Query(default=None, description="Filter by external case id"),
    status_filter: str | None = Query(
        default=None,
        alias="status",
        description="Filter by status: running | completed | failed",
    ),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[RunSummary]:
    """List recent investigation runs for the caller's tenant."""
    q = select(InvestigationRun).where(
        InvestigationRun.tenant_id == current_user.tenant_id
    )
    if case_id:
        q = q.where(InvestigationRun.case_id == case_id)
    if status_filter:
        q = q.where(InvestigationRun.status == status_filter)
    q = q.order_by(InvestigationRun.started_at.desc()).limit(limit)

    result = await db.execute(q)
    runs = result.scalars().all()
    return [_run_to_summary(r) for r in runs]


@router.get("/{run_id}", response_model=RunDetail)
async def get_run(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
) -> RunDetail:
    """Run summary plus count of attached events and artifacts."""
    run = await _fetch_run(db, run_id, current_user.tenant_id)

    event_count = (
        await db.execute(
            select(func.count(InvestigationEvent.id)).where(
                InvestigationEvent.run_id == run_id
            )
        )
    ).scalar_one()
    artifact_count = (
        await db.execute(
            select(func.count(InvestigationArtifact.id)).where(
                InvestigationArtifact.run_id == run_id
            )
        )
    ).scalar_one()

    base = _run_to_summary(run)
    return RunDetail(
        **base.model_dump(),
        alert_summary=run.alert_summary,
        event_count=event_count,
        artifact_count=artifact_count,
    )


# ---------------------------------------------------------------------------
# Event timeline
# ---------------------------------------------------------------------------


@router.get("/{run_id}/events", response_model=EventListResponse)
async def list_events(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
    since: int | None = Query(
        default=None,
        ge=0,
        description="Return only events with seq strictly greater than this value (long-poll)",
    ),
    limit: int = Query(default=200, ge=1, le=1000),
) -> EventListResponse:
    """Paginated event stream for a run.

    The ``since`` cursor lets clients tail the stream — pass the previously
    returned ``next_seq`` to fetch the next page without overlap.
    """
    # 404 instead of empty if the run doesn't exist or isn't ours
    await _fetch_run(db, run_id, current_user.tenant_id)

    q = select(InvestigationEvent).where(InvestigationEvent.run_id == run_id)
    if since is not None:
        q = q.where(InvestigationEvent.seq > since)

    total_q = select(func.count()).select_from(q.subquery())
    total: int = (await db.execute(total_q)).scalar_one()

    q = q.order_by(InvestigationEvent.seq.asc()).limit(limit)
    events = (await db.execute(q)).scalars().all()

    next_seq = events[-1].seq if events else None
    return EventListResponse(
        items=[_event_to_out(e) for e in events],
        total=total,
        since=since,
        next_seq=next_seq,
    )


@router.get("/{run_id}/replay", response_model=list[EventOut])
async def replay_run(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
    max_events: int = Query(default=10000, ge=1, le=50000),
) -> list[EventOut]:
    """Return the full ordered event list for a run.

    Bounded by ``max_events`` to keep responses sane; runs that exceed the
    bound should fall back to the paginated ``/events`` endpoint.
    """
    await _fetch_run(db, run_id, current_user.tenant_id)
    q = (
        select(InvestigationEvent)
        .where(InvestigationEvent.run_id == run_id)
        .order_by(InvestigationEvent.seq.asc())
        .limit(max_events)
    )
    events = (await db.execute(q)).scalars().all()
    return [_event_to_out(e) for e in events]


# ---------------------------------------------------------------------------
# Explain (single-step deep dive)
# ---------------------------------------------------------------------------


@router.get("/{run_id}/explain", response_model=ExplainResponse)
async def explain_step(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
    step: int = Query(..., ge=0, alias="step", description="Event seq to explain"),
) -> ExplainResponse:
    """Return prompt + response + evidence for a single step.

    Renders three events for context: the previous decision that led into
    this step, the focal event, and the next decision. All artifacts
    attached to the focal event are inlined so the auditor sees the
    literal LLM transcript.
    """
    run = await _fetch_run(db, run_id, current_user.tenant_id)

    focus_q = select(InvestigationEvent).where(
        InvestigationEvent.run_id == run_id,
        InvestigationEvent.seq == step,
    )
    focus = (await db.execute(focus_q)).scalar_one_or_none()
    if focus is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No event with seq={step} for this run",
        )

    prev_q = (
        select(InvestigationEvent)
        .where(
            InvestigationEvent.run_id == run_id,
            InvestigationEvent.seq < step,
        )
        .order_by(InvestigationEvent.seq.desc())
        .limit(1)
    )
    nxt_q = (
        select(InvestigationEvent)
        .where(
            InvestigationEvent.run_id == run_id,
            InvestigationEvent.seq > step,
        )
        .order_by(InvestigationEvent.seq.asc())
        .limit(1)
    )
    prev = (await db.execute(prev_q)).scalar_one_or_none()
    nxt = (await db.execute(nxt_q)).scalar_one_or_none()

    arts_q = select(InvestigationArtifact).where(
        InvestigationArtifact.run_id == run_id,
        InvestigationArtifact.event_id == focus.id,
    )
    arts = (await db.execute(arts_q)).scalars().all()

    return ExplainResponse(
        run=_run_to_summary(run),
        previous=_event_to_out(prev) if prev else None,
        focus=_event_to_out(focus),
        next=_event_to_out(nxt) if nxt else None,
        artifacts=[
            ArtifactDetail(
                id=a.id,
                kind=a.kind,
                sha256=a.sha256,
                size_bytes=a.size_bytes,
                event_id=a.event_id,
                created_at=a.created_at,
                content=a.content,
                blob_ref=a.blob_ref,
            )
            for a in arts
        ],
    )


# ---------------------------------------------------------------------------
# Artifacts
# ---------------------------------------------------------------------------


@router.get("/{run_id}/artifacts", response_model=list[ArtifactSummary])
async def list_artifacts(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
) -> list[ArtifactSummary]:
    await _fetch_run(db, run_id, current_user.tenant_id)
    q = (
        select(InvestigationArtifact)
        .where(InvestigationArtifact.run_id == run_id)
        .order_by(InvestigationArtifact.created_at.asc())
    )
    arts = (await db.execute(q)).scalars().all()
    return [
        ArtifactSummary(
            id=a.id,
            kind=a.kind,
            sha256=a.sha256,
            size_bytes=a.size_bytes,
            event_id=a.event_id,
            created_at=a.created_at,
        )
        for a in arts
    ]


@router.get("/{run_id}/artifacts/{artifact_id}", response_model=ArtifactDetail)
async def get_artifact(
    run_id: uuid.UUID,
    artifact_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
) -> ArtifactDetail:
    await _fetch_run(db, run_id, current_user.tenant_id)
    q = select(InvestigationArtifact).where(
        InvestigationArtifact.run_id == run_id,
        InvestigationArtifact.id == artifact_id,
    )
    art = (await db.execute(q)).scalar_one_or_none()
    if art is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Artifact not found",
        )
    return ArtifactDetail(
        id=art.id,
        kind=art.kind,
        sha256=art.sha256,
        size_bytes=art.size_bytes,
        event_id=art.event_id,
        created_at=art.created_at,
        content=art.content,
        blob_ref=art.blob_ref,
    )
