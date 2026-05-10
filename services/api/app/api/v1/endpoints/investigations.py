"""Investigation Ledger API.

The agents service writes runs/events/artifacts directly to Postgres
(see ``services/agents/app/investigator/ledger.py`` and migration
``008_investigation_ledger.sql``). This module exposes the read side over
the tenant-scoped REST API so the web console and external auditors can
replay every agent decision.

Endpoints:

* ``GET /v1/investigations``                              - list runs for this tenant
* ``GET /v1/investigations/{run_id}``                     - run summary + counts
* ``GET /v1/investigations/{run_id}/events``              - paginated event timeline
* ``GET /v1/investigations/{run_id}/replay``              - full ordered event list
* ``GET /v1/investigations/{run_id}/timeline``            - scrubbable timeline with
                                                             decision-provenance annotations
                                                             and cross-attempt diffs
* ``GET /v1/investigations/{run_id}/explain``             - per-step deep-dive: prompt,
                                                             response, evidence, downstream
                                                             effects for a single ``seq``
* ``POST /v1/investigations/{run_id}/close``              - close run + generate summary artifact
* ``GET  /v1/investigations/{run_id}/summary.pdf``        - PDF export of investigation summary
* ``GET /v1/investigations/{run_id}/artifacts/{artifact_id}`` - blob payload

All endpoints respect tenant RLS via ``TenantDBSession``.
"""

from __future__ import annotations

import hashlib
import io
import textwrap
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.engine import RowMapping

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


class ModelCostBreakdown(BaseModel):
    """Per-model cost telemetry for a single run.

    Sourced from ``aisoc_run_costs`` (populated by ``CostTracker`` in the
    agents service). Lets operators audit which model drove spend on a
    given investigation.
    """

    model: str
    total_prompt_tokens: int
    total_completion_tokens: int
    total_cost_usd: float
    total_latency_ms: int
    call_count: int


class RunDetail(RunSummary):
    """Full run view including counts of attached children."""

    alert_summary: str | None
    event_count: int
    artifact_count: int
    model_costs: list[ModelCostBreakdown]


class CostAggregateRow(BaseModel):
    """Aggregate spend grouped by model across runs."""

    model: str
    runs: int
    calls: int
    total_prompt_tokens: int
    total_completion_tokens: int
    total_cost_usd: float
    total_latency_ms: int
    avg_cost_per_run: float
    avg_latency_per_call_ms: float


class CostAggregateResponse(BaseModel):
    window_days: int
    by_model: list[CostAggregateRow]
    totals: CostAggregateRow | None


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


def _aggregate_row(row: RowMapping) -> CostAggregateRow:
    """Convert a single ``aisoc_run_costs`` aggregate row into the API model.

    Centralises the SUM-COALESCE-cast dance and the divide-by-zero guards
    for the two derived averages so the per-model and totals branches stay
    consistent.
    """
    runs = int(row["runs"] or 0)
    calls = int(row["calls"] or 0)
    cost = float(row["total_cost_usd"] or 0.0)
    latency = int(row["total_latency_ms"] or 0)
    return CostAggregateRow(
        model=row["model"],
        runs=runs,
        calls=calls,
        total_prompt_tokens=int(row["total_prompt_tokens"] or 0),
        total_completion_tokens=int(row["total_completion_tokens"] or 0),
        total_cost_usd=cost,
        total_latency_ms=latency,
        avg_cost_per_run=(cost / runs) if runs else 0.0,
        avg_latency_per_call_ms=(latency / calls) if calls else 0.0,
    )


async def _fetch_model_costs(
    db: TenantDBSession,
    run_id: uuid.UUID,
) -> list[ModelCostBreakdown]:
    """Fetch per-model cost rows from ``aisoc_run_costs`` for one run.

    The agents service's ``CostTracker`` writes ``run_id`` as TEXT, so we
    cast at the query boundary. Tenant scoping is already enforced by the
    caller's prior ``_fetch_run`` check (``run_id`` is unique and tenant-
    bound in ``investigation_runs``). Returns an empty list when no
    telemetry rows exist — runs that predate the cost-tracker rollout
    still load cleanly.
    """
    result = await db.execute(
        text(
            """
            SELECT model,
                   total_prompt_tokens,
                   total_completion_tokens,
                   total_cost_usd,
                   total_latency_ms,
                   call_count
            FROM aisoc_run_costs
            WHERE run_id = :run_id
            ORDER BY total_cost_usd DESC, model ASC
            """
        ),
        {"run_id": str(run_id)},
    )
    rows = result.mappings().all()
    return [
        ModelCostBreakdown(
            model=row["model"],
            total_prompt_tokens=int(row["total_prompt_tokens"] or 0),
            total_completion_tokens=int(row["total_completion_tokens"] or 0),
            total_cost_usd=float(row["total_cost_usd"] or 0.0),
            total_latency_ms=int(row["total_latency_ms"] or 0),
            call_count=int(row["call_count"] or 0),
        )
        for row in rows
    ]


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
    q = select(InvestigationRun).where(InvestigationRun.tenant_id == current_user.tenant_id)
    if case_id:
        q = q.where(InvestigationRun.case_id == case_id)
    if status_filter:
        q = q.where(InvestigationRun.status == status_filter)
    q = q.order_by(InvestigationRun.started_at.desc()).limit(limit)

    result = await db.execute(q)
    runs = result.scalars().all()
    return [_run_to_summary(r) for r in runs]


@router.get("/costs/aggregate", response_model=CostAggregateResponse)
async def aggregate_costs(
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
    window_days: int = Query(
        default=30,
        ge=1,
        le=365,
        description="Look-back window in days (anchored on run start time)",
    ),
) -> CostAggregateResponse:
    """Aggregate LLM spend across investigation runs for this tenant.

    Joins ``aisoc_run_costs`` against ``investigation_runs`` on ``run_id``
    and filters by ``investigation_runs.tenant_id``. We deliberately do NOT
    filter on ``aisoc_run_costs.tenant_id`` directly: the agents service
    writes whatever ``tenant_id`` string the request carried (e.g. the slug
    ``"default"``), which need not match the API-side UUID. Anchoring on
    the run's canonical tenant column keeps the answer correct regardless
    of how the cost row was tagged, and cannot leak across tenants because
    ``investigation_runs`` is RLS-bound and we re-filter explicitly.

    Uses Postgres ``GROUPING SETS`` to compute per-model rows and the
    grand total in one round-trip; ``COUNT(DISTINCT run_id)`` then yields
    a correct run count for both groupings (a naive ``SUM(runs)`` across
    models would double-count runs that touched more than one model).
    """
    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT GROUPING(c.model)              AS is_total,
                       COALESCE(c.model, '__total__') AS model,
                       COUNT(DISTINCT c.run_id)       AS runs,
                       SUM(c.call_count)              AS calls,
                       SUM(c.total_prompt_tokens)     AS total_prompt_tokens,
                       SUM(c.total_completion_tokens) AS total_completion_tokens,
                       SUM(c.total_cost_usd)          AS total_cost_usd,
                       SUM(c.total_latency_ms)        AS total_latency_ms
                FROM aisoc_run_costs c
                JOIN investigation_runs r ON r.id::text = c.run_id
                WHERE r.tenant_id = :tenant_id
                  AND r.started_at >= now() - make_interval(days => :window_days)
                GROUP BY GROUPING SETS ((c.model), ())
                ORDER BY GROUPING(c.model), SUM(c.total_cost_usd) DESC
                """
                ),
                {
                    "tenant_id": current_user.tenant_id,
                    "window_days": window_days,
                },
            )
        )
        .mappings()
        .all()
    )

    by_model: list[CostAggregateRow] = []
    totals: CostAggregateRow | None = None
    for row in rows:
        if int(row["is_total"]) == 1:
            totals = _aggregate_row(row)
        else:
            by_model.append(_aggregate_row(row))

    return CostAggregateResponse(
        window_days=window_days,
        by_model=by_model,
        totals=totals,
    )


@router.get("/{run_id}", response_model=RunDetail)
async def get_run(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
) -> RunDetail:
    """Run summary plus count of attached events and artifacts."""
    run = await _fetch_run(db, run_id, current_user.tenant_id)

    event_count = (await db.execute(select(func.count(InvestigationEvent.id)).where(InvestigationEvent.run_id == run_id))).scalar_one()
    artifact_count = (
        await db.execute(select(func.count(InvestigationArtifact.id)).where(InvestigationArtifact.run_id == run_id))
    ).scalar_one()
    model_costs = await _fetch_model_costs(db, run_id)

    base = _run_to_summary(run)
    return RunDetail(
        **base.model_dump(),
        alert_summary=run.alert_summary,
        event_count=event_count,
        artifact_count=artifact_count,
        model_costs=model_costs,
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
    q = select(InvestigationEvent).where(InvestigationEvent.run_id == run_id).order_by(InvestigationEvent.seq.asc()).limit(max_events)
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
    q = select(InvestigationArtifact).where(InvestigationArtifact.run_id == run_id).order_by(InvestigationArtifact.created_at.asc())
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


# ---------------------------------------------------------------------------
# Close + auto-summary  (WS-D2)
# ---------------------------------------------------------------------------


class CloseRequest(BaseModel):
    """Optional analyst note appended to the auto-generated summary."""

    analyst_note: str | None = None


class ClosedSummary(BaseModel):
    """Response body for POST /close."""

    run_id: uuid.UUID
    status: str
    artifact_id: uuid.UUID
    summary_markdown: str


# ---------------------------------------------------------------------------
# Timeline schemas (WS-D3)
# ---------------------------------------------------------------------------


class TimelineDecision(BaseModel):
    """Agent decision provenance annotation for a single timeline node."""

    reason: str | None
    confidence: float | None
    next_phase: str | None
    tool_name: str | None
    tool_args: dict | None
    tool_result_summary: str | None


class TimelineNode(BaseModel):
    """One node in the scrubbable investigation timeline."""

    seq: int
    ts: datetime
    kind: str
    agent: str
    summary: str
    duration_ms: int
    decision: TimelineDecision | None
    has_artifact: bool
    diff_vs_prev_attempt: str | None


class TimelineResponse(BaseModel):
    """Full timeline for a closed or in-progress run.

    ``nodes`` are ordered by ``seq`` ascending. ``total_duration_ms`` is the
    wall-clock span from first to last event. ``attempt_count`` counts unique
    retry attempts inferred from ``agent_start`` events.
    """

    run_id: uuid.UUID
    case_id: str
    status: str
    total_duration_ms: int
    attempt_count: int
    nodes: list[TimelineNode]


def _extract_decision(event: InvestigationEvent) -> TimelineDecision | None:
    """Extract decision-provenance fields from an event's payload.

    The agent graph stores structured decision metadata in the JSONB
    ``payload`` column. The keys used here mirror ``StepKind`` labels in
    ``services/agents/app/investigator/state.py``.  We gracefully tolerate
    missing keys so older ledger rows still render without error.
    """
    if event.payload is None:
        return None
    p = event.payload
    reason = p.get("reason") or p.get("rationale") or p.get("explanation")
    confidence = p.get("confidence")
    try:
        confidence = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence = None

    next_phase = p.get("next_phase") or p.get("next_step") or p.get("transition")
    tool_name = p.get("tool") or p.get("tool_name") or p.get("action")
    tool_args = p.get("tool_args") or p.get("args") or p.get("parameters")
    result = p.get("result") or p.get("output") or p.get("tool_result")
    if isinstance(result, dict):
        tool_result_summary = result.get("summary") or result.get("message") or str(result)[:200]
    elif isinstance(result, str):
        tool_result_summary = result[:200]
    else:
        tool_result_summary = None

    if not any([reason, confidence, next_phase, tool_name]):
        return None
    return TimelineDecision(
        reason=reason,
        confidence=confidence,
        next_phase=next_phase,
        tool_name=tool_name,
        tool_args=tool_args,
        tool_result_summary=tool_result_summary,
    )


def _diff_vs_prev(
    events: list[InvestigationEvent],
    idx: int,
) -> str | None:
    """Produce a one-line diff annotation when the same agent re-ran a step.

    Compares ``summary`` text between the current event and the last event
    of the same ``kind`` and ``agent`` combination that occurred earlier
    in the same run.  Returns ``None`` when no prior attempt exists or the
    summaries are identical.
    """
    current = events[idx]
    for prior in reversed(events[:idx]):
        if prior.kind == current.kind and prior.agent == current.agent:
            if prior.summary == current.summary:
                return None
            old_words = set(prior.summary.split())
            new_words = set(current.summary.split())
            added = new_words - old_words
            removed = old_words - new_words
            parts: list[str] = []
            if removed:
                parts.append(f"-{len(removed)} words")
            if added:
                parts.append(f"+{len(added)} words")
            return f"Changed vs seq {prior.seq}: {', '.join(parts)}" if parts else None
    return None


@router.get("/{run_id}/timeline", response_model=TimelineResponse)
async def get_timeline(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
) -> TimelineResponse:
    """Return a scrubbable investigation timeline with decision-provenance annotations.

    Each node carries:
    * ``decision`` — structured provenance (reason, confidence, next phase,
      tool name/args/result) extracted from the event ``payload``.
    * ``has_artifact`` — whether a detailed transcript artifact is attached.
    * ``diff_vs_prev_attempt`` — one-line diff for repeated steps so analysts
      can see how the agent corrected itself across retry attempts.

    The response is bounded at 10 000 events. Use the paginated ``/events``
    endpoint for runs that exceed this.
    """
    run = await _fetch_run(db, run_id, current_user.tenant_id)

    events_q = select(InvestigationEvent).where(InvestigationEvent.run_id == run_id).order_by(InvestigationEvent.seq.asc()).limit(10000)
    events: list[InvestigationEvent] = list((await db.execute(events_q)).scalars().all())

    artifact_event_ids_q = select(InvestigationArtifact.event_id).where(
        InvestigationArtifact.run_id == run_id,
        InvestigationArtifact.event_id.isnot(None),
    )
    artifact_event_ids: set[uuid.UUID] = {eid for eid in (await db.execute(artifact_event_ids_q)).scalars().all() if eid is not None}

    nodes: list[TimelineNode] = []
    for idx, ev in enumerate(events):
        nodes.append(
            TimelineNode(
                seq=ev.seq,
                ts=ev.ts,
                kind=ev.kind,
                agent=ev.agent,
                summary=ev.summary,
                duration_ms=ev.duration_ms,
                decision=_extract_decision(ev),
                has_artifact=ev.id in artifact_event_ids,
                diff_vs_prev_attempt=_diff_vs_prev(events, idx),
            )
        )

    total_ms = 0
    if len(events) >= 2:
        first_ts = events[0].ts
        last_ts = events[-1].ts
        total_ms = int((last_ts - first_ts).total_seconds() * 1000)

    attempt_count = sum(1 for e in events if e.kind in ("agent_start", "run_start"))
    if attempt_count == 0:
        attempt_count = 1

    return TimelineResponse(
        run_id=run.id,
        case_id=run.case_id,
        status=run.status,
        total_duration_ms=total_ms,
        attempt_count=attempt_count,
        nodes=nodes,
    )


def _build_summary_markdown(
    run: InvestigationRun,
    events: list[InvestigationEvent],
    analyst_note: str | None,
) -> str:
    """Build a structured Markdown investigation summary from ORM objects.

    The summary is deterministic (no LLM call) so it is always available
    even in air-gapped / local-LLM mode. It mirrors the structure that
    WS-H3 (Audit export) will ingest.
    """
    started = run.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if run.started_at else "—"
    closed_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Tally event kinds
    kind_counts: dict[str, int] = {}
    for ev in events:
        kind_counts[ev.kind] = kind_counts.get(ev.kind, 0) + 1

    timeline_lines = []
    for ev in events[-20:]:  # last 20 steps to keep the artifact manageable
        ts = ev.ts.strftime("%H:%M:%S") if ev.ts else "—"
        timeline_lines.append(f"| {ts} | `{ev.kind}` | {ev.agent} | {ev.summary[:120]} |")

    timeline_md = (
        ("| Time | Kind | Agent | Summary |\n|------|------|-------|---------|  \n" + "\n".join(timeline_lines))
        if timeline_lines
        else "_No events recorded._"
    )

    note_section = f"\n## Analyst Note\n\n{analyst_note}\n" if analyst_note else ""

    return textwrap.dedent(f"""\
        # Investigation Summary — {run.case_id}

        **Run ID:** `{run.id}`
        **Status:** {run.status}
        **Model:** {run.model_used or "unknown"}
        **Started:** {started}
        **Closed:** {closed_at}

        ## Metrics

        | Metric | Value |
        |--------|-------|
        | Iterations | {run.iterations} |
        | Total tokens | {run.total_tokens:,} |
        | Estimated cost (USD) | ${float(run.total_cost_usd):.4f} |
        | Events recorded | {len(events)} |

        ## Event Kind Breakdown

        {chr(10).join(f"- **{k}**: {v}" for k, v in sorted(kind_counts.items()))}

        ## Timeline (last {min(20, len(events))} steps)

        {timeline_md}
        {note_section}
        ---
        *Generated by AiSOC — beenu@cyble.com*
    """)


@router.post("/{run_id}/close", response_model=ClosedSummary)
async def close_investigation(
    run_id: uuid.UUID,
    body: CloseRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:write"))],
    db: TenantDBSession,
) -> ClosedSummary:
    """Close an investigation run and persist an auto-generated summary artifact.

    Idempotent: if the run is already closed a summary artifact is still
    generated and returned (useful for re-generating the PDF).

    Status transitions: ``running | completed | failed`` → ``closed``
    """
    run = await _fetch_run(db, run_id, current_user.tenant_id)

    # Load all events for summary generation
    events_result = await db.execute(
        select(InvestigationEvent).where(InvestigationEvent.run_id == run_id).order_by(InvestigationEvent.seq.asc())
    )
    events = list(events_result.scalars().all())

    summary_md = _build_summary_markdown(run, events, body.analyst_note)
    encoded = summary_md.encode()
    sha = hashlib.sha256(encoded).hexdigest()

    artifact = InvestigationArtifact(
        run_id=run_id,
        tenant_id=current_user.tenant_id,
        kind="investigation-summary",
        content=summary_md,
        sha256=sha,
        size_bytes=len(encoded),
    )
    db.add(artifact)

    # Transition status to closed
    run.status = "closed"
    run.completed_at = run.completed_at or datetime.now(UTC)

    await db.commit()
    await db.refresh(artifact)

    return ClosedSummary(
        run_id=run_id,
        status="closed",
        artifact_id=artifact.id,
        summary_markdown=summary_md,
    )


@router.get("/{run_id}/summary.pdf")
async def export_summary_pdf(
    run_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("cases:read"))],
    db: TenantDBSession,
) -> StreamingResponse:
    """Stream the investigation summary as a PDF.

    Looks for the most recent ``investigation-summary`` artifact. If none
    exists yet the caller should ``POST /close`` first. The PDF is generated
    server-side using pure-Python ``reportlab`` so there are no browser or
    headless-Chrome dependencies.
    """
    await _fetch_run(db, run_id, current_user.tenant_id)

    # Fetch most recent summary artifact
    q = (
        select(InvestigationArtifact)
        .where(
            InvestigationArtifact.run_id == run_id,
            InvestigationArtifact.kind == "investigation-summary",
        )
        .order_by(InvestigationArtifact.created_at.desc())
        .limit(1)
    )
    art = (await db.execute(q)).scalar_one_or_none()
    if art is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No summary artifact found. POST /close first to generate one.",
        )

    pdf_bytes = _render_pdf(art.content or "", str(run_id))
    filename = f"investigation-{run_id}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _render_pdf(markdown_text: str, run_id: str) -> bytes:
    """Render Markdown text to a minimal PDF using reportlab.

    Falls back to a plain-text PDF if reportlab is not installed so the
    endpoint never 500s in environments that haven't installed the optional
    dependency.
    """
    try:
        from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
        from reportlab.lib.styles import getSampleStyleSheet  # type: ignore[import-untyped]
        from reportlab.lib.units import cm  # type: ignore[import-untyped]
        from reportlab.platypus import (  # type: ignore[import-untyped]
            Paragraph,
            SimpleDocTemplate,
            Spacer,
        )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = getSampleStyleSheet()
        story = []

        for line in markdown_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("# "):
                story.append(Paragraph(stripped[2:], styles["Title"]))
            elif stripped.startswith("## "):
                story.append(Spacer(1, 0.3 * cm))
                story.append(Paragraph(stripped[3:], styles["Heading2"]))
            elif stripped.startswith("| "):
                # Render table rows as monospace for readability
                story.append(Paragraph(f"<font name='Courier' size='8'>{stripped}</font>", styles["Normal"]))
            elif stripped.startswith("- "):
                story.append(Paragraph(f"• {stripped[2:]}", styles["Normal"]))
            elif stripped.startswith("*") and stripped.endswith("*"):
                story.append(Spacer(1, 0.2 * cm))
                story.append(Paragraph(f"<i>{stripped.strip('*')}</i>", styles["Normal"]))
            elif stripped:
                story.append(Paragraph(stripped, styles["Normal"]))
            else:
                story.append(Spacer(1, 0.2 * cm))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        # reportlab not installed — emit a plain-text PDF-like fallback
        header = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        body = markdown_text.encode("utf-8", errors="replace")
        return header + body
