"""Replay evaluation: start a run, poll it, read the report, export it.

Gap-closure Phase 1.4.

Not to be confused with ``endpoints/replay.py``
----------------------------------------------
That module publishes a redacted investigation ledger to a public share link
at ``/r/{slug}``. It is a different noun that happens to share a word, and it
is deliberately not extended here: a reader looking for share-link publishing
should not be handed replay evaluation, and the two have opposite privacy
postures. This one is tenant-scoped and authenticated throughout.

The tenant never appears in a request
--------------------------------------
Every route takes ``user.tenant_id`` from the authenticated principal. There
is no tenant field on any payload and no tenant path parameter. The connector
is named by its row id, and that row is loaded with a tenant predicate, so
naming another tenant's connector is a 404 rather than a read.

Permissions
-----------
Starting a run needs ``connectors:write``, the same bar as testing a
connector, because it does the same kind of thing: an outbound call to a
customer's own SIEM using stored credentials. Reading a report needs
``reports:read``, which every analyst role holds, because the report is the
artefact the evaluation exists to produce.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query, status
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app._vendor.aisoc_benchmark.replay import MIN_MALICIOUS_FOR_HEADLINE
from app.api.v1.deps import AuthUser, DBSession
from app.db.database import AsyncSessionLocal
from app.models.connector import Connector
from app.services.branding.resolver import resolve_branding
from app.services.replay_evaluation import report as report_export
from app.services.replay_evaluation import store
from app.services.replay_evaluation.job import (
    BOOTSTRAP_RESAMPLES,
    BOOTSTRAP_SEED,
    ReplayRequest,
    run_evaluation,
)
from app.services.replay_evaluation.vendors import (
    REPLAYABLE_CONNECTORS,
    UnsupportedConnector,
    vendor_for,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/evaluations", tags=["evaluations"])

#: Default window when the caller names neither end. Ninety days is long
#: enough for most queues to hold the 30 malicious cases the headline needs
#: and short enough that the estate being graded still resembles today's.
DEFAULT_WINDOW_DAYS = 90

#: Matches the agents service's own ceiling on one replay.
MAX_FINDINGS = 2000


class StartReplayRequest(BaseModel):
    """Which connector, which window, and how the report should be computed."""

    #: The saved connector row. Its type decides which reader runs and its
    #: vault-encrypted credentials are what reaches the vendor. A connector id
    #: belonging to another tenant resolves to nothing, because the row is
    #: loaded with a tenant predicate.
    connector_id: uuid.UUID
    since: datetime | None = None
    until: datetime | None = None
    #: The time split. Findings closed at or before the split point are the
    #: train window and fix the frozen context; only the later period is
    #: replayed and graded.
    train_fraction: float = Field(default=0.7, gt=0.0, lt=1.0)
    limit: int = Field(default=1000, ge=1, le=MAX_FINDINGS)
    #: Both travel onto the row and into the report. A caller who wants a
    #: different interval can ask for one and the report will say so.
    bootstrap_seed: int = BOOTSTRAP_SEED
    bootstrap_resamples: int = Field(default=BOOTSTRAP_RESAMPLES, ge=0, le=20000)


class EvaluationSummary(BaseModel):
    """One run as the list and the poll return it."""

    id: uuid.UUID
    status: str
    error: str | None = None
    connector_id: str
    vendor: str
    window_start: datetime
    window_end: datetime
    train_fraction: float
    bootstrap_seed: int
    bootstrap_resamples: int

    # Sample sizes, beside the headline rather than buried in the score, so a
    # reader sees how much was graded at the same moment they see the number.
    findings_read: int
    findings_labelled: int
    decisions_recorded: int
    graded: int
    malicious_support: int

    #: ``None`` when the corpus was too thin. Never 0, which would read as
    #: "the agent got every answer wrong". ``headline_withheld_reason``
    #: carries the sentence explaining which it is.
    headline_accuracy: float | None = None
    headline_withheld_reason: str | None = None
    malicious_recall: float | None = None

    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    is_terminal: bool


class EvaluationDetail(EvaluationSummary):
    """A completed run with its report and the provenance behind it."""

    score: dict[str, Any] | None = None
    method: dict[str, Any] | None = None
    report_markdown: str | None = None


class ReplayableConnectorInfo(BaseModel):
    connector_type: str
    vendor: str
    label: str


class CapabilitiesResponse(BaseModel):
    """What this deployment can replay, so the console offers nothing it cannot.

    ``min_malicious_for_headline`` travels to the client so the page can say
    why a headline is withheld before a run is started, rather than only
    after.
    """

    connectors: list[ReplayableConnectorInfo]
    default_window_days: int
    default_train_fraction: float
    default_bootstrap_seed: int
    default_bootstrap_resamples: int
    min_malicious_for_headline: int
    max_findings: int


def _summary(row: store.EvaluationRow) -> EvaluationSummary:
    return EvaluationSummary(
        id=row.id,
        status=row.status,
        error=row.error,
        connector_id=row.connector_id,
        vendor=row.vendor,
        window_start=row.window_start,
        window_end=row.window_end,
        train_fraction=row.train_fraction,
        bootstrap_seed=row.bootstrap_seed,
        bootstrap_resamples=row.bootstrap_resamples,
        findings_read=row.findings_read,
        findings_labelled=row.findings_labelled,
        decisions_recorded=row.decisions_recorded,
        graded=row.graded,
        malicious_support=row.malicious_support,
        headline_accuracy=row.headline_accuracy,
        headline_withheld_reason=row.headline_withheld_reason,
        malicious_recall=row.malicious_recall,
        created_at=row.created_at,
        started_at=row.started_at,
        completed_at=row.completed_at,
        is_terminal=row.is_terminal,
    )


def _detail(row: store.EvaluationRow) -> EvaluationDetail:
    return EvaluationDetail(
        **_summary(row).model_dump(),
        score=row.score,
        method=row.method,
        report_markdown=row.report_markdown,
    )


async def _run_detached(request: ReplayRequest) -> None:
    """Run the job on its own session.

    The request's session is closed when the response is returned, so the
    background task opens its own rather than using one that is about to go
    away. ``run_evaluation`` never raises: every failure lands on the row.
    """
    async with AsyncSessionLocal() as session:
        await run_evaluation(session, request)


@router.get(
    "/replay/capabilities",
    response_model=CapabilitiesResponse,
    summary="Which connectors can be replayed on this deployment",
)
async def capabilities(user: AuthUser) -> CapabilitiesResponse:
    user.require_permission("reports:read")
    # MIN_MALICIOUS_FOR_HEADLINE comes from the vendored scorer, so the floor
    # the console shows and the floor the renderer applies are the same
    # number rather than two that happen to agree today.
    return CapabilitiesResponse(
        connectors=[
            ReplayableConnectorInfo(connector_type=entry.connector_type, vendor=entry.vendor, label=entry.label)
            for _, entry in sorted(REPLAYABLE_CONNECTORS.items())
        ],
        default_window_days=DEFAULT_WINDOW_DAYS,
        default_train_fraction=0.7,
        default_bootstrap_seed=BOOTSTRAP_SEED,
        default_bootstrap_resamples=BOOTSTRAP_RESAMPLES,
        min_malicious_for_headline=MIN_MALICIOUS_FOR_HEADLINE,
        max_findings=MAX_FINDINGS,
    )


@router.post(
    "/replay",
    response_model=EvaluationSummary,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a replay evaluation against this tenant's own history",
)
async def start_replay(
    body: StartReplayRequest,
    background: BackgroundTasks,
    db: DBSession,
    user: AuthUser,
) -> EvaluationSummary:
    """Queue a run and return its id immediately.

    202 rather than 200: replaying a few hundred findings through a model is
    not a request-response operation, and a route that blocked on it would
    time out at whichever proxy is in front of it while the work continued.
    """
    user.require_permission("connectors:write")

    until = body.until or datetime.now(UTC)
    since = body.since or (until - timedelta(days=DEFAULT_WINDOW_DAYS))
    if until <= since:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"until ({until.isoformat()}) must be after since ({since.isoformat()})",
        )

    connector = await _load_connector_row(db, tenant_id=user.tenant_id, connector_id=body.connector_id)
    try:
        vendor = vendor_for(connector.connector_type)
    except UnsupportedConnector as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    evaluation_id = await store.create_evaluation(
        db,
        tenant_id=user.tenant_id,
        connector_id=str(body.connector_id),
        vendor=vendor,
        window_start=since,
        window_end=until,
        train_fraction=body.train_fraction,
        bootstrap_seed=body.bootstrap_seed,
        bootstrap_resamples=body.bootstrap_resamples,
        requested_by=user.user_id,
    )

    background.add_task(
        _run_detached,
        ReplayRequest(
            tenant_id=user.tenant_id,
            evaluation_id=evaluation_id,
            connector_row_id=body.connector_id,
            connector_type=connector.connector_type,
            vendor=vendor,
            window_start=since,
            window_end=until,
            train_fraction=body.train_fraction,
            limit=body.limit,
            bootstrap_seed=body.bootstrap_seed,
            bootstrap_resamples=body.bootstrap_resamples,
        ),
    )

    row = await store.get_evaluation(db, tenant_id=user.tenant_id, evaluation_id=evaluation_id, detailed=False)
    if row is None:  # pragma: no cover - the insert committed one line above
        raise HTTPException(status_code=500, detail="the evaluation row disappeared immediately after insert")
    logger.info(
        "replay.evaluation.queued",
        evaluation_id=str(evaluation_id),
        vendor=vendor,
        tenant_id=str(user.tenant_id),
    )
    return _summary(row)


@router.get("/replay", response_model=list[EvaluationSummary], summary="This tenant's replay evaluations")
async def list_replays(
    db: DBSession,
    user: AuthUser,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[EvaluationSummary]:
    user.require_permission("reports:read")
    rows = await store.list_evaluations(db, tenant_id=user.tenant_id, limit=limit)
    return [_summary(row) for row in rows]


@router.get("/replay/{evaluation_id}", response_model=EvaluationDetail, summary="One replay evaluation")
async def get_replay(evaluation_id: uuid.UUID, db: DBSession, user: AuthUser) -> EvaluationDetail:
    user.require_permission("reports:read")
    return _detail(await _require_evaluation(db, tenant_id=user.tenant_id, evaluation_id=evaluation_id))


@router.get(
    "/replay/{evaluation_id}/decisions",
    response_model=list[dict],
    summary="The decisions behind a report",
)
async def get_replay_decisions(
    evaluation_id: uuid.UUID,
    db: DBSession,
    user: AuthUser,
    limit: int = Query(default=2000, ge=1, le=MAX_FINDINGS),
) -> list[dict[str, Any]]:
    """Every replayed finding, so a disputed number can be re-derived.

    Read separately from the report because these rows carry the evidence
    handed to triage and are measured in megabytes, and the page that shows
    the headline should not pay for them.
    """
    user.require_permission("reports:read")
    await _require_evaluation(db, tenant_id=user.tenant_id, evaluation_id=evaluation_id)
    return await store.list_decisions(db, tenant_id=user.tenant_id, evaluation_id=evaluation_id, limit=limit)


@router.get("/replay/{evaluation_id}/export", summary="Export a report as JSON, Markdown or PDF")
async def export_replay(
    evaluation_id: uuid.UUID,
    db: DBSession,
    user: AuthUser,
    format: Literal["json", "markdown", "pdf"] = Query(default="markdown"),
    exclude_latency: bool = Query(
        default=False,
        description=(
            "Replace the two wall-clock latency figures with a note. Everything else in the report "
            "is a property of the input and the code, so two runs over one pinned window are then "
            "byte-identical; latency measures the host and never will be."
        ),
    ),
) -> Response:
    """Serve the stored report, not a fresh render of it.

    All three formats come from the artefact written when the run completed.
    Re-rendering later would produce a document that no longer matches what
    the operator read, and this phase's acceptance bar is a report that
    reproduces byte for byte.
    """
    user.require_permission("reports:read")
    row = await _require_evaluation(db, tenant_id=user.tenant_id, evaluation_id=evaluation_id)

    if row.status != "completed" or not row.report_markdown:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(f"this evaluation is '{row.status}' and has no report to export" + (f": {row.error}" if row.error else "")),
        )

    stem = f"aisoc-replay-{evaluation_id}"
    if format == "json":
        return Response(
            content=report_export.report_json(
                evaluation_id=str(evaluation_id),
                score=row.score,
                method=row.method,
                exclude_latency=exclude_latency,
            ),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{stem}.json"'},
        )

    markdown = report_export.report_markdown(row.report_markdown, exclude_latency=exclude_latency)
    if format == "markdown":
        return PlainTextResponse(
            content=markdown,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{stem}.md"'},
        )

    try:
        # Inlined, because WeasyPrint renders server-side: a referenced logo
        # would be an outbound request made by this service to an address a
        # customer administrator supplied.
        pdf = report_export.render_pdf(markdown, await resolve_branding(db, user.tenant_id, inline_logo=True))
    except report_export.PdfUnavailableError as exc:
        # 503 rather than 500: the report exists and the other two formats
        # work, so this is a missing capability on this deployment rather
        # than a failure of the evaluation.
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{stem}.pdf"'},
    )


async def _require_evaluation(db: AsyncSession, *, tenant_id: uuid.UUID, evaluation_id: uuid.UUID) -> store.EvaluationRow:
    row = await store.get_evaluation(db, tenant_id=tenant_id, evaluation_id=evaluation_id)
    if row is None:
        # 404 rather than 403 for a row in another tenant. The query carries
        # the tenant predicate, so "not yours" and "not there" are the same
        # answer here and telling them apart would confirm the id exists.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="evaluation not found")
    return row


async def _load_connector_row(db: AsyncSession, *, tenant_id: uuid.UUID, connector_id: uuid.UUID) -> Connector:
    """The tenant's own connector row, or a 404.

    The tenant predicate is in the WHERE clause rather than checked after the
    fetch, so another tenant's connector id resolves to no row rather than to
    a row this code then decides to refuse.
    """
    row = (await db.execute(select(Connector).where(Connector.id == connector_id, Connector.tenant_id == tenant_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="connector not found")
    return row
