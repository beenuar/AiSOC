"""Tenant lake API endpoints — Workstream 7.

Two surfaces:

* ``POST /api/v1/lake/sql`` — execute a tenant-scoped SELECT against
  the warm tier (ClickHouse). Untrusted SQL is parsed and rewritten by
  :mod:`app.services.lake_sql` before it ever reaches the driver, so a
  caller cannot escape their tenant or invoke DML/DDL.
* ``GET /api/v1/lake/schema`` — return column metadata for the lake's
  allowlisted tables so an operator (or an LLM) can author queries
  without guessing column names.

Layered defences (top to bottom):

1. Authn + authz (``lake:query`` / ``lake:read_schema`` permission).
2. Per-tenant token-bucket rate limiter
   (:class:`app.services.lake_rate_limit.LakeRateLimiter`).
3. SQL rewriter — single SELECT, allowlisted tables only,
   ``tenant_id`` predicate injected, ``LIMIT`` clamped.
4. ClickHouse client with hard server-side caps on time, memory,
   threads, network egress.
5. Audit log entry capturing referenced tables + row count + elapsed.

The endpoints deliberately don't echo the rewritten SQL back to the
caller. Doing so would let a curious operator infer the rewriter's
exact behaviour (which is fine in our threat model) but it would also
log the resolved tenant predicate to anyone with browser devtools open,
which is needless leakage. The structured log line keeps it for
operators who need to debug.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy import text as sa_text

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.config import settings as app_settings
from app.core.logging import safe_log_value
from app.db.clickhouse import (
    LakeQueryError,
    LakeQueryNotConfiguredError,
    LakeQueryTimeoutError,
    execute_lake_query,
    fetch_lake_schema,
)
from app.models.lake_archive import (
    LakeArchivePartition,
    LakeArchivePolicy,
    LakePortabilityExport,
    LakeRehydration,
)
from app.models.lake_query_job import LakeQueryJob
from app.security.credential_vault import get_vault
from app.services import lake_archive as archive_svc
from app.services.audit import emit_audit
from app.services.lake_cold_query import ColdEstimateUnavailable, ScanEstimate, estimate_scan
from app.services.lake_query_runner import cancel_job, claim_job, new_query_id, read_progress, run_job
from app.services.lake_rate_limit import get_lake_rate_limiter
from app.services.lake_sql import (
    ALLOWED_TABLES,
    DEFAULT_ROW_CAP,
    MAX_ROW_CAP,
    LakeSqlForbiddenError,
    LakeSqlSyntaxError,
    rewrite_for_tenant,
)
from app.services.retention import MAX_LAKE_DAYS, resolve_policy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/lake", tags=["lake"])


# Token cost for a SELECT execution. Schema reads are cheap so we
# charge the bucket less for them — see ``_SCHEMA_COST`` below. These
# constants intentionally live in the endpoint module rather than the
# limiter because they're a *policy* decision (how much should each
# call type cost?) not a *mechanism* decision (how does the bucket
# refill?). The limiter exposes the mechanism; the endpoint owns the
# pricing.
_QUERY_COST: float = 1.0
_SCHEMA_COST: float = 0.25


# Default ClickHouse wall-clock cap for the lake API. The driver also
# enforces ``max_execution_time``; this value is the asyncio-side
# ceiling and is intentionally a hair higher than the driver setting
# so we get the nicer server-side error message instead of a
# TimeoutError.
_DEFAULT_API_TIMEOUT_SECONDS: float = 30.0


# ----------------------------------------------------------------- schemas


class LakeQueryRequest(BaseModel):
    """Request body for ``POST /api/v1/lake/sql``.

    Only ``sql`` is required. ``row_cap`` lets an operator request a
    smaller-than-default result set (e.g. for paginated UIs); the
    rewriter clamps to :data:`MAX_ROW_CAP` regardless. ``timeout_seconds``
    likewise lets the caller fail fast — useful for agent loops where a
    30-second hang would compound into a wall-clock budget overrun.
    """

    sql: str = Field(
        ...,
        min_length=1,
        max_length=200_000,
        description=(
            "SELECT query to run against the warm tier. The server "
            "enforces a single-statement, allowlisted-tables-only "
            "policy and injects ``tenant_id`` predicates before "
            "execution. Use ``GET /api/v1/lake/schema`` to discover "
            f"available tables and columns. Allowed tables: "
            f"{', '.join(sorted(ALLOWED_TABLES))}."
        ),
    )
    row_cap: int | None = Field(
        default=None,
        ge=1,
        le=MAX_ROW_CAP,
        description=(f"Optional ``LIMIT`` clamp; defaults to {DEFAULT_ROW_CAP}, hard-capped at {MAX_ROW_CAP}."),
    )
    timeout_seconds: float | None = Field(
        default=None,
        gt=0,
        le=60.0,
        description=("Optional wall-clock cap. Defaults to the server cap (30s). Useful for agent loops that need to fail fast."),
    )
    force_sync: bool = Field(
        default=False,
        description=(
            "Run synchronously even when the estimate says the query must read the cold "
            "volume. Off by default: the synchronous path is bounded by the 30-second default "
            "and 60-second maximum above, and a cold read that does not fit inside them used "
            "to come back as a bare timeout with no indication of how much data was involved. "
            "Set this only when you already know the scan is small."
        ),
    )


class LakeQueryResponse(BaseModel):
    """Response body for ``POST /api/v1/lake/sql``.

    ``referenced_tables`` is the set of allowlisted tables the
    rewriter actually touched — it's surfaced for clients that want
    to flag "you queried raw_events" in a UI without re-parsing the
    SQL themselves.
    """

    columns: list[str]
    rows: list[list[Any]]
    row_count: int
    row_cap: int
    referenced_tables: list[str]
    elapsed_ms: int
    executed_at: datetime


class LakeColumnInfo(BaseModel):
    """One column within a lake table."""

    name: str
    type: str
    comment: str = ""


class LakeTableInfo(BaseModel):
    """One allowlisted lake table, with its columns."""

    table: str
    columns: list[LakeColumnInfo]


class LakeSchemaResponse(BaseModel):
    """Response body for ``GET /api/v1/lake/schema``.

    Wraps the table list in an envelope so we can extend the response
    later (e.g. with retention info or row-count estimates) without a
    breaking change.
    """

    tables: list[LakeTableInfo]


# ----------------------------------------------------------------- helpers


async def _acquire_or_429(
    *,
    response: Response,
    tenant_id: uuid.UUID,
    cost: float,
) -> None:
    """Charge the bucket; raise HTTP 429 if over budget.

    Stamps ``X-RateLimit-*`` headers on ``response`` for both the
    allowed and the denied paths so a client always knows where it
    stands. The denied path raises ``HTTPException(429)`` with the
    same headers reused on the error envelope.
    """
    limiter = get_lake_rate_limiter()
    decision = await limiter.acquire(tenant_id, cost=cost)

    headers = decision.to_headers()
    for name, value in headers.items():
        response.headers[name] = value

    if not decision.allowed:
        # We log denials at INFO so a noisy tenant shows up in
        # standard ops dashboards without flooding ERROR.
        logger.info(
            "lake.rate_limited tenant_id=%s cost=%.2f remaining=%.2f retry_after=%.2fs",
            tenant_id,
            cost,
            decision.remaining,
            decision.retry_after_seconds,
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="lake API rate limit exceeded",
            headers=headers,
        )


def _scrub_sql_for_log(sql: str, *, max_chars: int = 4_000) -> str:
    """Return a length-bounded version of ``sql`` for structured logs.

    The lake accepts up to 200 KB SQL per request; logging that
    verbatim would spam the ops pipeline. We trim to ~4 KB which is
    plenty for debugging while staying inside per-record limits on
    most log backends.
    """
    if len(sql) <= max_chars:
        return sql
    return f"{sql[:max_chars]}…<truncated {len(sql) - max_chars} chars>"


# ----------------------------------------------------------------- endpoints


@router.post(
    "/sql",
    response_model=LakeQueryResponse,
    status_code=status.HTTP_200_OK,
)
async def execute_lake_sql(
    body: LakeQueryRequest,
    response: Response,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
    db: DBSession,
) -> LakeQueryResponse:
    """Run a tenant-scoped SELECT against the warm tier.

    Pipeline:

    1. Rate-limit the tenant.
    2. Rewrite the SQL — adds ``tenant_id`` predicates and clamps
       ``LIMIT``. Errors here are 400 (syntax) or 403 (forbidden).
    3. Execute against ClickHouse with the configured timeout +
       resource caps. Errors here are 502 (driver/server error),
       422 (timeout / memory limit), or 503 (driver not configured).
    4. Audit-log the call. We record the rewriter's view of the
       query (referenced tables, effective row cap) rather than the
       raw SQL, because audit logs are user-facing and we don't want
       to round-trip a malformed or PII-laden SQL string into the
       compliance UI.
    """
    await _acquire_or_429(
        response=response,
        tenant_id=current_user.tenant_id,
        cost=_QUERY_COST,
    )

    # ---- Step 1: rewrite ------------------------------------------------
    try:
        rewrite = rewrite_for_tenant(
            body.sql,
            current_user.tenant_id,
            row_cap=body.row_cap,
        )
    except LakeSqlForbiddenError as exc:
        # Operator wrote real SQL but it violated policy (DML, DDL,
        # non-allowlisted table, table function). 403 conveys that
        # this is an authorisation outcome, not a typo.
        logger.info(
            "lake.sql.forbidden",
            extra={
                "tenant_id": current_user.tenant_id,
                "user": safe_log_value(current_user.email),
                "reason": safe_log_value(str(exc)),
                "sql": safe_log_value(_scrub_sql_for_log(body.sql)),
            },
        )
        # Best-effort audit: failed access attempt is worth a row.
        await _audit_query_attempt(
            db=db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            user_email=current_user.email,
            request=request,
            outcome="forbidden",
            reason=str(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"lake SQL forbidden: {exc}",
        ) from exc
    except LakeSqlSyntaxError as exc:
        logger.info(
            "lake.sql.syntax_error",
            extra={
                "tenant_id": current_user.tenant_id,
                "user": safe_log_value(current_user.email),
                "reason": safe_log_value(str(exc)),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"lake SQL invalid: {exc}",
        ) from exc

    # ---- Step 1b: is this a cold scan? ----------------------------------
    #
    # Depth 4.3. Before this, a query over the cold volume either returned
    # inside the published 30-second default or raised a bare timeout,
    # which tells an analyst nothing about whether a longer deadline would
    # have helped or how much data was involved.
    #
    # The routing rule deliberately does not predict a duration. Doing so
    # would need a bytes-per-second figure, and the only honest source for
    # one is a measurement on the deployment's own hardware. A query is
    # routed to a job when ClickHouse's own estimate says it must read the
    # cold volume, which is the case the plan names.
    estimate: ScanEstimate | None = None
    if not body.force_sync:
        try:
            estimate = await estimate_scan(rewrite.sql)
        except ColdEstimateUnavailable as exc:
            # Not fatal. An un-estimable query runs the way it always did,
            # because refusing it would make the lake unusable on a
            # deployment whose system tables this role cannot read. Logged
            # so a permanently unreadable estimator is visible rather than
            # silently turning the feature off.
            logger.info("lake.sql.estimate_unavailable tenant_id=%s reason=%s", current_user.tenant_id, exc)
        if estimate is not None and estimate.touches_cold:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail={
                    "error": "cold_scan",
                    "message": (
                        "this query reads the cold tier, which does not reliably finish inside the "
                        f"{_DEFAULT_API_TIMEOUT_SECONDS:.0f}s synchronous bound. Submit it to "
                        "POST /api/v1/lake/query-jobs, which reports progress, or set force_sync "
                        "if you already know the scan is small."
                    ),
                    "estimate": estimate.as_dict(),
                },
            )

    # ---- Step 2: execute ------------------------------------------------
    try:
        result = await execute_lake_query(
            rewrite.sql,
            timeout_seconds=body.timeout_seconds or _DEFAULT_API_TIMEOUT_SECONDS,
        )
    except LakeQueryNotConfiguredError as exc:
        # 503 not 500 — this is a deployment-level problem (operator
        # forgot to set CLICKHOUSE_HOST), not a programmer-level bug.
        logger.error(
            "lake.sql.not_configured tenant_id=%s reason=%s",
            current_user.tenant_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="lake backend not configured",
        ) from exc
    except LakeQueryTimeoutError as exc:
        logger.warning(
            "lake.sql.timeout tenant_id=%s user=%s tables=%s",
            current_user.tenant_id,
            current_user.email,
            sorted(rewrite.referenced_tables),
        )
        await _audit_query_attempt(
            db=db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            user_email=current_user.email,
            request=request,
            outcome="timeout",
            reason=str(exc),
            referenced_tables=sorted(rewrite.referenced_tables),
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"lake query timed out: {exc}",
        ) from exc
    except LakeQueryError as exc:
        # Generic ClickHouse failure (syntax it didn't like, memory
        # limit, etc.). 502 conveys "we tried, the backend complained".
        logger.warning(
            "lake.sql.backend_error tenant_id=%s user=%s reason=%s",
            current_user.tenant_id,
            current_user.email,
            exc,
        )
        await _audit_query_attempt(
            db=db,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
            user_email=current_user.email,
            request=request,
            outcome="backend_error",
            reason=str(exc),
            referenced_tables=sorted(rewrite.referenced_tables),
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"lake backend error: {exc}",
        ) from exc

    # ---- Step 3: success path -----------------------------------------
    logger.info(
        "lake.sql.ok tenant_id=%s user=%s tables=%s rows=%d elapsed_ms=%d",
        current_user.tenant_id,
        current_user.email,
        sorted(rewrite.referenced_tables),
        result.row_count,
        result.elapsed_ms,
    )
    await _audit_query_attempt(
        db=db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        user_email=current_user.email,
        request=request,
        outcome="ok",
        referenced_tables=sorted(rewrite.referenced_tables),
        row_count=result.row_count,
        elapsed_ms=result.elapsed_ms,
        row_cap=rewrite.row_cap,
    )

    return LakeQueryResponse(
        columns=result.columns,
        rows=result.rows,
        row_count=result.row_count,
        row_cap=rewrite.row_cap,
        referenced_tables=sorted(rewrite.referenced_tables),
        elapsed_ms=result.elapsed_ms,
        executed_at=datetime.utcnow(),
    )


# ----------------------------------------------- cold-tier query jobs
#
# Depth plan 4.3, third bullet. A cold-tier scan outlives its request, so
# it becomes a row rather than a coroutine: the API runs more than one
# replica, and an in-process registry would lose every job on a restart
# and 404 half of them on the other replica.


class LakeEstimateRequest(BaseModel):
    """Ask what a query would read, without running it."""

    sql: str = Field(..., min_length=1, max_length=200_000)
    row_cap: int | None = Field(default=None, ge=1, le=MAX_ROW_CAP)


class LakeEstimateResponse(BaseModel):
    estimated_rows: int
    estimated_parts: int
    estimated_bytes: int
    cold_bytes: int
    warm_bytes: int
    touches_cold: bool
    tables: list[str]
    #: ``None`` when no retrieval price is configured. Never 0.0, which
    #: would read as "free".
    estimated_usd: float | None
    cost_basis: str


class LakeQueryJobRequest(BaseModel):
    sql: str = Field(..., min_length=1, max_length=200_000)
    row_cap: int | None = Field(default=None, ge=1, le=MAX_ROW_CAP)


class LakeQueryJobResponse(BaseModel):
    """A job's state. The fields a console needs to show progress honestly."""

    id: uuid.UUID
    status: str
    referenced_tables: list[str]
    row_cap: int
    estimate: dict[str, Any]
    rows_read: int
    bytes_read: int
    total_rows_approx: int
    #: Nullable. ClickHouse publishes ``total_rows_approx`` best-effort,
    #: so a running query can have a numerator and no denominator — and a
    #: bar that invents 100% because the denominator was zero is worse
    #: than one that says it does not know.
    progress_ratio: float | None
    columns: list[str] | None
    rows: list[list[Any]] | None
    row_count: int | None
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


def _job_response(job: LakeQueryJob) -> LakeQueryJobResponse:
    return LakeQueryJobResponse(
        id=job.id,
        status=job.status,
        referenced_tables=list(job.referenced_tables or []),
        row_cap=job.row_cap,
        estimate=job.estimate or {},
        rows_read=job.rows_read,
        bytes_read=job.bytes_read,
        total_rows_approx=job.total_rows_approx,
        progress_ratio=job.progress_ratio,
        columns=list(job.result_columns) if job.result_columns else None,
        rows=job.result_rows,
        row_count=job.row_count,
        error=job.error,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
    )


def _rewrite_or_raise(sql: str, tenant_id: uuid.UUID, row_cap: int | None):
    try:
        return rewrite_for_tenant(sql, tenant_id, row_cap=row_cap)
    except LakeSqlForbiddenError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"lake SQL forbidden: {exc}") from exc
    except LakeSqlSyntaxError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"lake SQL invalid: {exc}") from exc


@router.post("/estimate", response_model=LakeEstimateResponse)
async def estimate_lake_sql(
    body: LakeEstimateRequest,
    response: Response,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
) -> LakeEstimateResponse:
    """What would this query read, and where does that data live?

    Charged at the schema rate rather than the query rate: an estimate
    runs ``EXPLAIN ESTIMATE`` and two system-table reads, none of which
    touch tenant data. Pricing it like a scan would train analysts to
    skip the estimate, which is the opposite of the point.
    """
    await _acquire_or_429(response=response, tenant_id=current_user.tenant_id, cost=_SCHEMA_COST)
    rewrite = _rewrite_or_raise(body.sql, current_user.tenant_id, body.row_cap)
    try:
        estimate = await estimate_scan(rewrite.sql)
    except ColdEstimateUnavailable as exc:
        # 503, not an empty estimate. "We could not estimate" and "this
        # reads nothing" are opposite answers and must not share a
        # response shape.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"the scan could not be estimated: {exc}",
        ) from exc
    return LakeEstimateResponse(**estimate.as_dict())


@router.post("/query-jobs", response_model=LakeQueryJobResponse, status_code=status.HTTP_202_ACCEPTED)
async def submit_lake_query_job(
    body: LakeQueryJobRequest,
    background: BackgroundTasks,
    response: Response,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
    db: DBSession,
) -> LakeQueryJobResponse:
    """Submit a query that is allowed to take longer than the synchronous bound.

    The estimate is taken once, here, and stored on the job. It is never
    recomputed: it is the number the analyst agreed to before the scan
    started, and moving it afterwards would make the record of what they
    were told untrue.
    """
    await _acquire_or_429(response=response, tenant_id=current_user.tenant_id, cost=_QUERY_COST)
    rewrite = _rewrite_or_raise(body.sql, current_user.tenant_id, body.row_cap)

    try:
        estimate = (await estimate_scan(rewrite.sql)).as_dict()
    except ColdEstimateUnavailable as exc:
        # The job still runs. An un-estimable query is exactly the one an
        # analyst most wants the progress state for, and refusing it here
        # would leave them with only the synchronous path that times out.
        logger.info("lake.job.estimate_unavailable tenant_id=%s reason=%s", current_user.tenant_id, exc)
        estimate = {"unavailable": str(exc)}

    job = LakeQueryJob(
        tenant_id=current_user.tenant_id,
        submitted_by=current_user.user_id,
        submitted_email=current_user.email,
        rewritten_sql=rewrite.sql,
        row_cap=rewrite.row_cap,
        referenced_tables=sorted(rewrite.referenced_tables),
        query_id="pending",
        estimate=estimate,
    )
    db.add(job)
    await db.flush()
    job.query_id = new_query_id(job.id)
    await db.commit()
    await db.refresh(job)

    await _audit_query_attempt(
        db=db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        user_email=current_user.email,
        request=request,
        outcome="job_submitted",
        referenced_tables=sorted(rewrite.referenced_tables),
        row_cap=rewrite.row_cap,
    )

    background.add_task(_start_job, job.id)
    logger.info(
        "lake.job.submitted job_id=%s tenant_id=%s tables=%s cold_bytes=%s",
        job.id,
        current_user.tenant_id,
        sorted(rewrite.referenced_tables),
        estimate.get("cold_bytes"),
    )
    return _job_response(job)


async def _start_job(job_id: uuid.UUID) -> None:
    """Claim and run one job.

    Separated from the endpoint so the claim is the same conditional
    UPDATE whether the job is started by the submitting replica or picked
    up later: two replicas must not both start one scan.
    """
    from app.db.database import AsyncSessionLocal  # noqa: PLC0415 — avoids an import cycle at module load

    async with AsyncSessionLocal() as session:
        if not await claim_job(session, job_id):
            logger.info("lake.job.already_claimed job_id=%s", job_id)
            return
    await run_job(AsyncSessionLocal, job_id)


@router.get("/query-jobs", response_model=list[LakeQueryJobResponse])
async def list_lake_query_jobs(
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
    db: DBSession,
    limit: int = 50,
) -> list[LakeQueryJobResponse]:
    result = await db.execute(
        select(LakeQueryJob)
        .where(LakeQueryJob.tenant_id == current_user.tenant_id)
        .order_by(LakeQueryJob.created_at.desc())
        .limit(max(1, min(limit, 200)))
    )
    return [_job_response(job) for job in result.scalars().all()]


async def _load_job(db: Any, tenant_id: uuid.UUID, job_id: uuid.UUID) -> LakeQueryJob:
    """Fetch one job, scoped to the caller's tenant.

    The predicate is in the query rather than left to row-level security
    alone: a job id is a handle a console holds, and RLS here is defence
    in depth rather than the only control.
    """
    result = await db.execute(
        select(LakeQueryJob).where(
            LakeQueryJob.id == job_id,
            LakeQueryJob.tenant_id == tenant_id,
        )
    )
    job = result.scalar_one_or_none()
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="lake query job not found")
    return job


@router.get("/query-jobs/{job_id}", response_model=LakeQueryJobResponse)
async def get_lake_query_job(
    job_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
    db: DBSession,
) -> LakeQueryJobResponse:
    """One job's state, with a live progress read while it is running.

    The live read is folded into the response but is **not** written back
    over a terminal state: a late progress row must not make a finished
    job look like it started again.
    """
    job = await _load_job(db, current_user.tenant_id, job_id)
    if job.status == "running":
        progress = await read_progress(job.query_id)
        if progress is not None:
            job.rows_read = progress.rows_read
            job.bytes_read = progress.bytes_read
            job.total_rows_approx = progress.total_rows_approx
            job.progress_ratio = progress.ratio
            await db.commit()
    return _job_response(job)


@router.post("/query-jobs/{job_id}/cancel", response_model=LakeQueryJobResponse)
async def cancel_lake_query_job(
    job_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
    db: DBSession,
) -> LakeQueryJobResponse:
    """Stop a running scan.

    A job that has already ended answers 409 rather than being quietly
    re-marked: cancelling a finished job would rewrite the record of what
    happened.
    """
    job = await _load_job(db, current_user.tenant_id, job_id)
    if not await cancel_job(db, job):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"this job already ended as {job.status!r}",
        )
    return _job_response(job)


@router.get(
    "/schema",
    response_model=LakeSchemaResponse,
    status_code=status.HTTP_200_OK,
)
async def get_lake_schema(
    response: Response,
    request: Request,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:read_schema"))],
    db: DBSession,
) -> LakeSchemaResponse:
    """Return column metadata for the lake's allowlisted tables.

    Schema discovery is read-only and never returns row data, so it's
    safe to grant to roles that should not be allowed to execute
    SELECTs (``viewer`` has ``lake:read_schema`` but not
    ``lake:query``). The response is also tenant-independent —
    everyone sees the same columns — but we still rate-limit and
    audit-log it so noisy clients can't drum the endpoint into a DoS.
    """
    await _acquire_or_429(
        response=response,
        tenant_id=current_user.tenant_id,
        cost=_SCHEMA_COST,
    )

    try:
        raw = await fetch_lake_schema()
    except LakeQueryNotConfiguredError as exc:
        logger.error(
            "lake.schema.not_configured tenant_id=%s reason=%s",
            current_user.tenant_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="lake backend not configured",
        ) from exc
    except LakeQueryTimeoutError as exc:
        logger.warning(
            "lake.schema.timeout tenant_id=%s reason=%s",
            current_user.tenant_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"lake schema lookup timed out: {exc}",
        ) from exc
    except LakeQueryError as exc:
        logger.warning(
            "lake.schema.backend_error tenant_id=%s reason=%s",
            current_user.tenant_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"lake backend error: {exc}",
        ) from exc

    tables = [
        LakeTableInfo(
            table=entry["table"],
            columns=[
                LakeColumnInfo(
                    name=col["name"],
                    type=col["type"],
                    comment=col.get("comment", ""),
                )
                for col in entry.get("columns", [])
            ],
        )
        for entry in raw
    ]

    logger.info(
        "lake.schema.ok tenant_id=%s user=%s tables=%d",
        current_user.tenant_id,
        current_user.email,
        len(tables),
    )

    # Schema reads are deliberately *not* audit-logged on the success
    # path — they reveal no tenant data and would otherwise dominate
    # the audit_log table with low-signal rows. Failed lookups are
    # already logged at WARN above; that's the operator-facing
    # signal. If compliance later wants schema access logged, the
    # audit helper below is symmetrical to the SQL path and easy to
    # call here as well.

    return LakeSchemaResponse(tables=tables)


# ----------------------------------------------------------------- audit


async def _audit_query_attempt(
    *,
    db: Any,
    tenant_id: uuid.UUID,
    user_id: uuid.UUID,
    user_email: str,
    request: Request,
    outcome: str,
    reason: str | None = None,
    referenced_tables: list[str] | None = None,
    row_count: int | None = None,
    elapsed_ms: int | None = None,
    row_cap: int | None = None,
) -> None:
    """Emit one ``audit_log`` row for a lake query attempt.

    We log denials and timeouts as well as successes because
    compliance auditors expect to see a row per access attempt
    against analyst-facing data, not just successful reads. The
    ``changes`` payload carries the structured details — referenced
    tables, row count, elapsed — without including the raw SQL,
    which can be very large and may quote operator-typed values that
    aren't safe to surface in a compliance UI.
    """
    try:
        await emit_audit(
            db=db,
            tenant_id=tenant_id,
            actor_id=user_id,
            actor_email=user_email,
            action="lake.query",
            resource="lake",
            resource_id=None,
            changes={
                "outcome": outcome,
                "reason": reason,
                "referenced_tables": referenced_tables or [],
                "row_count": row_count,
                "elapsed_ms": elapsed_ms,
                "row_cap": row_cap,
            },
            request=request,
            api_key_prefix=getattr(user_id, "api_key_prefix", None),
        )
    except Exception as exc:  # noqa: BLE001 — audit must never fail the call
        # Audit write failures must not break the user-facing response;
        # an audit_log outage shouldn't cause a 500 on every lake
        # query. We log loudly so ops can investigate.
        logger.error(
            "lake.audit.failed tenant_id=%s outcome=%s error=%s",
            tenant_id,
            outcome,
            exc,
        )


# ═══════════════════════════════════════════════════════════════════════════
# Archive tier (WS2): policy, partitions, rehydration, portability,
# attestation. Literal subpaths registered after the /query-jobs/{job_id}
# family above — distinct first segments, no shadowing; within the archive
# family, /archive-partitions/run registers before /{partition_id}/verify.
# ═══════════════════════════════════════════════════════════════════════════


class ArchivePolicyBody(BaseModel):
    enabled: bool = False
    archive_years: int = Field(7, ge=1, le=30)
    s3_endpoint: str = ""
    s3_bucket: str = ""
    s3_region: str = ""
    #: Write-only: accepted here, vault-encrypted at rest, never echoed back.
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    worm_declared: bool = False


class ArchivePolicyOut(BaseModel):
    tenant_id: uuid.UUID
    enabled: bool = False
    archive_years: int = 7
    s3_endpoint: str = ""
    s3_bucket: str = ""
    s3_region: str = ""
    credentials_present: bool = False
    worm_declared: bool = False


class ArchivePartitionOut(BaseModel):
    id: uuid.UUID
    month: str
    status: str
    row_count: int | None = None
    verified_at: str | None = None
    failure_reason: str | None = None


class RehydrationBody(BaseModel):
    range_start: datetime
    range_end: datetime
    #: Closed vocabulary; compiled into the loader's SELECT, never caller SQL.
    connector_type: str | None = None
    reason: str = Field(..., min_length=3)
    #: False: estimate only (the default — nothing moves). True: load.
    confirm: bool = False
    expiry_days: int = Field(7, ge=1, le=30)


class RehydrationOut(BaseModel):
    id: uuid.UUID
    status: str
    estimate: dict[str, Any]
    table_name: str = ""
    rows_loaded: int | None = None
    expires_at: str | None = None
    failure_reason: str | None = None


class PortabilityBody(BaseModel):
    range_start: datetime
    range_end: datetime
    s3_endpoint: str
    s3_bucket: str
    #: Per-request credentials for the tenant's own bucket. Used for the
    #: job; never persisted.
    s3_access_key: str
    s3_secret_key: str
    reason: str = Field(..., min_length=3)


@router.get("/archive-policy", response_model=ArchivePolicyOut)
async def get_archive_policy(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:read"))],
) -> ArchivePolicyOut:
    """The tenant's archive policy; an absent row is the honest default (off).
    Credentials are reported as present/absent, never echoed."""

    policy = await db.get(LakeArchivePolicy, current_user.tenant_id)
    if policy is None:
        return ArchivePolicyOut(tenant_id=current_user.tenant_id)
    return ArchivePolicyOut(
        tenant_id=policy.tenant_id,
        enabled=policy.enabled,
        archive_years=policy.archive_years,
        s3_endpoint=policy.s3_endpoint,
        s3_bucket=policy.s3_bucket,
        s3_region=policy.s3_region,
        credentials_present=bool(policy.s3_access_key_enc and policy.s3_secret_key_enc),
        worm_declared=policy.worm_declared,
    )


@router.put("/archive-policy", response_model=ArchivePolicyOut)
async def put_archive_policy(
    body: ArchivePolicyBody,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> ArchivePolicyOut:
    """Upsert the policy. Credentials are vault-encrypted before the row is
    written; omitting them on an update keeps the stored ones."""

    if body.enabled:
        try:
            archive_svc.validate_destination(body.s3_endpoint, body.s3_bucket)
        except archive_svc.ArchiveConfigError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    policy = await db.get(LakeArchivePolicy, current_user.tenant_id)
    if policy is None:
        policy = LakeArchivePolicy(tenant_id=current_user.tenant_id)
        db.add(policy)
    policy.enabled = body.enabled
    policy.archive_years = body.archive_years
    policy.s3_endpoint = body.s3_endpoint
    policy.s3_bucket = body.s3_bucket
    policy.s3_region = body.s3_region
    policy.worm_declared = body.worm_declared
    policy.updated_by = current_user.user_id
    if body.s3_access_key is not None and body.s3_secret_key is not None:
        vault = get_vault()
        policy.s3_access_key_enc = vault.encrypt(body.s3_access_key)
        policy.s3_secret_key_enc = vault.encrypt(body.s3_secret_key)
    elif body.enabled and not policy.s3_access_key_enc:
        raise HTTPException(
            status_code=422,
            detail="enabling the archive requires s3_access_key and s3_secret_key",
        )
    await db.commit()
    await db.refresh(policy)
    return ArchivePolicyOut(
        tenant_id=policy.tenant_id,
        enabled=policy.enabled,
        archive_years=policy.archive_years,
        s3_endpoint=policy.s3_endpoint,
        s3_bucket=policy.s3_bucket,
        s3_region=policy.s3_region,
        credentials_present=bool(policy.s3_access_key_enc),
        worm_declared=policy.worm_declared,
    )


@router.get("/archive-partitions", response_model=list[ArchivePartitionOut])
async def list_archive_partitions(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
) -> list[ArchivePartitionOut]:

    rows = (
        await db.execute(
            select(LakeArchivePartition)
            .where(LakeArchivePartition.tenant_id == current_user.tenant_id)
            .order_by(LakeArchivePartition.month.desc())
        )
    ).scalars()
    return [
        ArchivePartitionOut(
            id=p.id,
            month=f"{p.month:%Y-%m}",
            status=p.status,
            row_count=(p.manifest or {}).get("row_count"),  # type: ignore[arg-type]  # JSONB int by construction
            verified_at=p.verified_at.isoformat() if p.verified_at else None,
            failure_reason=p.failure_reason,
        )
        for p in rows
    ]


class ArchiveRunBody(BaseModel):
    #: "YYYY-MM"; the month must be strictly in the past (closed).
    month: str = Field(..., pattern=r"^\d{4}-\d{2}$")


@router.post("/archive-partitions/run", response_model=ArchivePartitionOut)
async def run_archive_export(
    body: ArchiveRunBody,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> ArchivePartitionOut:
    """Export one closed month now (the sweep worker does this on schedule;
    this is the operator's explicit trigger). Refuses an open month and a
    tenant without an enabled policy — with the reason, not a 500."""

    policy = await db.get(LakeArchivePolicy, current_user.tenant_id)
    if policy is None or not policy.enabled:
        raise HTTPException(status_code=422, detail="the archive policy is not enabled for this tenant")
    month = datetime.strptime(body.month + "-01", "%Y-%m-%d").replace(tzinfo=UTC).date()
    try:
        dest = archive_svc.destination_from_policy(
            {
                "s3_endpoint": policy.s3_endpoint,
                "s3_bucket": policy.s3_bucket,
                "s3_access_key_enc": policy.s3_access_key_enc,
                "s3_secret_key_enc": policy.s3_secret_key_enc,
            }
        )
        manifest = await archive_svc.export_month(current_user.tenant_id, month, dest, signing_key=app_settings.SECRET_KEY)
    except archive_svc.ArchiveConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — the lake or the bucket refused; name it
        logger.error("lake.archive.export_failed tenant=%s err=%s", current_user.tenant_id, exc)
        raise HTTPException(status_code=502, detail=f"export failed: {type(exc).__name__}") from exc

    existing = (
        await db.execute(
            select(LakeArchivePartition).where(
                LakeArchivePartition.tenant_id == current_user.tenant_id,
                LakeArchivePartition.month == month,
            )
        )
    ).scalar_one_or_none()
    if existing is None:
        existing = LakeArchivePartition(tenant_id=current_user.tenant_id, month=month)
        db.add(existing)
    existing.manifest = manifest
    existing.status = "exported"
    existing.failure_reason = None
    existing.exported_at = datetime.now(UTC)
    existing.verified_at = None
    await db.commit()
    await db.refresh(existing)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="lake.archive.export",
        resource="lake_archive_partition",
        resource_id=str(existing.id),
        changes={"month": body.month, "rows": manifest.get("row_count")},
    )
    return ArchivePartitionOut(
        id=existing.id,
        month=body.month,
        status=existing.status,
        row_count=int(str(manifest.get("row_count", 0))) or None,
        verified_at=None,
        failure_reason=None,
    )


@router.post("/archive-partitions/{partition_id}/verify", response_model=ArchivePartitionOut)
async def verify_archive_partition(
    partition_id: uuid.UUID,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> ArchivePartitionOut:
    """Re-read the bucket and compare with the manifest. 'exported' is a
    claim; this is what makes it 'verified' — or 'failed', naming what
    differed."""

    partition = await db.get(LakeArchivePartition, partition_id)
    if partition is None or partition.tenant_id != current_user.tenant_id:
        raise HTTPException(status_code=404, detail="partition not found")
    policy = await db.get(LakeArchivePolicy, current_user.tenant_id)
    if policy is None:
        raise HTTPException(status_code=422, detail="no archive policy row; cannot resolve the bucket")
    dest = archive_svc.destination_from_policy(
        {
            "s3_endpoint": policy.s3_endpoint,
            "s3_bucket": policy.s3_bucket,
            "s3_access_key_enc": policy.s3_access_key_enc,
            "s3_secret_key_enc": policy.s3_secret_key_enc,
        }
    )
    problems = await archive_svc.verify_partition(dict(partition.manifest or {}), dest)
    if problems:
        partition.status = "failed"
        partition.failure_reason = "; ".join(problems)
        partition.verified_at = None
    else:
        partition.status = "verified"
        partition.failure_reason = None
        partition.verified_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(partition)
    return ArchivePartitionOut(
        id=partition.id,
        month=f"{partition.month:%Y-%m}",
        status=partition.status,
        row_count=(partition.manifest or {}).get("row_count"),  # type: ignore[arg-type]  # JSONB int by construction
        verified_at=partition.verified_at.isoformat() if partition.verified_at else None,
        failure_reason=partition.failure_reason,
    )


@router.post("/rehydrations", response_model=RehydrationOut)
async def create_rehydration(
    body: RehydrationBody,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
) -> RehydrationOut:
    """Estimate first; load only on ``confirm=true``.

    The estimate is computed from the covering manifests — bytes, files,
    months are real numbers; retrieval cost is null unless the deployment
    configured a price. Every rehydration records requester and reason.
    """

    start = body.range_start.date()
    end = body.range_end.date()
    if start > end:
        raise HTTPException(status_code=422, detail="range_start must be on or before range_end")

    months = archive_svc.months_in_range(start, end)
    partitions = (
        (
            await db.execute(
                select(LakeArchivePartition).where(
                    LakeArchivePartition.tenant_id == current_user.tenant_id,
                    LakeArchivePartition.month.in_(months),
                )
            )
        )
        .scalars()
        .all()
    )
    if not partitions:
        raise HTTPException(
            status_code=422,
            detail=f"no archived partitions cover {start}..{end}; nothing to rehydrate",
        )
    manifests = [dict(p.manifest or {}) for p in partitions]
    estimate = archive_svc.estimate_from_manifests(manifests)

    row = LakeRehydration(
        tenant_id=current_user.tenant_id,
        range_start=start,
        range_end=end,
        filters={"connector_type": body.connector_type} if body.connector_type else {},
        estimate=estimate,
        status="estimated",
        requested_by=current_user.user_id,
        reason=body.reason,
        expires_at=archive_svc.rehydration_expiry(body.expiry_days),
    )
    db.add(row)
    await db.flush()

    if body.confirm:
        policy = await db.get(LakeArchivePolicy, current_user.tenant_id)
        if policy is None or not policy.s3_access_key_enc:
            raise HTTPException(status_code=422, detail="no archive credentials to read the bucket with")
        dest = archive_svc.destination_from_policy(
            {
                "s3_endpoint": policy.s3_endpoint,
                "s3_bucket": policy.s3_bucket,
                "s3_access_key_enc": policy.s3_access_key_enc,
                "s3_secret_key_enc": policy.s3_secret_key_enc,
            }
        )
        row.status = "loading"
        await db.flush()
        try:
            table, loaded = await archive_svc.load_rehydration(
                row.id,
                current_user.tenant_id,
                manifests,
                dest,
                connector_type=body.connector_type,
            )
            row.table_name = table
            row.rows_loaded = loaded
            row.status = "ready"
        except Exception as exc:  # noqa: BLE001 — a failed load is a named failure
            row.status = "failed"
            row.failure_reason = f"{type(exc).__name__}: {exc}"[:500]

    await db.commit()
    await db.refresh(row)
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="lake.rehydration." + ("load" if body.confirm else "estimate"),
        resource="lake_rehydration",
        resource_id=str(row.id),
        changes={"range": f"{start}..{end}", "reason": body.reason, "status": row.status},
    )
    return RehydrationOut(
        id=row.id,
        status=row.status,
        estimate=dict(row.estimate),
        table_name=row.table_name,
        rows_loaded=row.rows_loaded,
        expires_at=row.expires_at.isoformat(),
        failure_reason=row.failure_reason,
    )


@router.get("/rehydrations", response_model=list[RehydrationOut])
async def list_rehydrations(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
) -> list[RehydrationOut]:

    rows = (
        await db.execute(
            select(LakeRehydration)
            .where(LakeRehydration.tenant_id == current_user.tenant_id)
            .order_by(LakeRehydration.created_at.desc())
            .limit(100)
        )
    ).scalars()
    return [
        RehydrationOut(
            id=r.id,
            status=r.status,
            estimate=dict(r.estimate or {}),
            table_name=r.table_name,
            rows_loaded=r.rows_loaded,
            expires_at=r.expires_at.isoformat() if r.expires_at else None,
            failure_reason=r.failure_reason,
        )
        for r in rows
    ]


@router.post("/portability-exports", response_model=dict)
async def create_portability_export(
    body: PortabilityBody,
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("settings:write"))],
) -> dict:
    """Export a range to a bucket the TENANT names: Parquet + signed manifest
    + a schema document, readable with no AiSOC code (the gate proves it
    with DuckDB). Request credentials are used for the job, never persisted."""

    start = body.range_start.date()
    end = body.range_end.date()
    if start > end:
        raise HTTPException(status_code=422, detail="range_start must be on or before range_end")
    try:
        archive_svc.validate_destination(body.s3_endpoint, body.s3_bucket)
    except archive_svc.ArchiveConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    job = LakePortabilityExport(
        tenant_id=current_user.tenant_id,
        range_start=start,
        range_end=end,
        s3_endpoint=body.s3_endpoint,
        s3_bucket=body.s3_bucket,
        requested_by=current_user.user_id,
        reason=body.reason,
    )
    db.add(job)
    await db.flush()

    dest = archive_svc.Destination(
        endpoint=body.s3_endpoint,
        bucket=body.s3_bucket,
        access_key=body.s3_access_key,
        secret_key=body.s3_secret_key,
    )
    month_manifests: list[dict[str, Any]] = []
    failure: str | None = None
    for month in archive_svc.months_in_range(start, end):
        try:
            manifest = await archive_svc.export_month(
                current_user.tenant_id,
                month,
                dest,
                signing_key=app_settings.SECRET_KEY,
                prefix="aisoc-portability",
            )
            month_manifests.append(manifest)
        except archive_svc.ArchiveConfigError as exc:
            # An empty or open month inside the range is recorded, not fatal.
            month_manifests.append({"month": f"{month:%Y-%m}", "skipped": str(exc)})
        except Exception as exc:  # noqa: BLE001
            failure = f"{month:%Y-%m}: {type(exc).__name__}"
            break

    if failure:
        job.status = "failed"
        job.failure_reason = failure
    else:
        schema_doc = {
            "schema_version": archive_svc.ARCHIVE_SCHEMA_VERSION,
            "ocsf_version": archive_svc.OCSF_VERSION,
            "format": "parquet",
            "note": "Each month is one Parquet object; read with any Parquet reader.",
            "months": month_manifests,
        }
        job.manifest = {**schema_doc, "signature": archive_svc.sign_envelope(schema_doc, signing_key=app_settings.SECRET_KEY)}
        job.status = "complete"
        job.completed_at = datetime.now(UTC)
    await db.commit()
    await emit_audit(
        db=db,
        tenant_id=current_user.tenant_id,
        actor_id=current_user.user_id,
        actor_email=current_user.email,
        api_key_prefix=getattr(current_user, "api_key_prefix", None),
        action="lake.portability.export",
        resource="lake_portability_export",
        resource_id=str(job.id),
        changes={"range": f"{start}..{end}", "bucket": body.s3_bucket, "status": job.status},
    )
    return {"id": str(job.id), "status": job.status, "manifest": job.manifest, "failure_reason": job.failure_reason}


@router.get("/retention-attestation", response_model=dict)
async def get_retention_attestation(
    db: DBSession,
    current_user: Annotated[AuthUser, Depends(require_permission("lake:query"))],
) -> dict:
    """What is retained per tier, oldest row per tier, manifests verified,
    holds active — each figure from its own store, 'not measured' where a
    store cannot answer (WS2.4)."""

    policy_row = await db.execute(
        sa_text("SELECT raw_events_days FROM retention_policies WHERE tenant_id = :t"),
        {"t": str(current_user.tenant_id)},
    )
    stored = policy_row.scalar_one_or_none()
    lake_days = int(stored) if stored else resolve_policy(None).raw_events_days
    lake_days = min(lake_days, MAX_LAKE_DAYS)
    archive_policy = await db.get(LakeArchivePolicy, current_user.tenant_id)
    return await archive_svc.retention_attestation(
        db,
        current_user.tenant_id,
        lake_days=lake_days,
        worm_declared=bool(archive_policy and archive_policy.worm_declared),
    )
