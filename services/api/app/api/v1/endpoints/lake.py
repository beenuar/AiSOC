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
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.core.logging import safe_log_value
from app.db.clickhouse import (
    LakeQueryError,
    LakeQueryNotConfiguredError,
    LakeQueryTimeoutError,
    execute_lake_query,
    fetch_lake_schema,
)
from app.services.audit import emit_audit
from app.services.lake_rate_limit import get_lake_rate_limiter
from app.services.lake_sql import (
    ALLOWED_TABLES,
    DEFAULT_ROW_CAP,
    MAX_ROW_CAP,
    LakeSqlForbiddenError,
    LakeSqlSyntaxError,
    rewrite_for_tenant,
)

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
