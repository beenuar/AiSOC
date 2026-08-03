"""Persistent agent decision ledger (Phase 1A).

Writes investigation runs, events, and artifacts to the same Postgres tables
created by ``services/api/migrations/008_investigation_ledger.sql``.

The agents service uses raw ``asyncpg`` for these writes — it's the only
service that needs database access and we don't want to drag in the full
SQLAlchemy stack just for three tables. The API service exposes the read
side via SQLAlchemy ORM models in ``services/api/app/models/investigation.py``.

Design notes
------------
* All writes are best-effort. If the database is unreachable we log and
  continue — the agent's primary job is to investigate, not to be a
  bookkeeping service. The realtime stream is unaffected.
* The ``investigation_events`` table is append-only and per-run sequence is
  enforced by a ``UNIQUE(run_id, seq)`` constraint, so the writer must keep a
  monotonic counter per run.
* ``tenant_id`` is required by the RLS policies. The agent currently passes a
  string tenant id (e.g. ``"default"``); we resolve it to the canonical UUID
  by looking it up in the ``tenants`` table on first write per run.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime
from typing import Any

import asyncpg
import structlog

logger = structlog.get_logger()


class LedgerPersistError(RuntimeError):
    """Raised by the durable write paths (e.g. :func:`persist_auto_triage`) when
    a real database error occurs, so the caller can retry / dead-letter instead
    of silently losing the outcome (issue #571). A *missing* database (no
    ``DATABASE_URL``) is NOT an error — those paths no-op and return ``False``.
    """


_POOL: asyncpg.Pool | None = None


def _normalise_dsn(url: str) -> str:
    """Convert SQLAlchemy-style DSNs to plain Postgres ones for asyncpg."""
    return url.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")


async def get_pool() -> asyncpg.Pool | None:
    """Lazy-init a connection pool. Returns None if no DATABASE_URL is set."""
    global _POOL
    if _POOL is not None:
        return _POOL

    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        logger.debug("ledger.disabled", reason="DATABASE_URL not set")
        return None

    try:
        _POOL = await asyncpg.create_pool(
            dsn=_normalise_dsn(dsn),
            min_size=1,
            max_size=4,
            command_timeout=10,
        )
        logger.info("ledger.pool_initialised")
        return _POOL
    except Exception as exc:  # noqa: BLE001
        logger.warning("ledger.pool_init_failed", error=str(exc))
        return None


async def close_pool() -> None:
    global _POOL
    if _POOL is not None:
        await _POOL.close()
        _POOL = None


async def _resolve_tenant_id(conn: asyncpg.Connection, tenant_ref: str) -> uuid.UUID | None:
    """Look up the canonical tenant UUID. Accepts a UUID string, slug, or name.

    Returns None if no matching tenant exists. Callers should fall back to
    skipping the write rather than violating the FK.
    """
    # If already a UUID, trust it
    try:
        return uuid.UUID(tenant_ref)
    except (ValueError, TypeError):
        pass

    row = await conn.fetchrow(
        """
        SELECT id FROM tenants
        WHERE slug = $1 OR name = $1
        LIMIT 1
        """,
        tenant_ref,
    )
    return row["id"] if row else None


async def _set_rls_context(conn: asyncpg.Connection, tenant_id: uuid.UUID) -> None:
    """Match the API service's set_rls_context — required so the audit-log
    immutability trigger and tenant policies allow our INSERTs."""
    await conn.execute("SELECT set_config('app.tenant_id', $1, true)", str(tenant_id))


async def start_run(
    *,
    run_id: uuid.UUID,
    case_id: str,
    tenant_ref: str,
    alert_summary: str,
    raw_alert: dict[str, Any] | None,
    model_used: str | None = None,
) -> uuid.UUID | None:
    """Insert a new ``investigation_runs`` row. Returns the resolved tenant
    UUID on success (caller can cache it for subsequent writes), None on
    failure."""
    pool = await get_pool()
    if pool is None:
        return None

    try:
        async with pool.acquire() as conn:
            tenant_id = await _resolve_tenant_id(conn, tenant_ref)
            if tenant_id is None:
                logger.debug(
                    "ledger.skip_run",
                    reason="unknown_tenant",
                    tenant_ref=tenant_ref,
                )
                return None
            await _set_rls_context(conn, tenant_id)
            await conn.execute(
                """
                INSERT INTO investigation_runs
                  (id, tenant_id, case_id, alert_summary, raw_alert,
                   model_used, status, started_at, created_at)
                VALUES
                  ($1, $2, $3, $4, $5::jsonb, $6, 'running', now(), now())
                ON CONFLICT (id) DO NOTHING
                """,
                run_id,
                tenant_id,
                case_id,
                alert_summary[:8000] if alert_summary else None,
                json.dumps(raw_alert or {}),
                model_used,
            )
            logger.info(
                "ledger.run_started",
                run_id=str(run_id),
                case_id=case_id,
                tenant_id=str(tenant_id),
            )
            return tenant_id
    except Exception as exc:  # noqa: BLE001
        logger.warning("ledger.start_run_failed", run_id=str(run_id), error=str(exc))
        return None


async def record_event(
    *,
    run_id: uuid.UUID,
    tenant_id: uuid.UUID,
    seq: int,
    kind: str,
    agent: str,
    summary: str,
    payload: dict[str, Any] | None = None,
    input_hash: str | None = None,
    output_hash: str | None = None,
    duration_ms: int = 0,
    timestamp: datetime | None = None,
) -> uuid.UUID | None:
    """Append an immutable event row. Returns the new event id, or None."""
    pool = await get_pool()
    if pool is None:
        return None

    event_id = uuid.uuid4()
    ts = timestamp or datetime.utcnow()

    try:
        async with pool.acquire() as conn:
            await _set_rls_context(conn, tenant_id)
            await conn.execute(
                """
                INSERT INTO investigation_events
                  (id, run_id, tenant_id, seq, ts, kind, agent, summary,
                   payload, input_hash, output_hash, duration_ms, created_at)
                VALUES
                  ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11, $12, now())
                ON CONFLICT (run_id, seq) DO NOTHING
                """,
                event_id,
                run_id,
                tenant_id,
                seq,
                ts,
                kind,
                agent,
                summary[:8000],
                json.dumps(payload or {}),
                input_hash,
                output_hash,
                duration_ms,
            )
            return event_id
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "ledger.record_event_failed",
            run_id=str(run_id),
            seq=seq,
            kind=kind,
            error=str(exc),
        )
        return None


async def record_artifact(
    *,
    run_id: uuid.UUID,
    tenant_id: uuid.UUID,
    kind: str,
    content: str,
    event_id: uuid.UUID | None = None,
) -> uuid.UUID | None:
    """Persist a large blob (LLM transcript, full report) inline.

    For now we store inline ``TEXT`` rather than offloading to S3 — the
    schema reserves ``blob_ref`` for later. SHA-256 of the content is
    always recorded so callers can verify integrity.
    """
    pool = await get_pool()
    if pool is None:
        return None

    artifact_id = uuid.uuid4()
    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()
    size = len(content.encode("utf-8"))

    try:
        async with pool.acquire() as conn:
            await _set_rls_context(conn, tenant_id)
            await conn.execute(
                """
                INSERT INTO investigation_artifacts
                  (id, run_id, event_id, tenant_id, kind, content,
                   sha256, size_bytes, created_at)
                VALUES
                  ($1, $2, $3, $4, $5, $6, $7, $8, now())
                """,
                artifact_id,
                run_id,
                event_id,
                tenant_id,
                kind,
                content,
                sha,
                size,
            )
            return artifact_id
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "ledger.record_artifact_failed",
            run_id=str(run_id),
            kind=kind,
            error=str(exc),
        )
        return None


async def complete_run(
    *,
    run_id: uuid.UUID,
    tenant_id: uuid.UUID,
    status: str,
    error: str | None = None,
    iterations: int = 0,
    total_tokens: int = 0,
    total_cost_usd: float = 0.0,
) -> None:
    """Finalise the run. Status should be 'completed' or 'failed'."""
    pool = await get_pool()
    if pool is None:
        return

    try:
        async with pool.acquire() as conn:
            await _set_rls_context(conn, tenant_id)
            await conn.execute(
                """
                UPDATE investigation_runs
                   SET status = $2,
                       error = $3,
                       iterations = $4,
                       total_tokens = $5,
                       total_cost_usd = $6,
                       completed_at = now()
                 WHERE id = $1
                """,
                run_id,
                status,
                error,
                iterations,
                total_tokens,
                total_cost_usd,
            )
            logger.info(
                "ledger.run_completed",
                run_id=str(run_id),
                status=status,
                iterations=iterations,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "ledger.complete_run_failed",
            run_id=str(run_id),
            error=str(exc),
        )


def _coerce_uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


async def persist_auto_triage(
    *,
    run_id: uuid.UUID,
    alert_id: str | None,
    tenant_ref: str,
    alert_summary: str,
    raw_alert: dict[str, Any] | None,
    tier: str,
    verdict: str,
    confidence: float,
    rationale: str,
    findings: list[str] | None = None,
    proposed_actions: list[dict[str, Any]] | None = None,
    auto_closed: bool = False,
    iterations: int = 0,
    tokens: int = 0,
    cost_usd: float = 0.0,
) -> bool:
    """Durably record an auto-triage outcome (issue #571) in ONE transaction:

    * upsert the ``investigation_runs`` row (idempotent on ``id``),
    * append the verdict as an immutable ``investigation_events`` row (seq 1),
    * mark the run completed, and
    * write the disposition/verdict + rationale + recommendations back onto the
      ``alerts`` row so the alert API surfaces the automated verdict.

    Idempotent: a replay reuses the deterministic ``run_id`` (ON CONFLICT DO
    NOTHING on the run + the ``(run_id, seq)`` event key), so it never
    duplicates ledger rows or outcomes.

    Returns ``True`` when written, ``False`` when skipped (no database
    configured, or an unknown tenant — neither is retryable). Raises
    :class:`LedgerPersistError` on a real DB error so the caller can retry /
    dead-letter. A completed run therefore always carries a non-null verdict.
    """
    pool = await get_pool()
    if pool is None:
        return False

    verdict = (verdict or "").strip() or "needs_review"
    recommendations = proposed_actions or []
    alert_uuid = _coerce_uuid(alert_id)

    try:
        async with pool.acquire() as conn:
            tenant_id = await _resolve_tenant_id(conn, tenant_ref)
            if tenant_id is None:
                logger.debug("ledger.auto_triage_skip", reason="unknown_tenant", tenant_ref=tenant_ref)
                return False
            await _set_rls_context(conn, tenant_id)
            async with conn.transaction():
                await conn.execute(
                    """
                    INSERT INTO investigation_runs
                      (id, tenant_id, case_id, alert_summary, raw_alert,
                       model_used, status, started_at, created_at)
                    VALUES
                      ($1, $2, $3, $4, $5::jsonb, $6, 'running', now(), now())
                    ON CONFLICT (id) DO NOTHING
                    """,
                    run_id,
                    tenant_id,
                    str(alert_id or ""),
                    (alert_summary or "")[:8000] or None,
                    json.dumps(raw_alert or {}),
                    f"kafka:auto_triage:{tier}",
                )
                await conn.execute(
                    """
                    INSERT INTO investigation_events
                      (id, run_id, tenant_id, seq, ts, kind, agent, summary,
                       payload, duration_ms, created_at)
                    VALUES
                      ($1, $2, $3, 1, now(), 'triage_verdict', $4, $5, $6::jsonb, 0, now())
                    ON CONFLICT (run_id, seq) DO NOTHING
                    """,
                    uuid.uuid4(),
                    run_id,
                    tenant_id,
                    f"auto_triage:{tier}",
                    f"verdict={verdict} confidence={confidence:.2f}"[:8000],
                    json.dumps(
                        {
                            "verdict": verdict,
                            "confidence": confidence,
                            "rationale": rationale,
                            "findings": findings or [],
                            "proposed_actions": recommendations,
                            "auto_closed": auto_closed,
                        }
                    ),
                )
                await conn.execute(
                    """
                    UPDATE investigation_runs
                       SET status = 'completed', iterations = $2,
                           total_tokens = $3, total_cost_usd = $4, completed_at = now()
                     WHERE id = $1
                    """,
                    run_id,
                    iterations,
                    tokens,
                    cost_usd,
                )
                if alert_uuid is not None:
                    # Surface the automated verdict on the alert row. Status is
                    # only advanced to 'resolved' when auto-triage auto-closed a
                    # benign/FP alert at high confidence; otherwise the alert
                    # stays open for escalation / human review.
                    await conn.execute(
                        """
                        UPDATE alerts
                           SET disposition = $3,
                               ai_score = $4,
                               ai_summary = $5,
                               ai_recommendations = $6::jsonb,
                               status = CASE WHEN $7 THEN 'resolved' ELSE status END,
                               resolved_at = CASE WHEN $7 THEN now() ELSE resolved_at END,
                               updated_at = now()
                         WHERE id = $1 AND tenant_id = $2
                        """,
                        alert_uuid,
                        tenant_id,
                        verdict[:50],
                        float(confidence),
                        (rationale or "")[:8000] or None,
                        json.dumps(recommendations),
                        auto_closed,
                    )
        logger.info(
            "ledger.auto_triage_persisted",
            run_id=str(run_id),
            verdict=verdict,
            auto_closed=auto_closed,
            alert_id=str(alert_id or ""),
        )
        return True
    except Exception as exc:  # noqa: BLE001 — re-raised as a typed, retryable error
        logger.warning("ledger.auto_triage_persist_failed", run_id=str(run_id), error=str(exc))
        raise LedgerPersistError(str(exc)) from exc
