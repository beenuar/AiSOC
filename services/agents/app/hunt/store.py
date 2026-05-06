"""Hunt persistence — best-effort writes to ``hunt_hypotheses`` /
``hunt_runs`` / ``hunt_findings``.

Mirrors :mod:`app.investigator.ledger`: raw asyncpg, lazy-initialised pool,
RLS context set on every connection, all writes wrapped so a database
outage never takes the scheduler offline.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

import asyncpg
import structlog

from .engine import HuntFindingDraft, HuntRunResult
from .loader import HuntDefinition

logger = structlog.get_logger()


_POOL: asyncpg.Pool | None = None


def _normalise_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://").replace(
        "postgres+asyncpg://", "postgresql://"
    )


async def _get_pool() -> asyncpg.Pool | None:
    global _POOL
    if _POOL is not None:
        return _POOL
    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        logger.debug("hunt.store.disabled", reason="DATABASE_URL not set")
        return None
    try:
        _POOL = await asyncpg.create_pool(
            dsn=_normalise_dsn(dsn),
            min_size=1,
            max_size=4,
            command_timeout=10,
        )
        logger.info("hunt.store.pool_initialised")
        return _POOL
    except Exception as exc:  # noqa: BLE001
        logger.warning("hunt.store.pool_init_failed", error=str(exc))
        return None


async def close_pool() -> None:
    global _POOL
    if _POOL is not None:
        await _POOL.close()
        _POOL = None


async def _resolve_tenant_id(conn: asyncpg.Connection, tenant_ref: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(tenant_ref)
    except (ValueError, TypeError):
        pass
    row = await conn.fetchrow(
        "SELECT id FROM tenants WHERE slug = $1 OR name = $1 LIMIT 1",
        tenant_ref,
    )
    return row["id"] if row else None


async def _set_rls_context(conn: asyncpg.Connection, tenant_id: uuid.UUID) -> None:
    await conn.execute("SELECT set_config('app.tenant_id', $1, true)", str(tenant_id))


# ---------------------------------------------------------------------------
# Catalog sync — keep ``hunt_hypotheses`` table in sync with the YAML corpus
# ---------------------------------------------------------------------------


async def sync_catalog(
    hunts: list[HuntDefinition],
    *,
    tenant_ref: str = "default",
) -> int:
    """Upsert each YAML hunt into the ``hunt_hypotheses`` table.

    The hunts directory is the source of truth; the database row is just a
    cache so the API/UI can list and inspect hunts without re-reading the
    filesystem on every request. Returns the number of rows touched.
    """
    pool = await _get_pool()
    if pool is None or not hunts:
        return 0

    touched = 0
    try:
        async with pool.acquire() as conn:
            tenant_id = await _resolve_tenant_id(conn, tenant_ref)
            if tenant_id is None:
                logger.debug(
                    "hunt.store.catalog.skip", reason="unknown_tenant", tenant_ref=tenant_ref
                )
                return 0
            await _set_rls_context(conn, tenant_id)

            for hunt in hunts:
                await conn.execute(
                    """
                    INSERT INTO hunt_hypotheses
                      (tenant_id, hunt_id, name, description, version,
                       severity, category, tags, log_sources,
                       schedule_enabled, interval_minutes, jitter_seconds,
                       hypothesis, expected, refs, author, source_sha256,
                       created_at, updated_at)
                    VALUES
                      ($1, $2, $3, $4, $5,
                       $6, $7, $8::text[], $9::text[],
                       $10, $11, $12,
                       $13::jsonb, $14::jsonb, $15::text[], $16, $17,
                       NOW(), NOW())
                    ON CONFLICT (tenant_id, hunt_id) DO UPDATE SET
                       name = EXCLUDED.name,
                       description = EXCLUDED.description,
                       version = EXCLUDED.version,
                       severity = EXCLUDED.severity,
                       category = EXCLUDED.category,
                       tags = EXCLUDED.tags,
                       log_sources = EXCLUDED.log_sources,
                       schedule_enabled = EXCLUDED.schedule_enabled,
                       interval_minutes = EXCLUDED.interval_minutes,
                       jitter_seconds = EXCLUDED.jitter_seconds,
                       hypothesis = EXCLUDED.hypothesis,
                       expected = EXCLUDED.expected,
                       refs = EXCLUDED.refs,
                       author = EXCLUDED.author,
                       source_sha256 = EXCLUDED.source_sha256,
                       updated_at = NOW()
                    """,
                    tenant_id,
                    hunt.id,
                    hunt.name,
                    hunt.description,
                    hunt.version,
                    hunt.severity,
                    hunt.category,
                    list(hunt.tags),
                    list(hunt.log_sources),
                    hunt.schedule.enabled,
                    hunt.schedule.interval_minutes,
                    hunt.schedule.jitter_seconds,
                    json.dumps(hunt.hypothesis.model_dump(by_alias=True)),
                    json.dumps(hunt.expected.model_dump()),
                    list(hunt.references),
                    hunt.author,
                    hunt.source_sha256,
                )
                touched += 1
            logger.info("hunt.store.catalog.synced", count=touched)
    except Exception as exc:  # noqa: BLE001
        logger.warning("hunt.store.catalog.failed", error=str(exc))
    return touched


# ---------------------------------------------------------------------------
# Run + finding writes
# ---------------------------------------------------------------------------


async def record_run(
    hunt: HuntDefinition,
    result: HuntRunResult,
    *,
    tenant_ref: str = "default",
    trigger_source: str = "scheduler",
) -> uuid.UUID | None:
    """Persist one ``hunt_runs`` row plus its findings. Returns the run id."""
    pool = await _get_pool()
    if pool is None:
        return None

    run_id = uuid.uuid4()
    try:
        async with pool.acquire() as conn:
            tenant_id = await _resolve_tenant_id(conn, tenant_ref)
            if tenant_id is None:
                logger.debug(
                    "hunt.store.run.skip", reason="unknown_tenant", tenant_ref=tenant_ref
                )
                return None
            await _set_rls_context(conn, tenant_id)

            hyp_row = await conn.fetchrow(
                "SELECT id FROM hunt_hypotheses WHERE tenant_id = $1 AND hunt_id = $2",
                tenant_id,
                hunt.id,
            )
            hypothesis_id = hyp_row["id"] if hyp_row else None

            status = "error" if result.error else "completed"
            await conn.execute(
                """
                INSERT INTO hunt_runs
                  (id, tenant_id, hunt_id, hypothesis_id, trigger_source,
                   status, events_scanned, findings_count, match_score,
                   error, started_at, completed_at, created_at)
                VALUES
                  ($1, $2, $3, $4, $5,
                   $6, $7, $8, $9,
                   $10, NOW(), NOW(), NOW())
                """,
                run_id,
                tenant_id,
                hunt.id,
                hypothesis_id,
                trigger_source,
                status,
                result.events_scanned,
                len(result.findings),
                round(result.match_score, 3),
                result.error,
            )

            for f in result.findings:
                await _insert_finding(conn, tenant_id, run_id, f)

            logger.info(
                "hunt.store.run.recorded",
                hunt_id=hunt.id,
                events_scanned=result.events_scanned,
                findings=len(result.findings),
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("hunt.store.run.failed", hunt_id=hunt.id, error=str(exc))
        return None

    return run_id


async def _insert_finding(
    conn: asyncpg.Connection,
    tenant_id: uuid.UUID,
    run_id: uuid.UUID,
    f: HuntFindingDraft,
) -> None:
    await conn.execute(
        """
        INSERT INTO hunt_findings
          (tenant_id, hunt_run_id, hunt_id, severity, title, summary,
           evidence, primary_entity, primary_log_source, match_score,
           mitre_techniques, status, created_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6,
           $7::jsonb, $8, $9, $10,
           $11::text[], 'open', NOW(), NOW())
        """,
        tenant_id,
        run_id,
        f.hunt_id,
        f.severity,
        f.title,
        f.summary,
        json.dumps(f.evidence, default=str),
        f.primary_entity,
        f.primary_log_source,
        round(f.match_score, 3),
        list(f.mitre_techniques),
    )


# ---------------------------------------------------------------------------
# Read-side helpers (used by the API router)
# ---------------------------------------------------------------------------


async def list_recent_runs(
    *, tenant_ref: str = "default", limit: int = 50
) -> list[dict[str, Any]]:
    pool = await _get_pool()
    if pool is None:
        return []
    try:
        async with pool.acquire() as conn:
            tenant_id = await _resolve_tenant_id(conn, tenant_ref)
            if tenant_id is None:
                return []
            await _set_rls_context(conn, tenant_id)
            rows = await conn.fetch(
                """
                SELECT id, hunt_id, status, trigger_source, events_scanned,
                       findings_count, match_score, error, started_at,
                       completed_at
                FROM hunt_runs
                WHERE tenant_id = $1
                ORDER BY started_at DESC
                LIMIT $2
                """,
                tenant_id,
                limit,
            )
            return [dict(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        logger.warning("hunt.store.list_runs.failed", error=str(exc))
        return []


async def list_recent_findings(
    *,
    tenant_ref: str = "default",
    hunt_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    pool = await _get_pool()
    if pool is None:
        return []
    try:
        async with pool.acquire() as conn:
            tenant_id = await _resolve_tenant_id(conn, tenant_ref)
            if tenant_id is None:
                return []
            await _set_rls_context(conn, tenant_id)
            clauses = ["tenant_id = $1"]
            params: list[Any] = [tenant_id]
            if hunt_id:
                params.append(hunt_id)
                clauses.append(f"hunt_id = ${len(params)}")
            if status:
                params.append(status)
                clauses.append(f"status = ${len(params)}")
            params.append(limit)
            sql = f"""
                SELECT id, hunt_run_id, hunt_id, severity, title, summary,
                       primary_entity, primary_log_source, match_score,
                       mitre_techniques, status, created_at
                FROM hunt_findings
                WHERE {' AND '.join(clauses)}
                ORDER BY created_at DESC
                LIMIT ${len(params)}
            """
            rows = await conn.fetch(sql, *params)
            return [dict(r) for r in rows]
    except Exception as exc:  # noqa: BLE001
        logger.warning("hunt.store.list_findings.failed", error=str(exc))
        return []
