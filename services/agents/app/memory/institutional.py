"""Institutional-tier memory — PostgreSQL-backed, permanent knowledge store.

Schema (created lazily if it does not exist):

    CREATE TABLE IF NOT EXISTS aisoc_institutional_memory (
        id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        tenant_id   TEXT NOT NULL,
        key         TEXT NOT NULL,
        value       JSONB NOT NULL,
        tags        TEXT[] NOT NULL DEFAULT '{}',
        analyst_override BOOLEAN NOT NULL DEFAULT FALSE,
        override_reason  TEXT,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE (tenant_id, key)
    );

Falls back to an in-process dict when the database is unavailable.
"""

from __future__ import annotations

import json
import os
from typing import Any

import structlog

from app.core.schema_bootstrap import ensure_table

logger = structlog.get_logger()

#: Why there is, or is not, a connection pool. The distinction is the whole
#: point: ``None`` used to mean all three of these at once, and
#: ``app.closure.policy`` read that single ``None`` as "no database is
#: configured, use the permissive process-wide default". It is far more
#: reachable than that — any exception from ``create_pool`` and any failure of
#: the bootstrap probe below produce the same ``None`` — so a missing
#: migration or an ACL problem on a table the closure policy never reads
#: silently disabled the closure policy and the kill switch together, logged
#: at ``debug``.
#:
#: ``POOL_UNCONFIGURED`` is a deployment that has no ``DATABASE_URL``.
#: ``POOL_UNAVAILABLE`` is a deployment that has one and could not use it.
#: A caller making a safety decision must be able to tell those apart.
POOL_READY = "ready"
POOL_UNCONFIGURED = "unconfigured"
POOL_UNAVAILABLE = "unavailable"

_FALLBACK: dict[str, Any] = {}

_POOL: Any = None  # asyncpg.Pool | None

#: The connected pool, independent of whether this module's own table exists.
#: Shared with ``app.closure``; see :func:`connection_pool`.
_RAW_POOL: Any = None

#: Tri-state: ``None`` not yet probed, ``True``/``False`` the probe's answer.
#: Cached so a deployment without the table does not re-probe on every read.
_MEMORY_TABLE_READY: bool | None = None

#: Only used when the table is genuinely absent — normally it arrives with
#: ``services/api/migrations/022_institutional_memory.sql``, which also gives
#: it the RLS policy this copy cannot.
_MEMORY_DDL = """
CREATE TABLE IF NOT EXISTS aisoc_institutional_memory (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL,
    key             TEXT NOT NULL,
    value           JSONB NOT NULL,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    analyst_override BOOLEAN NOT NULL DEFAULT FALSE,
    override_reason TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, key)
);
CREATE INDEX IF NOT EXISTS aisoc_institutional_memory_tenant_key
    ON aisoc_institutional_memory (tenant_id, key);
"""


def _normalise_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")


async def _connect() -> tuple[Any | None, str]:
    """Open, or reuse, the pool. Requires no particular table to exist.

    Split from :func:`_get_pool` so that this module's own bootstrap cannot
    decide whether *other* readers of the same database get a connection.
    It used to: a failed probe on ``aisoc_institutional_memory`` closed the
    pool and returned ``None``, and the closure policy — which reads two
    entirely different tables — resolved its pool through here and read that
    ``None`` as permission to fall back to a permissive default.
    """
    global _RAW_POOL
    if _RAW_POOL is not None:
        return _RAW_POOL, POOL_READY

    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        return None, POOL_UNCONFIGURED

    try:
        import asyncpg  # type: ignore[import]

        _RAW_POOL = await asyncpg.create_pool(_normalise_dsn(dsn), min_size=1, max_size=3)
    except Exception as exc:
        # `warning`, not `debug`. A deployment that configured a database and
        # did not get one is a fault an operator has to see, and a safety
        # control is about to refuse because of it.
        logger.warning("memory.institutional.db_unavailable", error=str(exc))
        return None, POOL_UNAVAILABLE

    return _RAW_POOL, POOL_READY


async def connection_pool() -> tuple[Any | None, str]:
    """A pool to the operational database, and why there is not one.

    The accessor other packages use. Returns the same pool
    :func:`_get_pool` would, without requiring this module's table: a reader
    of ``aisoc_closure_policies`` has no stake in whether
    ``aisoc_institutional_memory`` exists, and making it one is how a missing
    migration turned into a disabled kill switch.
    """
    return await _connect()


async def close_pool() -> None:
    """Release the shared pool. For tests and for a clean shutdown."""
    global _POOL, _RAW_POOL, _MEMORY_TABLE_READY
    pool, _RAW_POOL = _RAW_POOL, None
    _POOL = None
    _MEMORY_TABLE_READY = None
    if pool is not None:
        await pool.close()


async def _get_pool() -> Any | None:
    """The pool *this* store may use: the table has to be there.

    Still returns ``None`` when the probe fails, because the memory store
    genuinely cannot work without its table and falls back to the in-process
    dict. What changed is that the failure no longer closes the connection
    everything else shares.
    """
    global _POOL, _MEMORY_TABLE_READY
    if _POOL is not None:
        return _POOL

    pool, state = await _connect()
    if pool is None or state != POOL_READY:
        return None

    if _MEMORY_TABLE_READY is False:
        return None

    try:
        # Probe before creating: the runtime role holds DML only, and
        # `CREATE TABLE IF NOT EXISTS` checks the schema ACL before the
        # existence test, so it raises even when the table is there. See
        # app/core/schema_bootstrap.py.
        async with pool.acquire() as conn:
            _MEMORY_TABLE_READY = bool(await ensure_table(conn, "aisoc_institutional_memory", _MEMORY_DDL))
    except Exception as exc:
        logger.debug("memory.institutional.table_unavailable", error=str(exc))
        _MEMORY_TABLE_READY = False

    if not _MEMORY_TABLE_READY:
        return None

    _POOL = pool
    return _POOL


async def institutional_get(tenant_id: str, key: str) -> Any | None:
    pool = await _get_pool()
    fk = f"{tenant_id}:{key}"
    if pool is not None:
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT value FROM aisoc_institutional_memory WHERE tenant_id=$1 AND key=$2",
                    tenant_id,
                    key,
                )
                return json.loads(row["value"]) if row else None
        except Exception as exc:
            logger.warning("memory.institutional.get_error", key=fk, error=str(exc))
    return _FALLBACK.get(fk)


async def institutional_set(
    tenant_id: str,
    key: str,
    value: Any,
    *,
    tags: list[str] | None = None,
    analyst_override: bool = False,
    override_reason: str | None = None,
) -> None:
    pool = await _get_pool()
    fk = f"{tenant_id}:{key}"
    serialised = json.dumps(value, default=str)
    if pool is not None:
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO aisoc_institutional_memory
                        (tenant_id, key, value, tags, analyst_override, override_reason)
                    VALUES ($1, $2, $3::jsonb, $4, $5, $6)
                    ON CONFLICT (tenant_id, key) DO UPDATE
                        SET value            = EXCLUDED.value,
                            tags             = EXCLUDED.tags,
                            analyst_override = EXCLUDED.analyst_override,
                            override_reason  = EXCLUDED.override_reason,
                            created_at       = now()
                    """,
                    tenant_id,
                    key,
                    serialised,
                    tags or [],
                    analyst_override,
                    override_reason,
                )
            return
        except Exception as exc:
            logger.warning("memory.institutional.set_error", key=fk, error=str(exc))
    _FALLBACK[fk] = json.loads(serialised)


async def institutional_delete(tenant_id: str, key: str) -> None:
    pool = await _get_pool()
    fk = f"{tenant_id}:{key}"
    if pool is not None:
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    "DELETE FROM aisoc_institutional_memory WHERE tenant_id=$1 AND key=$2",
                    tenant_id,
                    key,
                )
        except Exception as exc:
            logger.warning("memory.institutional.delete_error", key=fk, error=str(exc))
    _FALLBACK.pop(fk, None)


async def institutional_search(
    tenant_id: str,
    tags: list[str] | None = None,
    limit: int = 20,
) -> list[dict]:
    """Return up to *limit* entries for *tenant_id*, optionally filtered by tags."""
    pool = await _get_pool()
    if pool is not None:
        try:
            async with pool.acquire() as conn:
                if tags:
                    rows = await conn.fetch(
                        """
                        SELECT key, value, tags, analyst_override, override_reason, created_at
                        FROM aisoc_institutional_memory
                        WHERE tenant_id=$1 AND tags && $2
                        ORDER BY created_at DESC LIMIT $3
                        """,
                        tenant_id,
                        tags,
                        limit,
                    )
                else:
                    rows = await conn.fetch(
                        """
                        SELECT key, value, tags, analyst_override, override_reason, created_at
                        FROM aisoc_institutional_memory
                        WHERE tenant_id=$1
                        ORDER BY created_at DESC LIMIT $2
                        """,
                        tenant_id,
                        limit,
                    )
                return [
                    {
                        "key": r["key"],
                        "value": json.loads(r["value"]),
                        "tags": list(r["tags"]),
                        "analyst_override": r["analyst_override"],
                        "override_reason": r["override_reason"],
                        "created_at": r["created_at"].isoformat(),
                    }
                    for r in rows
                ]
        except Exception as exc:
            logger.warning("memory.institutional.search_error", error=str(exc))
    # Fallback: return matching entries from in-process dict
    results = []
    for fk, val in _FALLBACK.items():
        if fk.startswith(f"{tenant_id}:"):
            results.append({"key": fk.split(":", 1)[1], "value": val, "tags": [], "analyst_override": False})
    return results[:limit]
