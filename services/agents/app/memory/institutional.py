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

logger = structlog.get_logger()

_FALLBACK: dict[str, Any] = {}

_POOL: Any = None  # asyncpg.Pool | None


def _normalise_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")


async def _get_pool() -> Any | None:
    global _POOL
    if _POOL is not None:
        return _POOL
    dsn = os.environ.get("DATABASE_URL", "").strip()
    if not dsn:
        return None
    try:
        import asyncpg  # type: ignore[import]

        pool = await asyncpg.create_pool(_normalise_dsn(dsn), min_size=1, max_size=3)
        # Ensure table exists
        async with pool.acquire() as conn:
            await conn.execute(
                """
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
            )
        _POOL = pool
        return _POOL
    except Exception as exc:
        logger.debug("memory.institutional.db_unavailable", error=str(exc))
        return None


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
