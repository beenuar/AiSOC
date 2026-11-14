"""Working-tier memory — Redis-backed, per-case/shift lifetime (~24 h).

Falls back to an in-process dict when Redis is unavailable so the agent
keeps running in development or minimal deployments.

Keys are namespaced as  ``aisoc:mem:working:{tenant_id}:{run_id}:{key}``
to prevent cross-tenant bleed.
"""

from __future__ import annotations

import json
import os
from typing import Any

import structlog

logger = structlog.get_logger()

_DEFAULT_TTL = 86_400  # 24 h
_FALLBACK: dict[str, Any] = {}

try:
    import redis.asyncio as aioredis  # type: ignore[import]

    _redis: aioredis.Redis | None = None

    async def _get_redis() -> aioredis.Redis | None:
        global _redis
        if _redis is not None:
            return _redis
        url = os.environ.get("REDIS_URL", "").strip()
        if not url:
            return None
        try:
            _redis = aioredis.from_url(url, decode_responses=True)
            await _redis.ping()
            return _redis
        except Exception as exc:
            logger.debug("memory.working.redis_unavailable", error=str(exc))
            return None

except ImportError:

    async def _get_redis():  # type: ignore[misc]
        return None


def _key(tenant_id: str, run_id: str | None, key: str) -> str:
    return f"aisoc:mem:working:{tenant_id}:{run_id or '*'}:{key}"


async def working_get(tenant_id: str, key: str, run_id: str | None = None) -> Any | None:
    r = await _get_redis()
    full_key = _key(tenant_id, run_id, key)
    if r is not None:
        try:
            raw = await r.get(full_key)
            return json.loads(raw) if raw is not None else None
        except Exception as exc:
            logger.warning("memory.working.get_error", key=full_key, error=str(exc))
    return _FALLBACK.get(full_key)


async def working_set(
    tenant_id: str,
    key: str,
    value: Any,
    run_id: str | None = None,
    ttl: int = _DEFAULT_TTL,
) -> None:
    r = await _get_redis()
    full_key = _key(tenant_id, run_id, key)
    serialised = json.dumps(value, default=str)
    if r is not None:
        try:
            await r.setex(full_key, ttl, serialised)
            return
        except Exception as exc:
            logger.warning("memory.working.set_error", key=full_key, error=str(exc))
    _FALLBACK[full_key] = json.loads(serialised)


async def working_delete(tenant_id: str, key: str, run_id: str | None = None) -> None:
    r = await _get_redis()
    full_key = _key(tenant_id, run_id, key)
    if r is not None:
        try:
            await r.delete(full_key)
        except Exception as exc:
            logger.warning("memory.working.delete_error", key=full_key, error=str(exc))
    _FALLBACK.pop(full_key, None)
