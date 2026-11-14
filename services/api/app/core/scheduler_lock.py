"""Distributed scheduler lock helper for in-process API workers.

Workers in ``app.main`` run in-process on every API replica. This helper
provides a per-job Redis lease so only one replica executes a given worker at
any time while keeping availability-first behavior:

* lock held by another replica -> caller gets ``False`` and can skip silently.
* Redis unavailable -> caller gets ``True`` (fail-open) and work proceeds.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from redis.asyncio import Redis, from_url
from redis.exceptions import RedisError

logger = logging.getLogger(__name__)

_redis_client: Redis | None = None
_redis_client_lock = asyncio.Lock()

_BACKEND_ERRORS = (RedisError, OSError, TimeoutError)

_RENEW_IF_OWNER_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('expire', KEYS[1], ARGV[2])
end
return 0
"""

_RELEASE_IF_OWNER_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
  return redis.call('del', KEYS[1])
end
return 0
"""


async def _get_redis_client() -> Redis:
    from app.core.config import settings  # lazy: only needed at first connect, not at import time

    global _redis_client
    if _redis_client is not None:
        return _redis_client

    async with _redis_client_lock:
        if _redis_client is None:
            _redis_client = from_url(str(settings.REDIS_URL), decode_responses=True)
    return _redis_client


def _warn_backend_unavailable(*, job_name: str, lock_key: str, phase: str, exc: Exception) -> None:
    logger.warning(
        "scheduler_lock.backend_unavailable job_name=%s lock_key=%s phase=%s error=%s",
        job_name,
        lock_key,
        phase,
        type(exc).__name__,
    )


async def _renew_lease_loop(
    *,
    redis_client: Redis,
    job_name: str,
    lock_key: str,
    token: str,
    ttl_seconds: int,
    renew_every_seconds: int,
) -> None:
    while True:
        await asyncio.sleep(renew_every_seconds)
        try:
            renewed = await redis_client.eval(
                _RENEW_IF_OWNER_SCRIPT,
                1,
                lock_key,
                token,
                str(ttl_seconds),
            )
        except _BACKEND_ERRORS as exc:
            _warn_backend_unavailable(job_name=job_name, lock_key=lock_key, phase="renew", exc=exc)
            return

        if not renewed:
            return


@asynccontextmanager
async def scheduler_lock(*, job_name: str, ttl_seconds: int) -> AsyncIterator[bool]:
    """Yield whether the caller should run this scheduler job.

    The lock key format is always ``scheduler_lock:{job_name}``.
    """
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be > 0")

    lock_key = f"scheduler_lock:{job_name}"
    token = uuid.uuid4().hex
    renew_task: asyncio.Task[None] | None = None
    redis_client: Redis | None = None

    try:
        redis_client = await _get_redis_client()
        acquired = await redis_client.set(lock_key, token, ex=ttl_seconds, nx=True)
    except _BACKEND_ERRORS as exc:
        _warn_backend_unavailable(job_name=job_name, lock_key=lock_key, phase="acquire", exc=exc)
        yield True
        return

    if not acquired:
        yield False
        return

    renew_every_seconds = max(1, ttl_seconds // 3)
    renew_task = asyncio.create_task(
        _renew_lease_loop(
            redis_client=redis_client,
            job_name=job_name,
            lock_key=lock_key,
            token=token,
            ttl_seconds=ttl_seconds,
            renew_every_seconds=renew_every_seconds,
        ),
        name=f"scheduler_lock_renew_{job_name}",
    )

    try:
        yield True
    finally:
        if renew_task is not None:
            renew_task.cancel()
            with suppress(asyncio.CancelledError):
                # Bind to `_` so the awaited result is explicitly discarded and
                # CodeQL's py/ineffectual-statement check doesn't misread this
                # as a no-op (the await itself is required to drain cancellation).
                _ = await renew_task

        if redis_client is not None:
            try:
                await redis_client.eval(
                    _RELEASE_IF_OWNER_SCRIPT,
                    1,
                    lock_key,
                    token,
                )
            except _BACKEND_ERRORS as exc:
                _warn_backend_unavailable(job_name=job_name, lock_key=lock_key, phase="release", exc=exc)


__all__ = ["scheduler_lock"]
