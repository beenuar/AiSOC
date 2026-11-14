"""
Alert deduplication using fingerprinting and a Redis sliding-window cache.

Postgres is the source of truth for whether an alert row exists
(``alert_sink`` inserts under a per-tenant dedup-hash guard), so this Redis
window is an optimisation: it avoids re-running correlation for an alert that
was just seen. It is **not** evidence that a row is durable.

Consequently a Redis outage must fail *open*. The previous implementation let
``RedisError`` escape from :meth:`is_duplicate`, which propagated out of the
fusion engine and — before the consumer's retry loop — either wedged the
partition or (worse) was logged and its offset committed, losing the event.
With Redis down an alert is now treated as non-duplicate, correlation still
runs (degraded), and the sink's database guard suppresses the actual duplicate
row.
"""

from __future__ import annotations

import redis.asyncio as aioredis
import structlog
from redis.exceptions import RedisError

from app.core.config import settings
from app.models.alert import RawAlert

logger = structlog.get_logger()

_DEDUP_PREFIX = "aisoc:fusion:dedup:"


class Deduplicator:
    """Deduplicates incoming alerts using SHA-256 fingerprints stored in Redis."""

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client
        self._window = settings.dedup_window_seconds
        self._degraded = False
        self.read_fallbacks = 0
        self.write_fallbacks = 0

    async def is_duplicate(self, alert: RawAlert) -> tuple[bool, str | None]:
        """
        Check if an alert is a duplicate within the deduplication window.

        Returns:
            (is_duplicate, original_alert_id)
        """
        fingerprint = alert.fingerprint()
        key = f"{_DEDUP_PREFIX}{fingerprint}"

        try:
            existing = await self._redis.get(key)
        except (TimeoutError, RedisError, OSError) as exc:
            self.read_fallbacks += 1
            self._enter_degraded(exc)
            # Fail open: Postgres still enforces per-tenant dedup, so the
            # worst case is a duplicate decision made downstream, never a lost
            # alert. Reporting "duplicate" here would be the loss.
            return False, None

        self._exit_degraded()
        if existing:
            try:
                original_id = existing.decode()
            except (AttributeError, UnicodeDecodeError):
                # A corrupt cache value is a cache miss, not a duplicate. The
                # Postgres guard still suppresses a real repeat row, whereas
                # raising here would dead-letter a valid alert over cache bytes.
                logger.warning("fusion.dedup_payload_invalid", fingerprint=fingerprint)
                return False, None
            logger.debug(
                "Duplicate alert detected",
                fingerprint=fingerprint,
                original_id=original_id,
                alert_id=str(alert.id),
            )
            return True, original_id

        return False, None

    async def register(self, alert: RawAlert) -> None:
        """Register an alert fingerprint to suppress future duplicates.

        Best-effort. A failed write means a later replay is not suppressed by
        Redis; the database's dedup guard still prevents a second row.
        """
        fingerprint = alert.fingerprint()
        key = f"{_DEDUP_PREFIX}{fingerprint}"
        try:
            await self._redis.set(key, str(alert.id), ex=self._window)
        except (TimeoutError, RedisError, OSError) as exc:
            self.write_fallbacks += 1
            self._enter_degraded(exc)
            return

        self._exit_degraded()
        logger.debug(
            "Alert fingerprint registered",
            fingerprint=fingerprint,
            alert_id=str(alert.id),
            ttl_seconds=self._window,
        )

    def metrics(self) -> dict[str, int | bool]:
        return {
            "degraded": self._degraded,
            "read_fallbacks": self.read_fallbacks,
            "write_fallbacks": self.write_fallbacks,
        }

    def _enter_degraded(self, exc: BaseException) -> None:
        if not self._degraded:
            self._degraded = True
            logger.warning(
                "fusion.dedup_degraded_fail_open",
                error=str(exc),
                detail="Redis unavailable; dedup falls back to the Postgres uniqueness guard",
            )

    def _exit_degraded(self) -> None:
        if self._degraded:
            self._degraded = False
            logger.info("fusion.dedup_recovered")
