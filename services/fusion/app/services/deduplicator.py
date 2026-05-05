"""
Alert deduplication using fingerprinting and a Redis sliding-window cache.
"""

import redis.asyncio as aioredis
import structlog

from app.core.config import settings
from app.models.alert import RawAlert

logger = structlog.get_logger()

_DEDUP_PREFIX = "aisoc:fusion:dedup:"


class Deduplicator:
    """Deduplicates incoming alerts using SHA-256 fingerprints stored in Redis."""

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client
        self._window = settings.dedup_window_seconds

    async def is_duplicate(self, alert: RawAlert) -> tuple[bool, str | None]:
        """
        Check if an alert is a duplicate within the deduplication window.

        Returns:
            (is_duplicate, original_alert_id)
        """
        fingerprint = alert.fingerprint()
        key = f"{_DEDUP_PREFIX}{fingerprint}"

        existing = await self._redis.get(key)
        if existing:
            logger.debug(
                "Duplicate alert detected",
                fingerprint=fingerprint,
                original_id=existing.decode(),
                alert_id=str(alert.id),
            )
            return True, existing.decode()

        return False, None

    async def register(self, alert: RawAlert) -> None:
        """Register an alert fingerprint to suppress future duplicates."""
        fingerprint = alert.fingerprint()
        key = f"{_DEDUP_PREFIX}{fingerprint}"
        await self._redis.set(key, str(alert.id), ex=self._window)
        logger.debug(
            "Alert fingerprint registered",
            fingerprint=fingerprint,
            alert_id=str(alert.id),
            ttl_seconds=self._window,
        )
