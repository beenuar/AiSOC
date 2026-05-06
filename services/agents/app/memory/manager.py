"""MemoryManager — unified interface over the three memory tiers."""

from __future__ import annotations

from typing import Any, Sequence

import structlog

from .institutional import (
    institutional_delete,
    institutional_get,
    institutional_search,
    institutional_set,
)
from .models import MemoryEntry, MemoryTier, OverrideFeedback
from .session import session_clear, session_delete, session_get, session_set
from .working import working_delete, working_get, working_set

logger = structlog.get_logger()

_ALL_TIERS: tuple[str, ...] = ("session", "working", "institutional")


class MemoryManager:
    """Unified API for three-tier agent memory.

    Create via the async factory::

        mgr = await MemoryManager.create(tenant_id="t1", run_id="run-abc")
    """

    def __init__(self, tenant_id: str, run_id: str | None = None) -> None:
        self._tenant_id = tenant_id
        self._run_id = run_id

    @classmethod
    async def create(cls, tenant_id: str, run_id: str | None = None) -> "MemoryManager":
        """Async factory — currently a passthrough; reserved for future init work."""
        return cls(tenant_id=tenant_id, run_id=run_id)

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    async def write_session(self, key: str, value: Any) -> None:
        """Write to the ephemeral session tier (in-process LRU)."""
        if self._run_id is None:
            raise ValueError("run_id is required for session memory")
        await session_set(self._run_id, key, value)

    async def write_working(
        self,
        key: str,
        value: Any,
        *,
        ttl: int = 86_400,
    ) -> None:
        """Write to the Redis-backed working tier (default TTL 24 h)."""
        await working_set(self._tenant_id, key, value, run_id=self._run_id, ttl=ttl)

    async def write_institutional(
        self,
        key: str,
        value: Any,
        *,
        tags: list[str] | None = None,
        analyst_override: bool = False,
        override_reason: str | None = None,
    ) -> None:
        """Write to the PostgreSQL institutional tier (permanent)."""
        await institutional_set(
            self._tenant_id,
            key,
            value,
            tags=tags,
            analyst_override=analyst_override,
            override_reason=override_reason,
        )

    # ------------------------------------------------------------------
    # Recall
    # ------------------------------------------------------------------

    async def recall(
        self,
        key: str,
        tiers: Sequence[str] = _ALL_TIERS,
    ) -> Any | None:
        """Search *tiers* in order; return first hit or None."""
        for tier in tiers:
            result = await self._get_from_tier(tier, key)
            if result is not None:
                return result
        return None

    async def _get_from_tier(self, tier: str, key: str) -> Any | None:
        if tier == MemoryTier.session:
            if self._run_id is None:
                return None
            return await session_get(self._run_id, key)
        if tier == MemoryTier.working:
            return await working_get(self._tenant_id, key, run_id=self._run_id)
        if tier == MemoryTier.institutional:
            return await institutional_get(self._tenant_id, key)
        logger.warning("memory.manager.unknown_tier", tier=tier)
        return None

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    async def delete(self, key: str, tier: str) -> None:
        if tier == MemoryTier.session:
            if self._run_id:
                await session_delete(self._run_id, key)
        elif tier == MemoryTier.working:
            await working_delete(self._tenant_id, key, run_id=self._run_id)
        elif tier == MemoryTier.institutional:
            await institutional_delete(self._tenant_id, key)

    async def clear_session(self) -> None:
        """Evict all session entries for the current run (call at investigation end)."""
        if self._run_id:
            await session_clear(self._run_id)

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    async def search_institutional(
        self,
        tags: list[str] | None = None,
        limit: int = 20,
    ) -> list[dict]:
        """Return institutional memory entries, optionally filtered by *tags*."""
        return await institutional_search(self._tenant_id, tags=tags, limit=limit)

    # ------------------------------------------------------------------
    # Analyst override ingestion
    # ------------------------------------------------------------------

    async def ingest_override(self, feedback: OverrideFeedback) -> None:
        """Ingest an analyst verdict correction into institutional memory."""
        key = f"analyst_override:{feedback.alert_id}"
        value = feedback.model_dump()
        await self.write_institutional(
            key,
            value,
            tags=["analyst_override"],
            analyst_override=True,
            override_reason=feedback.reason,
        )
        logger.info(
            "memory.institutional.override_ingested",
            alert_id=feedback.alert_id,
            original=feedback.original_verdict,
            corrected=feedback.corrected_verdict,
            analyst=feedback.analyst_id,
        )

    # ------------------------------------------------------------------
    # Convenience: read-back as MemoryEntry
    # ------------------------------------------------------------------

    async def recall_entry(
        self,
        key: str,
        tiers: Sequence[str] = _ALL_TIERS,
    ) -> MemoryEntry | None:
        """Like recall() but wraps the result in a MemoryEntry for richer context."""
        for tier in tiers:
            value = await self._get_from_tier(tier, key)
            if value is not None:
                return MemoryEntry(
                    tier=MemoryTier(tier),
                    tenant_id=self._tenant_id,
                    run_id=self._run_id,
                    key=key,
                    value=value,
                )
        return None
