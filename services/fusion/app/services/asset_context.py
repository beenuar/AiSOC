"""Fuse-time asset-context stamp — what did this alert land on?

The confidence scorer's ``asset_criticality`` factor reads
``fused.enrichments["asset_context"]``; this module is the only writer. It
resolves the alert's hostname/IP against the tenant's own ``assets``
inventory (the table the console's asset import and the CMDB connectors
write) at fuse time, the same slot the TI enrichment uses — the scorer stays
a pure projection and never opens a connection.

Honesty and robustness, same contract as the TI enricher one file over:

* **Unknown is unknown.** No inventory, no match, no database — the stamp is
  absent and the scorer's factor row reads "unknown (no inventory match)"
  with a contribution of exactly zero. Absence of a CMDB row is not evidence
  in either direction.
* **Fail-soft.** A missing DSN, a connection error or a slow query is a
  ``None`` and a warning — asset context never blocks or crashes fusion.
* **Bounded.** One indexed query per (tenant, host/ip) with a small TTL
  cache, because fusion sits on the hot path and the inventory changes on
  human timescales.
"""

from __future__ import annotations

import os
import time
from typing import Any

import structlog

from app.models.alert import RawAlert

logger = structlog.get_logger()

_CACHE_TTL_SECONDS = 300.0
_QUERY_TIMEOUT_SECONDS = 2.0

_CRITICALITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _asyncpg_dsn(url: str) -> str:
    """Strip the SQLAlchemy driver suffix — asyncpg wants plain postgresql://."""
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


class AssetContextResolver:
    """Resolve an alert's host/IP to the tenant's asset criticality."""

    def __init__(self, database_url: str | None = None) -> None:
        url = (database_url or os.getenv("DATABASE_URL") or "").strip()
        self._dsn = _asyncpg_dsn(url) if url else ""
        self._pool: Any = None
        self._cache: dict[tuple[str, str], tuple[float, dict[str, Any] | None]] = {}

    @property
    def configured(self) -> bool:
        return bool(self._dsn)

    async def _ensure_pool(self) -> Any:
        if self._pool is None:
            import asyncpg  # noqa: PLC0415 — optional at import time

            self._pool = await asyncpg.create_pool(self._dsn, min_size=0, max_size=2, timeout=_QUERY_TIMEOUT_SECONDS)
        return self._pool

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def resolve(self, alert: RawAlert) -> dict[str, Any] | None:
        """``{"criticality": ..., "matched": <asset name>}`` or ``None``.

        Matches on lowered name/FQDN or IP membership; several matches take
        the highest criticality, failing toward attention. The cache key is
        the pivot value, so two alerts on one host inside the TTL cost one
        query.
        """
        if not self._dsn:
            return None
        host = (alert.hostname or "").strip().lower()
        ip = (alert.src_ip or "").strip()
        pivot = host or ip
        if not pivot:
            return None

        key = (str(alert.tenant_id), pivot)
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached is not None and now - cached[0] < _CACHE_TTL_SECONDS:
            return cached[1]

        try:
            pool = await self._ensure_pool()
            # Empty-string guards rather than NUL sentinels: Postgres refuses
            # a 0x00 byte in a text parameter outright, and '' would otherwise
            # match an asset with an empty name.
            rows = await pool.fetch(
                """
                SELECT name, criticality
                FROM assets
                WHERE tenant_id = $1
                  AND (
                    ($2 <> '' AND (lower(name) = $2 OR lower(fqdn) = $2))
                    OR ($3 <> '' AND $3 = ANY(ip_addresses))
                  )
                """,
                alert.tenant_id,
                host,
                ip,
                timeout=_QUERY_TIMEOUT_SECONDS,
            )
        except Exception as exc:  # noqa: BLE001 — never block fusion on inventory
            logger.warning("asset_context.resolve_failed", error=str(exc))
            return None

        result: dict[str, Any] | None = None
        if rows:
            best = max(rows, key=lambda r: _CRITICALITY_RANK.get(str(r["criticality"] or "").lower(), 0))
            result = {
                "criticality": str(best["criticality"] or "medium").lower(),
                "matched": str(best["name"] or ""),
            }
        self._cache[key] = (now, result)
        return result
