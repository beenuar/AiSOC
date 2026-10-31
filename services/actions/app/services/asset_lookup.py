"""What is the action about to touch? — target → asset criticality.

The approval matrix's asset modifier (``evaluate_contract``'s
``asset_criticality``) is tighten-only, and this module is where the value
comes from: the action's ``target`` (a hostname, FQDN or IP, which is what
every containment verb names) matched against the tenant's own ``assets``
inventory — the same table the console import writes and the queue resolver
reads.

Fail-soft by construction: no DSN, no match, a slow query or an outage is a
``None``, and ``None`` grades exactly as before — a deployment with no CMDB
keeps every verb it had. Highest criticality wins on multiple matches,
failing toward attention. A small TTL cache bounds the cost on the dispatch
hot path; inventories change on human timescales.
"""

from __future__ import annotations

import time
from typing import Any

import structlog

from app.services.tenant_policy import resolve_dsn

logger = structlog.get_logger()

_CACHE_TTL_SECONDS = 300.0
_QUERY_TIMEOUT_SECONDS = 3.0
_CRITICALITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

_cache: dict[tuple[str, str], tuple[float, str | None]] = {}


def _clear_cache() -> None:
    """Tests only."""
    _cache.clear()


async def asset_criticality_for_target(tenant_id: Any, target: str | None) -> str | None:
    """The target asset's criticality in this tenant's inventory, or ``None``.

    ``target`` is matched as a lowered hostname/FQDN and as an IP — the
    caller does not have to know which it holds, because a containment
    request frequently doesn't either.
    """
    value = (target or "").strip().lower()
    if not value or tenant_id is None:
        return None
    dsn = resolve_dsn()
    if not dsn:
        return None

    key = (str(tenant_id), value)
    now = time.monotonic()
    cached = _cache.get(key)
    if cached is not None and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    result: str | None = None
    try:
        import asyncpg  # noqa: PLC0415 — optional at import time

        conn = await asyncpg.connect(dsn, timeout=_QUERY_TIMEOUT_SECONDS)
        try:
            rows = await conn.fetch(
                """
                SELECT criticality
                FROM assets
                WHERE tenant_id = CAST($1 AS uuid)
                  AND (lower(name) = $2 OR lower(fqdn) = $2 OR $2 = ANY(ip_addresses))
                """,
                str(tenant_id),
                value,
                timeout=_QUERY_TIMEOUT_SECONDS,
            )
        finally:
            await conn.close()
        if rows:
            best = max(rows, key=lambda r: _CRITICALITY_RANK.get(str(r["criticality"] or "").lower(), 0))
            result = str(best["criticality"] or "").lower() or None
    except Exception as exc:  # noqa: BLE001 — inventory must never block dispatch
        logger.debug("asset_lookup.unresolved", error=str(exc))
        return None

    _cache[key] = (now, result)
    return result
