"""Live per-tenant memory priors for the confidence scorer (Wave 1).

Closes the "distill exists but never reaches the live verdict path" gap: this
provider periodically distills the tenant's alert-disposition history into
per-signature priors (:func:`app.memory.distill.distill`) and hands them to the
``ConfidenceScorer`` so a signature analysts keep correcting to benign nudges
new alerts of that signature down (bounded ±0.10), and vice-versa.

Priors are keyed per tenant so one tenant's history never nudges another's
alerts (tenant isolation). Best-effort: no DB / no history => empty priors and
the scorer is unchanged.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

import structlog

from app.memory.distill import SignaturePrior, distill

logger = structlog.get_logger()

# Look-back window + per-signature cap for the distillation query.
_WINDOW_DAYS = 90
_MAX_ROWS = 50_000


def _primary_technique(value: Any) -> str:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return ""
    if isinstance(value, list) and value:
        return str(value[0])
    return ""


class MemoryPriorProvider:
    """In-process cache of per-tenant signature priors, refreshed on a cadence."""

    def __init__(self) -> None:
        self._by_tenant: dict[str, dict[str, SignaturePrior]] = {}

    def get_priors(self, tenant_id: str) -> dict[str, SignaturePrior]:
        return self._by_tenant.get(str(tenant_id), {})

    async def refresh(self, pool: Any) -> int:
        """Rebuild the per-tenant prior cache from disposition history.

        Returns the number of tenants refreshed. Never raises — a query failure
        keeps the previous cache in place.
        """
        if pool is None:
            return 0
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch(
                    """
                    SELECT tenant_id, connector_type, mitre_techniques, disposition
                      FROM alerts
                     WHERE disposition IS NOT NULL
                       AND created_at > now() - make_interval(days => $1)
                     LIMIT $2
                    """,
                    _WINDOW_DAYS,
                    _MAX_ROWS,
                )
        except Exception as exc:  # noqa: BLE001 — keep the last good cache
            logger.debug("memory_provider.refresh_failed", error=str(exc))
            return 0

        by_tenant_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in rows:
            by_tenant_rows[str(r["tenant_id"])].append(
                {
                    "category": "",
                    "connector_type": r["connector_type"] or "",
                    "primary_technique": _primary_technique(r["mitre_techniques"]),
                    "corrected_verdict": r["disposition"],
                }
            )

        self._by_tenant = {tid: distill(rws).priors for tid, rws in by_tenant_rows.items()}
        logger.info("memory_provider.refreshed", tenants=len(self._by_tenant))
        return len(self._by_tenant)
