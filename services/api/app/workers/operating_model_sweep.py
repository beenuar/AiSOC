"""Operating-model sweep: shift handoffs + per-tenant escalations.

Two ticks in one worker, both reading per-tenant configuration that gates
the real behaviour (no shifts → no handoffs; no routes → no escalations),
so the worker itself is hygiene and on by default like the others:

* **Handoffs** — every enabled shift whose occurrence just ended gets a
  snapshot of its tenant's real open work (`shift_handoff.generate_due_
  handoffs`), idempotently through the one-per-occurrence constraint.
* **Escalations** — open unowned cases past a route's unacked window
  escalate to that tenant's own outbound webhooks
  (`escalation_router.route_overdue_cases`), once per case per route.
"""

from __future__ import annotations

import asyncio
import logging

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.services.escalation_router import route_overdue_cases
from app.services.shift_handoff import generate_due_handoffs
from app.workers._tick_failures import TickFailures

logger = logging.getLogger("aisoc.operating_model_sweep")


async def run_once() -> dict[str, object]:
    async with AsyncSessionLocal() as db:
        handoffs = await generate_due_handoffs(db)
        escalations = await route_overdue_cases(db)
        await db.commit()
    summary: dict[str, object] = {
        "handoffs_generated": handoffs.generated,
        "handoffs_existing": handoffs.skipped_existing,
        "handoff_errors": handoffs.errors,
        "routes": escalations.routes,
        "escalated": escalations.escalated,
        "suppressed_by_matrix": escalations.suppressed_by_matrix,
        "route_errors": escalations.errors,
    }
    if handoffs.generated or escalations.escalated or handoffs.errors or escalations.errors:
        logger.info("operating_model_sweep %s", summary)
    return summary


async def run_forever() -> None:
    interval = max(int(getattr(settings, "OPERATING_MODEL_SWEEP_INTERVAL_SECONDS", 300)), 60)
    logger.info("operating_model_sweep started interval=%ds", interval)
    failures = TickFailures("operating_model_sweep", logger)
    try:
        while True:
            try:
                await run_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                failures.record_failure(exc)
            else:
                failures.record_success()
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("operating_model_sweep stopped")
        raise
