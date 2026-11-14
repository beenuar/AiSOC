"""Drain the outbound-webhook retry queue.

Without this the queue is a table that fills up: ``enqueue_event`` writes a
pending row and nothing ever attempts it, which is the "mechanism exists,
nothing calls it" shape that this plan keeps finding. The dead-letter view
would read empty forever, which is the most reassuring possible way to be
wrong about whether a tenant's SIEM has their alerts.

Safe on several replicas: each attempt is one row read, one HTTP call and
one commit, and a row already taken by another worker has moved off
``pending`` by the time this one commits. Two replicas can at worst send
one event twice, which is why the envelope carries a stable ``id`` the
receiver can deduplicate on — exactly backwards from losing one.
"""

from __future__ import annotations

import asyncio
import os

import structlog

from app.db.database import AsyncSessionLocal
from app.services.outbound_webhooks import attempt_delivery, due_deliveries

logger = structlog.get_logger(__name__)

__all__ = ["run_forever", "run_once"]

#: Tight enough that the 30-second first retry means roughly 30 seconds.
POLL_INTERVAL_SECONDS = float(os.getenv("OUTBOUND_WEBHOOK_POLL_INTERVAL_SECONDS", "15"))

#: Per tick. Bounds how long one pass can hold the loop when a receiver is
#: timing out: 25 deliveries at a 10-second timeout is the worst case.
BATCH_SIZE = int(os.getenv("OUTBOUND_WEBHOOK_BATCH_SIZE", "25"))


async def run_once() -> dict[str, int]:
    """Attempt every delivery that has come due. Returns a small tally."""
    attempted = delivered = dead = 0
    async with AsyncSessionLocal() as db:
        for delivery, webhook in await due_deliveries(db, limit=BATCH_SIZE):
            await attempt_delivery(delivery, webhook)
            attempted += 1
            delivered += delivery.status == "delivered"
            dead += delivery.status == "dead"
        await db.commit()
    if attempted:
        logger.info("outbound_webhook.swept", attempted=attempted, delivered=delivered, dead=dead)
    return {"attempted": attempted, "delivered": delivered, "dead": dead}


async def run_forever() -> None:
    """Poll until cancelled. A failed pass must not end the loop."""
    while True:
        try:
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("outbound_webhook.sweep_failed", error=str(exc)[:300])
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
