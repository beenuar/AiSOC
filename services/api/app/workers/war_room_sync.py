"""Keep every open war room current with its case.

Depth plan 9.4. "Posts the timeline and verdicts as they change" is a sweep,
and without one the feature is a button that posts a header once and then
goes quiet — which is worse than not opening the channel, because people in
it believe they are watching the case.

Safe on several replicas. Each post is keyed by a fingerprint of the event
and ``aisoc_war_room_posts`` carries a unique constraint on
``(war_room_id, event_key)``, so two workers racing on the same room end
with one post and one ``ON CONFLICT DO NOTHING``. That is why the sweep is
deliberately *not* under the scheduler lock: a single lock holder stalling
every tenant's war rooms is a worse failure than an occasional duplicate
attempt that the constraint already absorbs.

A room whose sync fails keeps its place in the queue and records
``last_error``. It is not disabled: a chat outage is transient and a room
that quietly stops mirroring is the thing this worker exists to prevent.
"""

from __future__ import annotations

import asyncio
import os

import structlog
from sqlalchemy import text

from app.db.database import AsyncSessionLocal
from app.db.rls import set_rls_context
from app.services.war_room import sync_war_room

logger = structlog.get_logger(__name__)

__all__ = ["run_forever", "run_once"]

#: A minute. Chat is a human-latency surface: posting a status change within
#: a minute is indistinguishable from instant to somebody reading a channel,
#: and a tighter loop buys nothing but vendor rate limit.
POLL_INTERVAL_SECONDS = int(os.environ.get("AISOC_WAR_ROOM_SYNC_INTERVAL", "60"))

#: How many rooms one pass touches. Bounded so a tenant with hundreds cannot
#: make one tick run for minutes and starve the rest.
BATCH = int(os.environ.get("AISOC_WAR_ROOM_SYNC_BATCH", "50"))

#: Oldest sync first, never-synced before that. A room that has just been
#: opened and has never been told anything is the most urgent one.
_DUE_SQL = """
SELECT * FROM aisoc_case_war_rooms
WHERE state = 'open'
ORDER BY last_synced_at ASC NULLS FIRST
LIMIT :limit
"""


async def run_once() -> int:
    """Sync every due room. Returns how many posts were made."""
    posted = 0
    async with AsyncSessionLocal() as db:
        rooms = (await db.execute(text(_DUE_SQL).bindparams(limit=BATCH))).mappings().all()
        for room in rooms:
            # Bind the tenant per room. The sweep reads across tenants by
            # design — it is a platform worker — so it sets the context
            # explicitly for each one rather than running with none, which
            # would leave the writes unscoped.
            await set_rls_context(db, room["tenant_id"])
            try:
                result = await sync_war_room(db, tenant_id=room["tenant_id"], war_room=dict(room))
                posted += result["posted"]
                if result["error"]:
                    logger.warning(
                        "war_room.sync_failed",
                        war_room_id=str(room["id"]),
                        provider=room["provider"],
                        error=result["error"][:300],
                    )
            except Exception as exc:  # noqa: BLE001 — one bad room must not stop the sweep
                logger.warning("war_room.sync_raised", war_room_id=str(room["id"]), error=str(exc)[:300])
                await db.rollback()
                continue
            await db.commit()
    return posted


async def run_forever() -> None:
    """Poll until cancelled. A failed pass must not end the loop."""
    while True:
        try:
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("war_room.sweep_failed", error=str(exc)[:300])
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
