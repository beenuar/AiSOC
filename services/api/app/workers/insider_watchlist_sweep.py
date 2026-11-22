"""Insider-watchlist sweep: expiry hygiene plus the HR door (WS4.4).

Two jobs on one tick, deliberately asymmetric about defaults:

* **Expiry** runs for every tenant unconditionally, like
  ``approval_expiry``. It only touches our own rows — flipping
  ``is_watchlisted`` off where ``watchlist_expires_at`` has passed and
  regenerating that tenant's managed rules — and the alternative is a
  watchlist entry that promised to end and then silently didn't. Hygiene
  of a deadline we recorded is not automation a tenant opts into.

* **The HR door** runs only for tenants whose
  ``insider_watchlist_policies.hr_sync_enabled`` row says so (default
  off): it reads ``workforce_members`` — the HR store the connectors
  service already syncs — and watchlists departing members with the HR
  fact as the reason and last-day-plus-grace as the expiry. Watching the
  HR store and acting on it *is* automation, so it is per-tenant opt-in.

Both halves are idempotent: an expired row flips once, and the HR door
never touches an identity already on the list (in particular it never
shortens a manual expiry).
"""

from __future__ import annotations

import asyncio
import logging

from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.services.insider_watchlist import sweep_expired, sweep_hr
from app.workers._tick_failures import TickFailures

logger = logging.getLogger("aisoc.insider_watchlist_sweep")


async def run_once() -> dict[str, int | list[str]]:
    """One tick. Returns the summary so tests and logs see the same truth."""
    async with AsyncSessionLocal() as db:
        expired = await sweep_expired(db)
        hr = await sweep_hr(db)
        await db.commit()
    summary: dict[str, int | list[str]] = {
        "expired": expired.expired,
        "tenants_rebuilt": expired.tenants_rebuilt,
        "hr_tenants": hr.hr_tenants,
        "hr_watchlisted": hr.hr_watchlisted,
        "errors": hr.errors,
    }
    if expired.expired or hr.hr_watchlisted or hr.errors:
        logger.info("insider_watchlist_sweep %s", summary)
    return summary


async def run_forever() -> None:
    """Tick until cancelled. Owned by the API ``lifespan``, like the others."""
    interval = max(int(getattr(settings, "INSIDER_WATCHLIST_SWEEP_INTERVAL_SECONDS", 900)), 60)
    logger.info("insider_watchlist_sweep started interval=%ds", interval)
    failures = TickFailures("insider_watchlist_sweep", logger)
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
        logger.info("insider_watchlist_sweep stopped")
        raise
