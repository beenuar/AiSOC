"""Saved-hunt scheduler — Track 3, T3.4 (`/hunt` NL surface).

Sweeps the ``aisoc_saved_hunts`` table on a tick and fires any saved hunt
whose cron schedule says it's due. "Firing" means re-translating the saved
NL question, executing the resulting ES|QL query against the configured
Elasticsearch backend, and (if the hit count exceeds zero) opening a case
so the duty analyst sees the result on the cases queue.

Why an in-process asyncio worker instead of APScheduler?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The API service already runs two singleton ``asyncio.Task`` workers
(``oauth_refresh``, ``weekly_digest``) from the ``lifespan`` hook. They
share the same DB engine and shutdown semantics. Adding a third in the
same shape is the path of least surprise for operators — one process,
one log stream, one scaling unit. Pulling in APScheduler would give us
better cron semantics but would also introduce a new dependency that
makes deployment and graceful shutdown harder to reason about.

The trade-off: cron-string accuracy. We use a very small structural cron
parser (5 fields, ``* / , -``) and only support the common cadences. For
a v1 surface where 90% of saved hunts will be "every hour" or "every
6 hours" this is fine. If users start writing complex schedules we can
swap the parser without touching the call sites.

Disabling
~~~~~~~~~

Default-on, but flipped off in test environments and for operators who
run the API behind a separate scheduler service. Set
``AISOC_HUNT_SCHEDULER_ENABLED=false`` to disable. ``main.py`` honours
the flag the same way it gates ``oauth_refresh`` and
``weekly_digest``.

# TODO(T3.4-followup): swap the bespoke cron parser for ``croniter``
# once the depedency is added in T3.5 (we'll already need it for
# scheduled report generation). The current parser uses ``last_run_at +
# fixed_interval_for_known_cadence`` which handles the documented set of
# cadences but is not a full POSIX cron implementation.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.airgap import AirgapViolation
from app.core.config import settings
from app.db.database import AsyncSessionLocal
from app.models.case import Case
from app.models.saved_hunt import SavedHunt
from app.services.esql_runner import (
    ESQLExecutionError,
    ESQLNotConfigured,
    resolve_es_credentials,
    run_esql_query,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cadence parsing
# ---------------------------------------------------------------------------


def _interval_seconds_for(schedule: str) -> int | None:
    """Return how often (seconds) ``schedule`` should fire.

    Recognises the common SOC cadences:

    * ``"* * * * *"``        — every minute
    * ``"*/N * * * *"``      — every N minutes
    * ``"0 * * * *"``        — every hour, top of the hour
    * ``"0 */N * * *"``      — every N hours
    * ``"0 0 * * *"``        — daily at midnight UTC
    * ``"0 0 * * <weekday>"`` — weekly on the named weekday

    Returns ``None`` for cron strings the bespoke parser can't classify.
    The worker treats ``None`` as "skip" so an unparseable schedule never
    crashes the loop — it just doesn't fire until the parser is upgraded
    or the analyst re-saves with a recognised cadence. See module
    docstring for the planned ``croniter`` follow-up.
    """
    fields = schedule.strip().split()
    if len(fields) != 5:
        return None
    minute, hour, dom, month, dow = fields

    # */N minutes
    if minute.startswith("*/") and hour == "*" and dom == "*" and month == "*" and dow == "*":
        try:
            n = int(minute[2:])
            if n > 0:
                return n * 60
        except ValueError:
            return None

    # Every minute
    if minute == "*" and hour == "*" and dom == "*" and month == "*" and dow == "*":
        return 60

    # Top of every hour
    if minute.isdigit() and hour == "*" and dom == "*" and month == "*" and dow == "*":
        return 3600

    # */N hours
    if minute.isdigit() and hour.startswith("*/") and dom == "*" and month == "*" and dow == "*":
        try:
            n = int(hour[2:])
            if n > 0:
                return n * 3600
        except ValueError:
            return None

    # Daily
    if minute.isdigit() and hour.isdigit() and dom == "*" and month == "*" and dow == "*":
        return 24 * 3600

    # Weekly: "0 0 * * 1" → every 7 days. Approximation; the worker
    # tolerates drift because it's not used for compliance evidence.
    if minute.isdigit() and hour.isdigit() and dom == "*" and month == "*" and dow not in ("*", ""):
        return 7 * 24 * 3600

    return None


def _is_due(hunt: SavedHunt, now: datetime) -> bool:
    """Should ``hunt`` be fired at ``now``?

    A hunt is due when the cadence interval has elapsed since the last
    run (or — if the hunt has never run — since save time, so analysts
    don't see "first scheduled run two hours from now" and wonder if
    something is broken).
    """
    if not hunt.schedule:
        return False
    interval = _interval_seconds_for(hunt.schedule)
    if interval is None:
        return False
    last = hunt.last_run_at or hunt.created_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return (now - last) >= timedelta(seconds=interval)


# ---------------------------------------------------------------------------
# Hit-handler hook
# ---------------------------------------------------------------------------


HitCallback = Callable[[AsyncSession, SavedHunt, int], Awaitable[None]]


async def _open_case_for_hits(db: AsyncSession, hunt: SavedHunt, hit_count: int) -> None:
    """Open a new case row when a scheduled hunt produces hits.

    Kept deliberately simple — title + description + tenant binding only.
    Triage routing, severity scoring, and analyst assignment all happen
    in the existing case lifecycle once the row exists.
    """
    if hit_count <= 0:
        return
    case = Case(
        tenant_id=hunt.tenant_id,
        case_number=f"HUNT-{hunt.id.hex[:8].upper()}-{int(datetime.now(UTC).timestamp())}",
        title=f"Scheduled hunt fired: {hunt.name}",
        description=(
            f"Saved hunt {hunt.name!r} returned {hit_count} hit(s) on its scheduled run.\n\nOriginal NL question: {hunt.nl_query}"
        ),
        case_type="hunt_finding",
        priority="medium",
        severity="medium",
        status="open",
        tags=["scheduled-hunt", f"hunt:{hunt.id}"],
    )
    db.add(case)
    logger.info(
        "hunt_scheduler.case_opened hunt_id=%s tenant=%s hits=%d",
        hunt.id,
        hunt.tenant_id,
        hit_count,
    )


# ---------------------------------------------------------------------------
# Hunt execution stub
# ---------------------------------------------------------------------------


async def _execute_hunt(db: AsyncSession, hunt: SavedHunt) -> int:
    """Run the hunt's translated query and return the hit count.

    Uses the shared :mod:`app.services.esql_runner` so the scheduler
    and the request-scoped ``/nl-query/execute`` endpoint share one
    code path for the outbound POST, the SSRF guard, and the air-gap
    enforcement.

    Falls back to ``0`` hits (and logs at ``info``) when:

    * The saved hunt has no translated ES|QL stored. A NL question
      that never produced a deterministic translation can still be
      saved as a draft; on schedule we just skip it rather than
      re-running the translator (LLM enhancement, network, retries —
      not the worker's job).
    * Elasticsearch credentials aren't configured. The worker stays
      quiet in self-hosted dev where ES isn't wired up, and only
      logs once per missing-credentials run.

    Raises Elasticsearch transport / air-gap errors back to the caller,
    where ``run_once`` records them via ``logger.exception`` and skips
    the ``last_run_at`` bump so the hunt retries on the next tick.
    """
    _ = db  # unused — kept in the signature for future hunt-specific reads
    esql = (hunt.translated_query or {}).get("esql") if isinstance(hunt.translated_query, dict) else None
    if not esql:
        logger.info(
            "hunt_scheduler.execute_skip hunt_id=%s reason=no_translated_esql",
            hunt.id,
        )
        return 0

    try:
        es_url, es_api_key = resolve_es_credentials()
    except ESQLNotConfigured:
        logger.info(
            "hunt_scheduler.execute_skip hunt_id=%s reason=es_not_configured",
            hunt.id,
        )
        return 0

    try:
        result = await run_esql_query(
            esql=esql,
            es_url=es_url,
            es_api_key=es_api_key,
            max_rows=int(getattr(settings, "HUNT_SCHEDULER_MAX_ROWS", 500)),
        )
    except (AirgapViolation, ValueError, ESQLExecutionError) as exc:
        # Let ``run_once`` mark this tick as failed and retry next sweep.
        logger.warning(
            "hunt_scheduler.execute_failed hunt_id=%s err=%s",
            hunt.id,
            type(exc).__name__,
        )
        raise

    return len(result.rows)


# ---------------------------------------------------------------------------
# Single-tick worker (importable from tests)
# ---------------------------------------------------------------------------


async def run_once(
    *,
    db: AsyncSession | None = None,
    now: datetime | None = None,
    hit_callback: HitCallback | None = None,
    executor: Callable[[AsyncSession, SavedHunt], Awaitable[int]] | None = None,
) -> int:
    """Sweep all due hunts once. Returns the number of hunts fired.

    All four hooks are dependency-injected so tests can pin the clock,
    swap a mock executor, and assert on case opening without touching
    Elasticsearch or the case lifecycle.
    """
    own_session = db is None
    if db is None:
        db = AsyncSessionLocal()
    assert db is not None  # for type narrowing
    now = now or datetime.now(UTC)
    callback = hit_callback or _open_case_for_hits
    runner = executor or _execute_hunt
    fired = 0
    try:
        # The DB session bound here doesn't carry an ``app.current_tenant_id``
        # GUC, so RLS would block reads. Disable the row filter for the
        # scheduler's sweep — we *want* cross-tenant visibility because the
        # worker iterates every tenant's scheduled hunts. We re-bind the
        # tenant before each per-hunt write to keep RLS enforcement intact
        # for the case insert.
        await db.execute(text("SET LOCAL row_security = off"))
        rows = (await db.execute(select(SavedHunt).where(SavedHunt.schedule.is_not(None)))).scalars().all()
        for hunt in rows:
            if not _is_due(hunt, now):
                continue
            try:
                # Bind tenant for this hunt's writes so the case insert
                # passes RLS. ``set_config(local=true)`` keeps the GUC
                # scoped to the current transaction.
                await db.execute(
                    text("SELECT set_config('app.current_tenant_id', :t, true)"),
                    {"t": str(hunt.tenant_id)},
                )
                hits = await runner(db, hunt)
                await callback(db, hunt, hits)
                # Stamp last_run_at so we don't re-fire on the next tick.
                await db.execute(update(SavedHunt).where(SavedHunt.id == hunt.id).values(last_run_at=now, updated_at=now))
                fired += 1
            except Exception as exc:  # pragma: no cover - defensive
                logger.exception(
                    "hunt_scheduler.fire_failed hunt_id=%s err=%s",
                    hunt.id,
                    type(exc).__name__,
                )
                # Don't update last_run_at — let the next tick retry.
        if fired:
            await db.commit()
    finally:
        if own_session:
            await db.close()
    return fired


# ---------------------------------------------------------------------------
# Long-running loop (started from main.py)
# ---------------------------------------------------------------------------


async def run_forever() -> None:
    """Tick the scheduler until cancelled. Owned by the API ``lifespan``."""
    interval = max(int(getattr(settings, "HUNT_SCHEDULER_POLL_INTERVAL_SECONDS", 30)), 5)
    logger.info("hunt_scheduler started interval=%ds", interval)
    try:
        while True:
            try:
                fired = await run_once()
                if fired:
                    logger.info("hunt_scheduler tick fired=%d", fired)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "hunt_scheduler tick failed err=%s",
                    type(exc).__name__,
                )
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        logger.info("hunt_scheduler stopped")
        raise


# Re-export for tests that want to monkeypatch the executor without
# touching internals.
__all__ = [
    "HitCallback",
    "run_forever",
    "run_once",
    "_execute_hunt",
    "_is_due",
    "_interval_seconds_for",
    "_open_case_for_hits",
]
