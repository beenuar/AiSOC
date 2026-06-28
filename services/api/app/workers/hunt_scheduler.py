"""Saved-hunt scheduler — Track 3, T3.4 (`/hunt` NL surface).

Sweeps the ``aisoc_saved_hunts`` table on a tick and fires any saved hunt
whose cron schedule says it's due. "Firing" means re-running the saved
translated query against the configured event warehouse (Elasticsearch
today; Splunk and Chronicle drivers shipped as scaffolds — see
:mod:`app.services.event_warehouse`) and, if the hit count exceeds
zero, opening a case so the duty analyst sees the result on the cases
queue.

Why an in-process asyncio worker instead of APScheduler?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The API service already runs two singleton ``asyncio.Task`` workers
(``oauth_refresh``, ``weekly_digest``) from the ``lifespan`` hook. They
share the same DB engine and shutdown semantics. Adding a third in the
same shape is the path of least surprise for operators — one process,
one log stream, one scaling unit. Pulling in APScheduler would give us
better cron semantics but would also introduce a new dependency that
makes deployment and graceful shutdown harder to reason about.

Cron accuracy (Phase 4.5 update)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The bespoke 5-field parser that used to live in this module has been
replaced by :mod:`croniter`. The worker now honours the full POSIX
cron grammar (ranges, lists, day-of-week names, the ``L`` / ``W`` /
``#`` modifiers where croniter supports them) without changing the
call surface — :func:`_interval_seconds_for` and :func:`_is_due` are
still importable for tests, but they now delegate to croniter and
only fall back to the historical bespoke parser when croniter is
unavailable.

Warehouse provider (Phase 4.5 update)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The previous version of :func:`_execute_hunt` was hard-wired to
Elasticsearch via :mod:`app.services.esql_runner`. The scheduler now
goes through :func:`app.services.event_warehouse.resolve_provider`,
which picks an :class:`~app.services.event_warehouse.base.EventWarehouseProvider`
per hunt based on the keys present in ``hunt.translated_query``.
Elasticsearch is the only provider with a live execution path today;
Splunk + Chronicle are scaffolded so adding them is a one-PR change.

Disabling
~~~~~~~~~

Default-on, but flipped off in test environments and for operators who
run the API behind a separate scheduler service. Set
``AISOC_HUNT_SCHEDULER_ENABLED=false`` to disable. ``main.py`` honours
the flag the same way it gates ``oauth_refresh`` and
``weekly_digest``.
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
from app.services.event_warehouse import (
    HuntExecutionError,
    HuntNotConfigured,
    UnsupportedTranslation,
    resolve_provider,
)

try:
    from croniter import croniter  # type: ignore[import-untyped]

    _CRONITER_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via fallback path
    croniter = None  # type: ignore[assignment]
    _CRONITER_AVAILABLE = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cadence parsing — croniter front, bespoke fallback
# ---------------------------------------------------------------------------


def _fallback_interval_seconds_for(schedule: str) -> int | None:
    """Bespoke 5-field parser used when croniter is unavailable.

    Recognises ``"* * * * *"``, ``"*/N * * * *"``, ``"0 * * * *"``,
    ``"0 */N * * *"``, ``"0 0 * * *"`` and ``"0 0 * * <weekday>"``.
    Returns ``None`` for anything else — the worker treats ``None``
    as "skip" so an unparseable schedule never crashes the loop.
    """
    fields = schedule.strip().split()
    if len(fields) != 5:
        return None
    minute, hour, dom, month, dow = fields

    if minute.startswith("*/") and hour == "*" and dom == "*" and month == "*" and dow == "*":
        try:
            n = int(minute[2:])
            if n > 0:
                return n * 60
        except ValueError:
            return None
    if minute == "*" and hour == "*" and dom == "*" and month == "*" and dow == "*":
        return 60
    if minute.isdigit() and hour == "*" and dom == "*" and month == "*" and dow == "*":
        return 3600
    if minute.isdigit() and hour.startswith("*/") and dom == "*" and month == "*" and dow == "*":
        try:
            n = int(hour[2:])
            if n > 0:
                return n * 3600
        except ValueError:
            return None
    if minute.isdigit() and hour.isdigit() and dom == "*" and month == "*" and dow == "*":
        return 24 * 3600
    if minute.isdigit() and hour.isdigit() and dom == "*" and month == "*" and dow not in ("*", ""):
        return 7 * 24 * 3600
    return None


def _interval_seconds_for(schedule: str) -> int | None:
    """Average seconds between fires for ``schedule``.

    Used by tests and the legacy code path; the live scheduler now
    drives :func:`_is_due` through :func:`_next_fire_at` which honours
    the full cron grammar via croniter. We keep this helper because
    several existing tests assert on its return shape.
    """
    if not _CRONITER_AVAILABLE:
        return _fallback_interval_seconds_for(schedule)
    if not croniter.is_valid(schedule):  # type: ignore[union-attr]
        return None
    ref = datetime(2024, 1, 1, tzinfo=UTC)
    it = croniter(schedule, ref)  # type: ignore[misc]
    first = it.get_next(datetime)
    second = it.get_next(datetime)
    delta = (second - first).total_seconds()
    return int(delta) if delta > 0 else None


def _next_fire_at(schedule: str, *, after: datetime) -> datetime | None:
    """The next datetime ``schedule`` would fire strictly after ``after``.

    Returns ``None`` for an invalid schedule. The worker uses this for
    "is the hunt due?" — strictly more accurate than averaging the
    interval, especially for schedules whose cadence isn't constant
    (e.g. weekday-only rules).
    """
    if not _CRONITER_AVAILABLE:
        interval = _fallback_interval_seconds_for(schedule)
        if interval is None:
            return None
        return after + timedelta(seconds=interval)
    if not croniter.is_valid(schedule):  # type: ignore[union-attr]
        return None
    return croniter(schedule, after).get_next(datetime)  # type: ignore[misc, no-any-return]


def _is_due(hunt: SavedHunt, now: datetime) -> bool:
    """Should ``hunt`` be fired at ``now``?

    A hunt is due when the schedule's next fire-time (computed from
    its last run, or from ``created_at`` for a brand-new hunt) has
    passed.
    """
    if not hunt.schedule:
        return False
    last = hunt.last_run_at or hunt.created_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    next_at = _next_fire_at(hunt.schedule, after=last)
    if next_at is None:
        return False
    if next_at.tzinfo is None:
        next_at = next_at.replace(tzinfo=UTC)
    return next_at <= now


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
# Hunt execution — routes through the warehouse provider registry
# ---------------------------------------------------------------------------


async def _execute_hunt(db: AsyncSession, hunt: SavedHunt) -> int:
    """Run the hunt's translated query and return the hit count.

    Picks an :class:`~app.services.event_warehouse.base.EventWarehouseProvider`
    via :func:`resolve_provider`, then delegates the actual query
    execution to the driver. The scheduler stays agnostic of the
    backend — adding Splunk / Chronicle as live drivers later changes
    nothing here.

    Returns ``0`` (and logs at INFO) when:

    * The hunt has no translated query for any registered provider —
      typically a draft saved before the translator ran. The worker
      doesn't re-translate, only re-runs.
    * The chosen provider raises :class:`HuntNotConfigured` (missing
      credentials, scaffolded driver). The worker stays quiet in
      self-hosted dev where warehouses aren't wired up.

    Raises warehouse transport / air-gap errors back to the caller,
    where :func:`run_once` records them via ``logger.exception`` and
    skips the ``last_run_at`` bump so the hunt retries next tick.
    """
    _ = db  # unused — kept in the signature for future hunt-specific reads
    try:
        provider = resolve_provider(hunt)
    except UnsupportedTranslation as exc:
        logger.info(
            "hunt_scheduler.execute_skip hunt_id=%s reason=no_provider err=%s",
            hunt.id,
            exc,
        )
        return 0

    max_rows = int(getattr(settings, "HUNT_SCHEDULER_MAX_ROWS", 500))
    try:
        return await provider.run_hunt(hunt, max_rows=max_rows)
    except HuntNotConfigured as exc:
        logger.info(
            "hunt_scheduler.execute_skip hunt_id=%s provider=%s reason=not_configured err=%s",
            hunt.id,
            provider.name,
            exc,
        )
        return 0
    except UnsupportedTranslation as exc:
        logger.info(
            "hunt_scheduler.execute_skip hunt_id=%s provider=%s reason=unsupported_translation err=%s",
            hunt.id,
            provider.name,
            exc,
        )
        return 0
    except (AirgapViolation, ValueError, HuntExecutionError) as exc:
        logger.warning(
            "hunt_scheduler.execute_failed hunt_id=%s provider=%s err=%s",
            hunt.id,
            provider.name,
            type(exc).__name__,
        )
        raise


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
    the warehouse or the case lifecycle.
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


__all__ = [
    "HitCallback",
    "run_forever",
    "run_once",
    "_execute_hunt",
    "_is_due",
    "_interval_seconds_for",
    "_next_fire_at",
    "_open_case_for_hits",
]
