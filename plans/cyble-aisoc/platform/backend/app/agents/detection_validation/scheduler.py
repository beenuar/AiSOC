"""Periodic scheduler for the Continuous Detection Validation Agent.

Runs the BAS agent on a fixed cadence per tenant so detection drift is
caught between releases without an analyst having to remember to click
``POST /detection-validation/scan``. The endpoint stays available for
on-demand runs (e.g. immediately after a Detection Author Agent PR
lands) — this module is the *baseline* heartbeat.

Why a bespoke loop instead of APScheduler / Celery beat:
- We're in-process inside the FastAPI app already; the BAS scan is
  cheap (single-digit seconds on the seed catalogue) so we don't need
  a worker pool.
- Lifespan integration means the loop dies with the app — no orphan
  worker processes, no separate deployment surface.
- Per-tenant fan-out is just a Python loop; we don't need cron-style
  expressions for "every 24h".

Failure posture:
- One tenant raising never blocks the others — each scan is wrapped
  in a try/except that logs and moves on.
- A scan that exceeds ``bas_scan_timeout_seconds`` is cancelled so a
  pathologically slow run can't pin the loop indefinitely.
- The loop itself is resilient to a fully empty tenant list (it just
  sleeps and re-discovers next tick).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Iterable

from sqlmodel import select

from app.config import settings
from app.db import session_scope
from app.models.case import Case
from app.models.detection_validation import ValidationRun

from .agent import DetectionValidationAgent

logger = logging.getLogger(__name__)

_task: asyncio.Task[None] | None = None
_stop_event: asyncio.Event | None = None


def _discover_tenants() -> list[str]:
    """Return the set of tenants we should run BAS scans against.

    Strategy: union of every tenant we've actually seen do work
    (cases written, validation runs persisted) plus the configured
    demo tenants so a freshly-seeded box still gets covered. Sorted
    for stable scan ordering across restarts.
    """
    seeded = {settings.default_tenant, settings.demo_mssp_tenant}
    seeded.update(settings.demo_mssp_children)

    observed: set[str] = set()
    try:
        with session_scope() as session:
            for tid in session.exec(select(Case.tenant_id).distinct()).all():
                if tid:
                    observed.add(tid)
            for tid in session.exec(select(ValidationRun.tenant_id).distinct()).all():
                if tid:
                    observed.add(tid)
    except Exception:  # pragma: no cover - discovery must never crash boot
        logger.exception("bas_scheduler: tenant discovery failed; using seeded set only")

    return sorted(seeded | observed)


async def _scan_one_tenant(tenant_id: str) -> None:
    """Run a single BAS sweep for one tenant, bounded by timeout."""
    # Each scan gets its own short-lived session so the loop never
    # holds a connection across the inter-tenant gap.
    try:
        with session_scope() as session:
            agent = DetectionValidationAgent(session=session, tenant_id=tenant_id)
            result = await asyncio.wait_for(
                agent.scan(),
                timeout=settings.bas_scan_timeout_seconds,
            )
        logger.info(
            "bas_scheduler: tenant=%s run_id=%s sims=%d drift=%d regressions=%d cases=%d",
            tenant_id,
            result.run_id,
            result.simulations_run,
            result.drift_count,
            result.coverage_regressions,
            len(result.cases_opened),
        )
    except asyncio.TimeoutError:
        logger.error(
            "bas_scheduler: tenant=%s scan exceeded %ds — skipping",
            tenant_id,
            settings.bas_scan_timeout_seconds,
        )
    except Exception:
        # One tenant failing must never bring down the loop. Cases
        # opened on partial drift have already been committed by the
        # agent's inner session, so a late failure does not roll
        # back diagnostic value.
        logger.exception("bas_scheduler: tenant=%s scan crashed", tenant_id)


async def _scan_tenants(tenants: Iterable[str]) -> None:
    for tid in tenants:
        if _stop_event is not None and _stop_event.is_set():
            return
        await _scan_one_tenant(tid)


async def _run_loop() -> None:
    """Forever-loop until ``stop_background_tasks`` is called."""
    assert _stop_event is not None  # set by start_background_tasks

    # Initial delay so a rolling restart doesn't immediately re-replay
    # the full catalogue on every box at the same instant.
    try:
        await asyncio.wait_for(
            _stop_event.wait(),
            timeout=settings.bas_initial_delay_seconds,
        )
        return  # stop fired during the warm-up
    except asyncio.TimeoutError:
        pass

    while not _stop_event.is_set():
        tenants = _discover_tenants()
        logger.info(
            "bas_scheduler: starting sweep over %d tenant(s): %s",
            len(tenants),
            tenants,
        )
        await _scan_tenants(tenants)

        try:
            await asyncio.wait_for(
                _stop_event.wait(),
                timeout=settings.bas_scan_interval_seconds,
            )
            return  # stop fired during the inter-sweep sleep
        except asyncio.TimeoutError:
            continue  # next sweep


def start_background_tasks() -> None:
    """Spawn the BAS scheduler loop. Idempotent."""
    global _task, _stop_event

    if not settings.bas_scheduler_enabled:
        logger.info("bas_scheduler: disabled via settings.bas_scheduler_enabled")
        return
    if _task is not None and not _task.done():
        return  # already running

    _stop_event = asyncio.Event()
    _task = asyncio.create_task(_run_loop(), name="bas-scheduler")
    logger.info(
        "bas_scheduler: started (interval=%ds, initial_delay=%ds, timeout=%ds)",
        settings.bas_scan_interval_seconds,
        settings.bas_initial_delay_seconds,
        settings.bas_scan_timeout_seconds,
    )


async def stop_background_tasks() -> None:
    """Signal the loop to exit and await its termination."""
    global _task, _stop_event

    if _stop_event is not None:
        _stop_event.set()
    if _task is not None:
        try:
            await asyncio.wait_for(_task, timeout=5.0)
        except asyncio.TimeoutError:
            # Loop is wedged inside a scan — cancel it.
            _task.cancel()
            try:
                await _task
            except (asyncio.CancelledError, Exception):
                pass
        finally:
            _task = None
            _stop_event = None
