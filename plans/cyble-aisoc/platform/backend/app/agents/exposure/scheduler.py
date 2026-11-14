"""Periodic scheduler for the closed-loop Exposure Agent (t3a-closed-loop).

Modeled on the BAS scheduler. Differences:

* Cadence is hourly (vs. BAS's nightly) — dark-web leaks and typosquats
  appear unpredictably; a one-day latency on credential exposure is
  already a postmortem-class miss.
* Each sweep is verification-aware, so the loop both opens new cases
  AND re-confirms / closes the previous sweep's open exposure cases.
* The lifespan-managed background task degrades gracefully: any tenant
  raising during a sweep is logged + skipped; the loop survives.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Iterable

from sqlmodel import select

from app.config import settings
from app.db import session_scope
from app.models.case import Case

from .agent import ExposureAgent

logger = logging.getLogger(__name__)

_task: asyncio.Task[None] | None = None
_stop_event: asyncio.Event | None = None


def _discover_tenants() -> list[str]:
    """Tenants we should sweep against.

    Union of the configured demo tenants and every tenant we've ever
    persisted a Case for — same heuristic as the BAS scheduler so a
    fresh seed gets coverage and live MSSP tenants accumulate
    automatically as they appear.
    """
    seeded = {settings.default_tenant, settings.demo_mssp_tenant}
    seeded.update(settings.demo_mssp_children)

    observed: set[str] = set()
    try:
        with session_scope() as session:
            for tid in session.exec(select(Case.tenant_id).distinct()).all():
                if tid:
                    observed.add(tid)
    except Exception:  # pragma: no cover - discovery must never crash boot
        logger.exception(
            "exposure_scheduler: tenant discovery failed; using seeded set only"
        )

    return sorted(seeded | observed)


async def _scan_one_tenant(tenant_id: str) -> None:
    """One bounded sweep per tenant."""
    try:
        with session_scope() as session:
            agent = ExposureAgent(session=session, tenant_id=tenant_id)
            result = await asyncio.wait_for(
                agent.sweep(),
                timeout=settings.exposure_sweep_timeout_seconds,
            )
        logger.info(
            "exposure_scheduler: tenant=%s findings=%d new=%d "
            "cases_opened=%d verified_closed=%d escalated=%d "
            "responses_routed=%d",
            tenant_id,
            result.findings_total,
            result.new_findings,
            len(result.cases_opened),
            len(result.cases_verified_closed),
            len(result.cases_escalated),
            result.responses_routed,
        )
    except asyncio.TimeoutError:
        logger.error(
            "exposure_scheduler: tenant=%s sweep exceeded %ds — skipping",
            tenant_id,
            settings.exposure_sweep_timeout_seconds,
        )
    except Exception:
        # Per-tenant isolation: one bad CTI hit / one broken response
        # tool mapping must not bring down the loop. Cases already
        # opened in the failing sweep have been committed by the
        # agent's session, so a late raise doesn't roll them back.
        logger.exception(
            "exposure_scheduler: tenant=%s sweep crashed",
            tenant_id,
        )


async def _scan_tenants(tenants: Iterable[str]) -> None:
    for tid in tenants:
        if _stop_event is not None and _stop_event.is_set():
            return
        await _scan_one_tenant(tid)


async def _run_loop() -> None:
    """Forever-loop until ``stop_background_tasks`` is called."""
    assert _stop_event is not None

    # Initial delay so rolling restarts don't fan out N concurrent
    # CTI sweeps against the same endpoints.
    try:
        await asyncio.wait_for(
            _stop_event.wait(),
            timeout=settings.exposure_initial_delay_seconds,
        )
        return  # stop fired during warm-up
    except asyncio.TimeoutError:
        pass

    while not _stop_event.is_set():
        tenants = _discover_tenants()
        logger.info(
            "exposure_scheduler: starting sweep over %d tenant(s): %s",
            len(tenants),
            tenants,
        )
        await _scan_tenants(tenants)

        try:
            await asyncio.wait_for(
                _stop_event.wait(),
                timeout=settings.exposure_scan_interval_seconds,
            )
            return  # stop fired during inter-sweep sleep
        except asyncio.TimeoutError:
            continue  # next sweep


def start_background_tasks() -> None:
    """Spawn the Exposure scheduler loop. Idempotent."""
    global _task, _stop_event

    if not settings.exposure_scheduler_enabled:
        logger.info(
            "exposure_scheduler: disabled via settings.exposure_scheduler_enabled"
        )
        return
    if _task is not None and not _task.done():
        return  # already running

    _stop_event = asyncio.Event()
    _task = asyncio.create_task(_run_loop(), name="exposure-scheduler")
    logger.info(
        "exposure_scheduler: started (interval=%ds, initial_delay=%ds, "
        "timeout=%ds, verification_window=%ds)",
        settings.exposure_scan_interval_seconds,
        settings.exposure_initial_delay_seconds,
        settings.exposure_sweep_timeout_seconds,
        settings.exposure_verification_window_seconds,
    )


async def stop_background_tasks() -> None:
    """Signal loop exit and await termination."""
    global _task, _stop_event

    if _stop_event is not None:
        _stop_event.set()
    if _task is not None:
        try:
            await asyncio.wait_for(_task, timeout=5.0)
        except asyncio.TimeoutError:
            _task.cancel()
            try:
                await _task
            except (asyncio.CancelledError, Exception):
                pass
        finally:
            _task = None
            _stop_event = None
