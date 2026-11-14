"""Periodic scheduler for the Brand Responder (t3c-brand-takedown).

Modeled on :mod:`app.agents.exposure.scheduler`. Differences:

* Cadence is multi-hour (default 6h) rather than hourly. Takedowns are
  downstream of brand-intel; registrars need time to action what we
  already filed before we hammer them again.
* Each sweep is idempotent against the ``(tenant, brand_asset,
  candidate_domain)`` key, so a missed cycle or a double-fire only
  refreshes ``last_seen`` / ``score`` rather than duplicating filings.
* The lifespan-managed background task degrades gracefully: any tenant
  raising during a sweep is logged + skipped; the loop survives.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Iterable

from sqlmodel import select

from app.brand_responder.responder import BrandResponderAgent
from app.config import settings
from app.db import session_scope
from app.models.brand import BrandAsset
from app.models.case import Case

logger = logging.getLogger(__name__)

_task: asyncio.Task[None] | None = None
_stop_event: asyncio.Event | None = None


def _discover_tenants() -> list[str]:
    """Tenants we should sweep against.

    Union of the configured demo tenants, every tenant we've ever
    persisted a Case for, AND every tenant with at least one registered
    BrandAsset. The latter matters because a freshly onboarded MSSP
    child may have brand assets before its first case lands, and we
    still need to defend them.
    """
    seeded = {settings.default_tenant, settings.demo_mssp_tenant}
    seeded.update(settings.demo_mssp_children)

    observed: set[str] = set()
    try:
        with session_scope() as session:
            for tid in session.exec(select(Case.tenant_id).distinct()).all():
                if tid:
                    observed.add(tid)
            for tid in session.exec(
                select(BrandAsset.tenant_id).distinct()
            ).all():
                if tid:
                    observed.add(tid)
    except Exception:  # pragma: no cover - discovery must never crash boot
        logger.exception(
            "brand_scheduler: tenant discovery failed; using seeded set only"
        )

    return sorted(seeded | observed)


async def _scan_one_tenant(tenant_id: str) -> None:
    """One bounded sweep per tenant."""
    try:
        with session_scope() as session:
            agent = BrandResponderAgent(session=session, tenant_id=tenant_id)
            report = await asyncio.wait_for(
                agent.sweep(),
                timeout=settings.brand_sweep_timeout_seconds,
            )
        logger.info(
            "brand_scheduler: tenant=%s considered=%d recorded=%d "
            "auto_filed=%d parked=%d submitted=%d ack=%d failed=%d "
            "cases=%d errors=%d",
            tenant_id,
            report.candidates_considered,
            report.candidates_recorded,
            report.candidates_auto_filed,
            report.candidates_parked,
            report.takedowns_submitted,
            report.takedowns_acknowledged,
            report.takedowns_failed,
            len(report.cases_opened),
            len(report.errors),
        )
    except asyncio.TimeoutError:
        logger.error(
            "brand_scheduler: tenant=%s sweep exceeded %ds — skipping",
            tenant_id,
            settings.brand_sweep_timeout_seconds,
        )
    except Exception:
        # Per-tenant isolation: one broken brand-intel tool / one
        # broken submitter must not bring down the loop. Rows
        # already committed in the failing sweep survive a late
        # raise because the agent commits per candidate.
        logger.exception(
            "brand_scheduler: tenant=%s sweep crashed",
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
    # brand-intel sweeps against the same endpoints.
    try:
        await asyncio.wait_for(
            _stop_event.wait(),
            timeout=settings.brand_initial_delay_seconds,
        )
        return  # stop fired during warm-up
    except asyncio.TimeoutError:
        pass

    while not _stop_event.is_set():
        tenants = _discover_tenants()
        logger.info(
            "brand_scheduler: starting sweep over %d tenant(s): %s",
            len(tenants),
            tenants,
        )
        await _scan_tenants(tenants)

        try:
            await asyncio.wait_for(
                _stop_event.wait(),
                timeout=settings.brand_scan_interval_seconds,
            )
            return  # stop fired during inter-sweep sleep
        except asyncio.TimeoutError:
            continue  # next sweep


def start_background_tasks() -> None:
    """Spawn the Brand Responder scheduler loop. Idempotent."""
    global _task, _stop_event

    if not settings.brand_scheduler_enabled:
        logger.info(
            "brand_scheduler: disabled via settings.brand_scheduler_enabled"
        )
        return
    if _task is not None and not _task.done():
        return  # already running

    _stop_event = asyncio.Event()
    _task = asyncio.create_task(_run_loop(), name="brand-responder-scheduler")
    logger.info(
        "brand_scheduler: started (interval=%ds, initial_delay=%ds, "
        "timeout=%ds, auto_threshold=%d, min_score=%d)",
        settings.brand_scan_interval_seconds,
        settings.brand_initial_delay_seconds,
        settings.brand_sweep_timeout_seconds,
        settings.brand_auto_takedown_threshold,
        settings.brand_min_candidate_score,
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
