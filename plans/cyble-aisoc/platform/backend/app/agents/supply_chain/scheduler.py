"""Periodic scheduler for the Supply-Chain Risk Agent (t3f-supply-chain).

Mirrors :mod:`app.agents.exposure.scheduler` and
:mod:`app.agents.actor_profiler.scheduler`.

Cadence is intentionally slower than the Exposure sweep — vendor
breach signals move on hour-to-day timescales, and each vendor pulls
multiple CTI tool calls so the cost-per-sweep is non-trivial. The
defaults give a useful demo (a few hours between sweeps) without
hammering the deterministic mock CTI catalogue.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Iterable

from sqlmodel import select

from app.config import settings
from app.db import session_scope
from app.models.case import Case

from .agent import SupplyChainAgent

logger = logging.getLogger(__name__)

_task: asyncio.Task[None] | None = None
_stop_event: asyncio.Event | None = None


def _discover_tenants() -> list[str]:
    """Tenants the agent should sweep.

    Same heuristic as the Exposure / Actor schedulers: configured demo
    tenants plus any tenant we've ever opened a Case for.
    """
    seeded = {settings.default_tenant, settings.demo_mssp_tenant}
    seeded.update(settings.demo_mssp_children)

    observed: set[str] = set()
    try:
        with session_scope() as session:
            for tid in session.exec(select(Case.tenant_id).distinct()).all():
                if tid:
                    observed.add(tid)
    except Exception:  # pragma: no cover — discovery must never crash boot
        logger.exception(
            "supply_chain_scheduler: tenant discovery failed; "
            "using seeded set only"
        )

    return sorted(seeded | observed)


async def _scan_one_tenant(tenant_id: str) -> None:
    """One bounded sweep per tenant."""
    try:
        with session_scope() as session:
            agent = SupplyChainAgent(session=session, tenant_id=tenant_id)
            result = await asyncio.wait_for(
                agent.sweep(),
                timeout=settings.supply_chain_sweep_timeout_seconds,
            )
        logger.info(
            "supply_chain_scheduler: tenant=%s vendors=%d signals=%d "
            "cases_opened=%d errors=%d",
            tenant_id,
            result.vendors_scanned,
            result.signals_recorded,
            len(result.cases_opened),
            len(result.errors),
        )
    except asyncio.TimeoutError:
        logger.error(
            "supply_chain_scheduler: tenant=%s sweep exceeded %ds — skipping",
            tenant_id,
            settings.supply_chain_sweep_timeout_seconds,
        )
    except Exception:
        logger.exception(
            "supply_chain_scheduler: tenant=%s sweep crashed",
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

    try:
        await asyncio.wait_for(
            _stop_event.wait(),
            timeout=settings.supply_chain_initial_delay_seconds,
        )
        return  # stop fired during warm-up
    except asyncio.TimeoutError:
        pass

    while not _stop_event.is_set():
        tenants = _discover_tenants()
        logger.info(
            "supply_chain_scheduler: starting sweep over %d tenant(s): %s",
            len(tenants),
            tenants,
        )
        await _scan_tenants(tenants)

        try:
            await asyncio.wait_for(
                _stop_event.wait(),
                timeout=settings.supply_chain_scan_interval_seconds,
            )
            return  # stop fired during inter-sweep sleep
        except asyncio.TimeoutError:
            continue


def start_background_tasks() -> None:
    """Spawn the supply-chain scheduler loop. Idempotent."""
    global _task, _stop_event

    if not settings.supply_chain_scheduler_enabled:
        logger.info(
            "supply_chain_scheduler: disabled via "
            "settings.supply_chain_scheduler_enabled"
        )
        return
    if _task is not None and not _task.done():
        return  # already running

    _stop_event = asyncio.Event()
    _task = asyncio.create_task(
        _run_loop(), name="supply-chain-scheduler"
    )
    logger.info(
        "supply_chain_scheduler: started (interval=%ds, "
        "initial_delay=%ds, timeout=%ds)",
        settings.supply_chain_scan_interval_seconds,
        settings.supply_chain_initial_delay_seconds,
        settings.supply_chain_sweep_timeout_seconds,
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
