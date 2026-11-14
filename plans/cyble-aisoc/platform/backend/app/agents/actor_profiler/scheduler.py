"""Periodic scheduler for the Threat Actor Profiling Agent (t3e-actor-profiling).

Mirrors :mod:`app.agents.exposure.scheduler`. Differences:

* Cadence defaults to slower than Exposure — actor attribution shifts
  on hour-to-day timescales, not minute-to-hour, so we don't need to
  re-resolve every IOC every sweep. The default 30 min interval gives
  fresh demo data without hammering CTI tools.
* Sweeps are pure-read for the actor catalogue itself; the only writes
  are tenant-scoped (``ThreatActor`` rows, ``ActorIOCLink`` rows, graph
  edges). A failing sweep can never corrupt the shared catalogue.
* Per-tenant isolation: one bad CTI response on tenant A must not
  delay or break tenant B's profiling. We log + skip and move on.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Iterable

from sqlmodel import select

from app.config import settings
from app.db import session_scope
from app.models.case import Case

from .agent import ThreatActorProfilingAgent

logger = logging.getLogger(__name__)

_task: asyncio.Task[None] | None = None
_stop_event: asyncio.Event | None = None


def _discover_tenants() -> list[str]:
    """Tenants the agent should sweep.

    Same heuristic as the Exposure scheduler: configured demo tenants
    plus any tenant we've ever opened a Case for. Means fresh demos
    get profiled immediately and live MSSP children appear as soon as
    they generate their first case.
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
            "actor_profiler_scheduler: tenant discovery failed; "
            "using seeded set only"
        )

    return sorted(seeded | observed)


async def _scan_one_tenant(tenant_id: str) -> None:
    """One bounded sweep per tenant."""
    try:
        with session_scope() as session:
            agent = ThreatActorProfilingAgent(
                session=session, tenant_id=tenant_id
            )
            result = await asyncio.wait_for(
                agent.sweep(),
                timeout=settings.actor_profiler_sweep_timeout_seconds,
            )
        logger.info(
            "actor_profiler_scheduler: tenant=%s iocs=%d actors=%d "
            "(new=%d) links=%d (new=%d) catalogue_misses=%d errors=%d",
            tenant_id,
            result.iocs_scanned,
            result.actors_upserted,
            result.actors_new,
            result.ioc_links_upserted,
            result.ioc_links_new,
            result.catalogue_misses,
            len(result.errors),
        )
    except asyncio.TimeoutError:
        logger.error(
            "actor_profiler_scheduler: tenant=%s sweep exceeded %ds — skipping",
            tenant_id,
            settings.actor_profiler_sweep_timeout_seconds,
        )
    except Exception:
        # Per-tenant isolation. Cases already committed by the agent's
        # session survive a late raise; we just lose this sweep.
        logger.exception(
            "actor_profiler_scheduler: tenant=%s sweep crashed",
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

    # Stagger initial sweep so rolling restarts don't fan out N
    # concurrent CTI lookups against the same endpoint.
    try:
        await asyncio.wait_for(
            _stop_event.wait(),
            timeout=settings.actor_profiler_initial_delay_seconds,
        )
        return  # stop fired during warm-up
    except asyncio.TimeoutError:
        pass

    while not _stop_event.is_set():
        tenants = _discover_tenants()
        logger.info(
            "actor_profiler_scheduler: starting sweep over %d tenant(s): %s",
            len(tenants),
            tenants,
        )
        await _scan_tenants(tenants)

        try:
            await asyncio.wait_for(
                _stop_event.wait(),
                timeout=settings.actor_profiler_scan_interval_seconds,
            )
            return  # stop fired during inter-sweep sleep
        except asyncio.TimeoutError:
            continue


def start_background_tasks() -> None:
    """Spawn the Actor Profiling scheduler loop. Idempotent."""
    global _task, _stop_event

    if not settings.actor_profiler_scheduler_enabled:
        logger.info(
            "actor_profiler_scheduler: disabled via "
            "settings.actor_profiler_scheduler_enabled"
        )
        return
    if _task is not None and not _task.done():
        return  # already running

    _stop_event = asyncio.Event()
    _task = asyncio.create_task(
        _run_loop(), name="actor-profiler-scheduler"
    )
    logger.info(
        "actor_profiler_scheduler: started (interval=%ds, "
        "initial_delay=%ds, timeout=%ds)",
        settings.actor_profiler_scan_interval_seconds,
        settings.actor_profiler_initial_delay_seconds,
        settings.actor_profiler_sweep_timeout_seconds,
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
