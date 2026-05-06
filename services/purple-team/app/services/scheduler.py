"""APScheduler-based detection drift snapshot scheduler.

Recomputes ATT&CK coverage from each tenant's current execution history
on a fixed cadence (default: weekly) and persists a
``DetectionDriftSnapshot`` row per tenant. The MITRE heatmap UI then
diffs the two most recent snapshots to surface "delta vs. last week".

Mirrors the pattern in ``services/threatintel/app/feeds/scheduler.py``.
"""

from __future__ import annotations

import logging
import uuid

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.models.purple_team import AtomicTest, TestExecution
from app.services.drift import capture_snapshot

LOG = logging.getLogger(__name__)


class DriftScheduler:
    """Periodically captures coverage snapshots across all known tenants."""

    JOB_ID = "purple-team-drift-snapshot"

    def __init__(
        self,
        session_factory: async_sessionmaker,
        interval_seconds: int,
    ) -> None:
        self._session_factory = session_factory
        self._interval_seconds = interval_seconds
        self._scheduler = AsyncIOScheduler()

    async def _discover_tenants(self) -> list[uuid.UUID]:
        """Tenants with any purple-team data — atomic catalog or executions.

        We can't reach the central tenants table from here without
        crossing a service boundary, so we discover tenants from rows
        the service itself owns. A tenant with zero rows has nothing
        to snapshot.
        """

        async with self._session_factory() as session:
            tids: set[uuid.UUID] = set()
            for table in (TestExecution, AtomicTest):
                rows = await session.execute(select(table.tenant_id).distinct())
                tids.update(rows.scalars().all())
            return list(tids)

    async def _run_once(self) -> None:
        """Single scheduler tick — snapshot every active tenant."""

        tenants = await self._discover_tenants()
        if not tenants:
            LOG.info("Drift scheduler tick: no tenants with purple-team data")
            return

        async with self._session_factory() as session:
            for tenant_id in tenants:
                try:
                    snap = await capture_snapshot(
                        session, tenant_id, trigger="scheduled"
                    )
                    LOG.info(
                        "Captured drift snapshot tenant=%s coverage=%.3f tested=%d",
                        tenant_id,
                        snap.overall_coverage,
                        snap.tested_techniques,
                    )
                except Exception:
                    LOG.exception(
                        "Drift snapshot failed for tenant=%s", tenant_id
                    )
            await session.commit()

    def start(self) -> None:
        """Register the snapshot job and start the scheduler."""

        if self._interval_seconds <= 0:
            LOG.info("Drift scheduler disabled (interval<=0)")
            return

        self._scheduler.add_job(
            func=self._run_once,
            trigger=IntervalTrigger(seconds=self._interval_seconds),
            id=self.JOB_ID,
            name="Detection drift snapshot",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        if not self._scheduler.running:
            self._scheduler.start()
        LOG.info(
            "Drift scheduler started (interval=%ss)", self._interval_seconds
        )

    def stop(self) -> None:
        """Gracefully stop the scheduler."""

        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            LOG.info("Drift scheduler stopped")
