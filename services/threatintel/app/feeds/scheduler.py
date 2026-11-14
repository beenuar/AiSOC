"""
APScheduler-based feed polling orchestrator.

Coordinates TAXII, MISP, OTX, and CISA KEV polling intervals and
pipes normalized IOCs through the deduplication + storage pipeline.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

if TYPE_CHECKING:
    from app.feeds.pipeline import ThreatIntelPipeline

logger = structlog.get_logger(__name__)

#: Window the first poll of each feed is scattered across, in seconds.
#:
#: Not zero, because several feeds registering at once would otherwise fire
#: simultaneously into the same Redis bloom filter and the same vector store on
#: every boot. Not large, because a new install has nothing on its threat-intel
#: page until the first poll returns and that page is one of the first a new
#: user opens.
FIRST_POLL_JITTER_SECONDS = 20


class FeedScheduler:
    """
    Manages periodic polling of all threat intelligence feeds.

    Each feed has its own job with a configurable interval so that
    high-frequency feeds (e.g., TAXII every 15 min) and low-frequency
    feeds (CISA KEV once a day) can coexist without contention.
    """

    def __init__(self, pipeline: ThreatIntelPipeline) -> None:
        self._pipeline = pipeline
        self._scheduler = AsyncIOScheduler()

    def register(
        self,
        feed_name: str,
        handler,
        interval_seconds: int,
    ) -> None:
        """Register a feed polling function, polled now and then on interval.

        ``next_run_time`` is explicit because an ``IntervalTrigger`` on its own
        schedules its *first* run one full interval after the scheduler starts.
        CISA KEV polls daily, so a fresh ``make up`` would have shown an empty
        Threat Intelligence page for twenty-four hours — with every component
        running, healthy, and correct. That is indistinguishable from the
        feature not working, and it is the first page a new user looks at for
        evidence the product does anything on its own.
        """
        first_run = datetime.now(UTC) + timedelta(seconds=random.uniform(1, FIRST_POLL_JITTER_SECONDS))  # noqa: S311 - scheduling jitter, not a security decision
        self._scheduler.add_job(
            func=handler,
            trigger=IntervalTrigger(seconds=interval_seconds),
            id=feed_name,
            name=f"Feed: {feed_name}",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
            next_run_time=first_run,
        )
        logger.info(
            "Registered feed",
            feed=feed_name,
            interval_seconds=interval_seconds,
            first_poll_at=first_run.isoformat(),
        )

    def start(self) -> None:
        """Start the scheduler (non-blocking in async context)."""
        if not self._scheduler.running:
            self._scheduler.start()
            logger.info("Feed scheduler started")

    def stop(self) -> None:
        """Gracefully stop the scheduler."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)
            logger.info("Feed scheduler stopped")
