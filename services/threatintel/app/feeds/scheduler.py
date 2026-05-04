"""
APScheduler-based feed polling orchestrator.

Coordinates TAXII, MISP, OTX, and CISA KEV polling intervals and
pipes normalized IOCs through the deduplication + storage pipeline.

AiSOC — open-source AI Security Operations Center (MIT License)
"""
from __future__ import annotations

import structlog
from typing import TYPE_CHECKING

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

if TYPE_CHECKING:
    from app.feeds.pipeline import ThreatIntelPipeline

logger = structlog.get_logger(__name__)


class FeedScheduler:
    """
    Manages periodic polling of all threat intelligence feeds.

    Each feed has its own job with a configurable interval so that
    high-frequency feeds (e.g., TAXII every 15 min) and low-frequency
    feeds (CISA KEV once a day) can coexist without contention.
    """

    def __init__(self, pipeline: "ThreatIntelPipeline") -> None:
        self._pipeline = pipeline
        self._scheduler = AsyncIOScheduler()

    def register(
        self,
        feed_name: str,
        handler,
        interval_seconds: int,
    ) -> None:
        """Register a feed polling function."""
        self._scheduler.add_job(
            func=handler,
            trigger=IntervalTrigger(seconds=interval_seconds),
            id=feed_name,
            name=f"Feed: {feed_name}",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        logger.info(
            "Registered feed",
            feed=feed_name,
            interval_seconds=interval_seconds,
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
