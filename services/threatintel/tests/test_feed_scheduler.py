"""A feed that polls daily must still poll on the day it is installed.

`FeedScheduler.register` used to hand APScheduler an `IntervalTrigger` and
nothing else. An interval trigger schedules its *first* run one whole interval
after the scheduler starts, and CISA KEV's interval is 86400 seconds — so a
fresh `make up` had a healthy threatintel container, a registered feed, a
created Qdrant collection, and an empty Threat Intelligence page for the next
twenty-four hours.

Nothing was broken in a way any probe could see. The container was up, the log
said "Registered feed", and the page was correct: there genuinely were no
indicators. That is the shape of defect this file exists to catch, and it is
the same one that made every connector's poll job register as PAUSED.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from app.feeds.scheduler import FIRST_POLL_JITTER_SECONDS, FeedScheduler

DAILY = 86_400


async def _noop() -> None:
    """Stand-in for a feed handler; never invoked, the job is never run."""


@pytest.fixture
def scheduler() -> FeedScheduler:
    return FeedScheduler(pipeline=None)  # type: ignore[arg-type]  # register() never touches it


def _job(scheduler: FeedScheduler, feed: str):
    return scheduler._scheduler.get_job(feed)


def test_a_daily_feed_polls_within_the_first_minute(scheduler: FeedScheduler) -> None:
    before = datetime.now(UTC)
    scheduler.register(feed_name="cisa-kev", handler=_noop, interval_seconds=DAILY)

    job = _job(scheduler, "cisa-kev")
    assert job is not None, "register() did not add a job"
    assert job.next_run_time is not None, (
        "next_run_time is None, which APScheduler treats as a PAUSED job — the feed would never poll at all"
    )

    delay = (job.next_run_time - before).total_seconds()
    assert 0 <= delay <= FIRST_POLL_JITTER_SECONDS + 1, (
        f"first poll is {delay:.0f}s away. An IntervalTrigger alone would put it {DAILY}s away, "
        "which is a full day of an empty Threat Intelligence page on a working install."
    )


def test_the_recurring_interval_is_still_the_one_asked_for(scheduler: FeedScheduler) -> None:
    """Firing early must not turn a daily feed into a busy loop."""
    scheduler.register(feed_name="cisa-kev", handler=_noop, interval_seconds=DAILY)
    trigger = _job(scheduler, "cisa-kev").trigger
    assert trigger.interval == timedelta(seconds=DAILY)


def test_feeds_do_not_all_fire_at_the_same_instant(scheduler: FeedScheduler) -> None:
    """Jitter: several feeds registering at boot share one bloom filter and one
    vector store, and a synchronised stampede on every restart is avoidable."""
    for name in ("cisa-kev", "misp", "otx", "taxii:enterprise-attack"):
        scheduler.register(feed_name=name, handler=_noop, interval_seconds=DAILY)

    times = {_job(scheduler, n).next_run_time for n in ("cisa-kev", "misp", "otx", "taxii:enterprise-attack")}
    assert len(times) > 1, "every feed was scheduled for the identical instant — the jitter is not being applied"


@pytest.mark.asyncio
async def test_re_registering_a_running_feed_replaces_rather_than_duplicates() -> None:
    """`replace_existing` only takes effect against a started scheduler.

    Before `start()`, APScheduler holds additions in a pending list and does
    not look for an id collision there, so two `register` calls really do
    produce two jobs. That is harmless — the lifespan registers each feed once,
    before starting — but it is worth pinning which of the two states the flag
    protects, so nobody later concludes from a pre-start duplicate that the
    flag is not working.
    """
    scheduler = FeedScheduler(pipeline=None)  # type: ignore[arg-type]
    scheduler.start()
    try:
        scheduler.register(feed_name="cisa-kev", handler=_noop, interval_seconds=DAILY)
        scheduler.register(feed_name="cisa-kev", handler=_noop, interval_seconds=DAILY)
        assert len(scheduler._scheduler.get_jobs()) == 1
    finally:
        scheduler.stop()
