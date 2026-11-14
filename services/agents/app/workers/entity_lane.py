"""Concurrency for triage, with ordering kept per entity (parity 6.9).

Auto-triage processed one alert at a time: `async for msg` with an
inline `await` on an LLM call. That is an I/O-bound stage serialised on
network latency, and it is the slowest thing in the pipeline by a wide
margin — a replica spends almost all of its time waiting rather than
working.

Why not simply run them all at once
-----------------------------------
Because the ordering matters for exactly the alerts that are related.
Two alerts about one host are the ones most likely to be the same
incident, and triage reads institutional memory written by earlier
triages of the same entity. Running them concurrently makes the second
one's context depend on whether the first happened to finish first,
which turns a deterministic verdict into a race.

So concurrency is **per entity**: alerts about different entities run in
parallel up to a bound, and alerts about one entity run in the order
they arrived. That is the same property partitioning the Kafka topic by
entity gives across replicas, applied inside one.

Why a bound at all
------------------
An unbounded fan-out hands the model provider as many concurrent
requests as the topic can deliver, which is how a burst becomes a rate
limit and then a retry storm. The default is small and deliberately
stated as a policy choice rather than a measurement.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable

import structlog

logger = structlog.get_logger()

#: How many entities may be in flight at once. A policy choice, not a
#: measurement: nothing here claims eight is optimal. It is small enough
#: that a burst does not become a provider rate limit and large enough
#: that a replica is not idling on one network round trip.
DEFAULT_MAX_CONCURRENCY = 8

#: An upper bound on what an operator may ask for, for the same reason.
MAX_CONCURRENCY_CEILING = 64

_CONCURRENCY_ENV = "AISOC_TRIAGE_CONCURRENCY"


def configured_concurrency() -> int:
    """How many entities to process at once, from the environment.

    An unreadable or out-of-range value falls back to the default and
    says so. Silently clamping a typo would leave an operator who asked
    for 200 believing they got it.
    """
    raw = os.environ.get(_CONCURRENCY_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_CONCURRENCY
    try:
        value = int(raw)
    except ValueError:
        logger.error("triage.bad_concurrency", value=raw, using=DEFAULT_MAX_CONCURRENCY)
        return DEFAULT_MAX_CONCURRENCY
    if value < 1 or value > MAX_CONCURRENCY_CEILING:
        logger.error(
            "triage.concurrency_out_of_range",
            value=value,
            ceiling=MAX_CONCURRENCY_CEILING,
            using=DEFAULT_MAX_CONCURRENCY,
        )
        return DEFAULT_MAX_CONCURRENCY
    return value


def entity_of(alert: dict) -> str:
    """The entity an alert is about, in fusion's own precedence.

    The same order ``RawAlert.correlation_key()`` uses and the same order
    the ingest partition key uses, so the lane an alert runs in and the
    incident it correlates into are named by one field. An alert naming
    nobody gets its own lane, keyed by id: it shares an incident with
    nothing, so there is no order to preserve.
    """
    for key in ("src_ip", "hostname", "host", "username", "user", "domain"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    entities = alert.get("entities")
    if isinstance(entities, list):
        for item in entities:
            if isinstance(item, dict):
                value = item.get("value")
                if isinstance(value, str) and value.strip():
                    return value.strip()
    identifier = alert.get("id") or alert.get("alert_id")
    return f"alert:{identifier}" if identifier else "unknown"


class EntityLanes:
    """Runs work concurrently across entities and serially within one.

    Not a queue per entity held forever: a lane is created on demand and
    dropped when it drains, so a long-running deployment does not
    accumulate one lock per host it has ever seen.
    """

    def __init__(self, max_concurrency: int | None = None) -> None:
        self._limit = max_concurrency if max_concurrency is not None else configured_concurrency()
        self._semaphore = asyncio.Semaphore(self._limit)
        self._locks: dict[str, asyncio.Lock] = {}
        self._waiters: dict[str, int] = {}
        self._tasks: set[asyncio.Task] = set()

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def in_flight(self) -> int:
        return len(self._tasks)

    @property
    def tracked_entities(self) -> int:
        """Lanes currently held. Should return to zero when idle."""
        return len(self._locks)

    def _lock_for(self, entity: str) -> asyncio.Lock:
        lock = self._locks.get(entity)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[entity] = lock
        self._waiters[entity] = self._waiters.get(entity, 0) + 1
        return lock

    def _release(self, entity: str) -> None:
        remaining = self._waiters.get(entity, 1) - 1
        if remaining <= 0:
            self._waiters.pop(entity, None)
            self._locks.pop(entity, None)
        else:
            self._waiters[entity] = remaining

    async def submit(self, entity: str, work: Callable[[], Awaitable[None]]) -> asyncio.Task:
        """Schedule ``work`` in ``entity``'s lane and return its task.

        Returns immediately once the task is created; the caller decides
        when to wait. The task never raises: an exception escaping a
        background task leaves nothing in any log, which is the defect
        the consume loop's own guard exists for.
        """
        lock = self._lock_for(entity)

        async def _run() -> None:
            try:
                async with self._semaphore, lock:
                    await work()
            except Exception as exc:  # noqa: BLE001 — see the docstring
                logger.error(
                    "triage.lane_failed",
                    entity=entity,
                    error=str(exc),
                    error_type=type(exc).__name__,
                    exc_info=True,
                )
            finally:
                self._release(entity)

        task = asyncio.create_task(_run())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def drain(self) -> None:
        """Wait for everything in flight.

        Called before an offset commit: committing while work is in
        flight is the at-least-once contract broken, because a crash
        after the commit loses an alert that was never triaged.
        """
        while self._tasks:
            await asyncio.gather(*tuple(self._tasks), return_exceptions=True)
