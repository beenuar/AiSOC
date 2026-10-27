"""The fused-alert publish must wait for the broker, not for the accumulator.

``AIOKafkaProducer.send`` is a coroutine that appends a record to the client's
in-memory batch accumulator and returns a **future** that resolves when the
broker acknowledges it. Awaiting the call therefore awaits the *enqueue*; the
delivery result is in the returned future, and a caller that drops the future
has learned nothing about whether the record was ever delivered.

The consumer commits the input offset as soon as the message is handled. So an
enqueue-only publish means the offset advances while the envelope is still in
process memory: a kill in that window leaves the alert row in Postgres, the
offset past it, and nothing on ``aisoc.alerts.fused`` for auto-triage to read.

The repository already applies the right pattern two files away --
``dlq.KafkaDLQ.record`` does ``future = await send(...)`` then ``await future``
and says why, and ``dlq_replay`` uses ``send_and_wait``. The fused-alert hot
path was the one place it was not applied.

Why the double here is shaped the way it is
-------------------------------------------
``AsyncMock()`` cannot test this. Its ``send`` returns an awaitable resolving
to a ``MagicMock``, so ``send`` and ``send_and_wait`` are indistinguishable:
both read as "awaited, no exception". Every assertion built on one would pass
against the defect. :class:`TwoStageProducer` models the real contract -- the
enqueue and the acknowledgement are separate awaitables with separate outcomes
-- which is the only way a test can tell the two apart.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.core.config import settings
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_sink import PersistOutcome, PersistResult
from app.workers.consumer import FusionWorker, RetryableProcessingError


class TwoStageProducer:
    """A producer double with aiokafka's real enqueue/acknowledge split.

    ``send`` resolves as soon as the record is "accepted into the batch" and
    hands back a future. What that future does is the whole point of the
    double: it can resolve with metadata (delivered), resolve with an
    exception (the broker refused it *after* the enqueue returned), or never
    resolve at all (the record is still sitting in the accumulator).
    """

    def __init__(self, *, ack_after: float = 0.0, ack_error: Exception | None = None, never_ack: bool = False) -> None:
        self.enqueued: list[dict] = []
        self.futures: list[asyncio.Future] = []
        self._ack_after = ack_after
        self._ack_error = ack_error
        self._never_ack = never_ack
        self._tasks: list[asyncio.Task] = []

    async def send(self, topic, value=None, key=None):  # noqa: ANN001, ANN201
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self.enqueued.append({"topic": topic, "value": value, "key": key})
        self.futures.append(future)
        if not self._never_ack:
            self._tasks.append(loop.create_task(self._settle(future)))
        return future

    async def _settle(self, future: asyncio.Future) -> None:
        if self._ack_after:
            await asyncio.sleep(self._ack_after)
        if future.done():  # pragma: no cover — the caller cancelled it
            return
        if self._ack_error is not None:
            future.set_exception(self._ack_error)
        else:
            future.set_result(SimpleNamespace(topic="t", partition=0, offset=len(self.enqueued)))

    async def drain(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)


def _alert() -> RawAlert:
    return RawAlert(
        tenant_id="00000000-0000-0000-0000-000000000001",
        source="CrowdStrike Falcon",
        title="Credential dumping via LSASS access",
        severity=AlertSeverity.CRITICAL,
        src_ip="10.20.30.40",
        hostname="WIN-DC01",
    )


def _fused(alert: RawAlert) -> FusedAlert:
    alert.id = alert.deterministic_id()
    return FusedAlert(id=alert.id, tenant_id=alert.tenant_id, fusion_decision=FusionDecision.NEW_ALERT, alert=alert)


def _worker(producer) -> tuple[FusionWorker, RawAlert]:  # noqa: ANN001
    alert = _alert()
    fused = _fused(alert)
    worker = FusionWorker(engine=SimpleNamespace(process=AsyncMock(return_value=fused)), sink=AsyncMock())
    worker._sink.persist = AsyncMock(return_value=PersistResult(PersistOutcome.INSERTED, str(fused.id)))  # noqa: SLF001
    worker._producer = producer  # noqa: SLF001
    return worker, alert


@pytest.mark.asyncio
async def test_a_broker_error_delivered_after_the_enqueue_is_observed(monkeypatch):
    """The acceptance case: a *delayed* delivery failure must be reported.

    The enqueue succeeds -- there is no exception to catch at that point --
    and the broker refuses the record a moment later. Code that awaits only
    the enqueue returns cleanly here and lets the offset commit, so the alert
    row exists in Postgres with nothing ever published for it.
    """
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 2.0)
    producer = TwoStageProducer(ack_after=0.02, ack_error=RuntimeError("NotLeaderForPartitionError"))
    worker, alert = _worker(producer)

    before = worker.get_metrics()["publish_failed"]
    with pytest.raises(RetryableProcessingError):
        await worker._fuse_and_persist(alert)  # noqa: SLF001

    assert producer.enqueued, "the record should still have been enqueued"
    assert worker.get_metrics()["publish_failed"] == before + 1
    await producer.drain()


@pytest.mark.asyncio
async def test_an_unacknowledged_record_is_not_reported_as_published(monkeypatch):
    """A record still in the accumulator is not a delivery.

    This is the crash window stated directly: the broker never acknowledges,
    so the only honest outcome is "not delivered". Awaiting the enqueue alone
    returns immediately and reports success for an envelope that exists
    nowhere but this process's memory.
    """
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 0.2)
    producer = TwoStageProducer(never_ack=True)
    worker, alert = _worker(producer)

    with pytest.raises(RetryableProcessingError):
        await worker._fuse_and_persist(alert)  # noqa: SLF001
    assert worker.get_metrics()["publish_failed"] >= 1
    await producer.drain()


@pytest.mark.asyncio
async def test_publishing_returns_only_after_the_acknowledgement(monkeypatch):
    """The positive control, and the ordering claim stated directly.

    A successful delivery must still be a success -- without this the fix
    could be "always raise", which passes every failure test and breaks the
    pipeline. The second assertion is the one that distinguishes the two
    implementations on the *happy* path: when ``_fuse_and_persist`` returns,
    the acknowledgement must already have arrived. An enqueue-only publish
    returns with the future still pending.
    """
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 2.0)
    producer = TwoStageProducer(ack_after=0.01)
    worker, alert = _worker(producer)

    await worker._fuse_and_persist(alert)  # noqa: SLF001

    assert len(producer.enqueued) == 1
    assert producer.futures[0].done(), "returned before the broker acknowledged the record"
    assert producer.futures[0].exception() is None
    await producer.drain()


@pytest.mark.asyncio
async def test_the_published_envelope_carries_a_stable_dedupe_key(monkeypatch):
    """Duplicate publication is designed-for, so it needs a key to collapse on.

    Re-delivery republishes by design (the offset commit and the broker ack
    cannot be made atomic), so the contract downstream needs is a key that is
    identical across every republication of one alert and different between
    alerts. Keying the Kafka record also puts every copy of an alert on one
    partition, which is what makes a downstream de-duplicator tractable.
    """
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 2.0)
    producer = TwoStageProducer(ack_after=0.0)
    worker, alert = _worker(producer)

    await worker._fuse_and_persist(alert)  # noqa: SLF001
    await worker._fuse_and_persist(alert)  # noqa: SLF001 — the re-delivery

    keys = [record["key"] for record in producer.enqueued]
    assert len(keys) == 2
    assert keys[0] is not None, "a fused alert must be keyed so duplicates can be collapsed"
    assert keys[0] == keys[1], "the same alert must republish under the same key"
    assert keys[0] == str(alert.id)
    await producer.drain()
