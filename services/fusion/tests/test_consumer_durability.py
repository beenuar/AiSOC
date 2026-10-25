"""Durability regression tests for the fusion consumer's ack boundary.

The defect these pin: a per-message exception was logged, the loop moved on,
and the *next* successful message committed past the failed offset. A Postgres
outage therefore became permanent event loss. These tests drive the retry /
classification machinery directly (no Kafka) and assert the two invariants that
make loss impossible:

* the offset is committed only when the message is durable or captured;
* a transient failure is retried with a bounded backoff, and a failure to
  capture is held uncommitted rather than acknowledged.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiokafka import TopicPartition
from app.core.config import settings
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_sink import AlertSink, PersistOutcome, PersistResult
from app.services.dlq import InMemoryDLQ, LoggingDLQ
from app.services.dlq_sink import PostgresDLQ
from app.workers.consumer import (
    FusionWorker,
    PermanentProcessingError,
    RetryableProcessingError,
    _decode_record_value,
    _UnparseableRecord,
)


def _msg(offset: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        value={"tenant_id": "00000000-0000-0000-0000-000000000001", "nonsense": True},
        topic=settings.kafka_topic_raw_events,
        partition=0,
        offset=offset,
    )


def _worker(dlq=None) -> FusionWorker:
    worker = FusionWorker(engine=SimpleNamespace(process=AsyncMock()), dlq=dlq)
    worker._running = True  # noqa: SLF001 — this test drives the loop directly
    worker._stop_event.clear()  # noqa: SLF001
    return worker


def _retry_settings(monkeypatch: pytest.MonkeyPatch, *, attempts: int) -> None:
    monkeypatch.setattr(settings, "consumer_max_retries", attempts)
    monkeypatch.setattr(settings, "consumer_retry_base_seconds", 0.0)
    monkeypatch.setattr(settings, "consumer_retry_max_seconds", 0.0)
    monkeypatch.setattr(settings, "consumer_recovery_retry_seconds", 0.01)


@pytest.mark.asyncio
async def test_transient_failure_is_retried_then_committed(monkeypatch):
    _retry_settings(monkeypatch, attempts=3)
    worker = _worker()
    worker._process_message = AsyncMock(  # noqa: SLF001
        side_effect=[RetryableProcessingError("db unavailable"), None]
    )

    before = worker.get_metrics()["retried"]
    assert await worker._handle_message(_msg()) is True  # noqa: SLF001
    assert worker._process_message.await_count == 2  # noqa: SLF001
    assert worker.get_metrics()["retried"] == before + 1


@pytest.mark.asyncio
async def test_retry_exhaustion_captures_before_allowing_commit(monkeypatch):
    _retry_settings(monkeypatch, attempts=2)
    dlq = InMemoryDLQ()
    worker = _worker(dlq)
    worker._process_message = AsyncMock(  # noqa: SLF001
        side_effect=RetryableProcessingError("postgres still down")
    )

    before = worker.get_metrics()["retry_exhausted"]
    assert await worker._handle_message(_msg(offset=17)) is True  # noqa: SLF001
    assert worker._process_message.await_count == 3  # initial + 2 retries  # noqa: SLF001
    assert worker.get_metrics()["retry_exhausted"] == before + 1
    assert len(dlq.records) == 1
    assert dlq.records[0].offset == 17
    assert "transient processing failure" in dlq.records[0].reason


@pytest.mark.asyncio
async def test_permanent_failure_is_captured_without_retrying(monkeypatch):
    _retry_settings(monkeypatch, attempts=5)
    dlq = InMemoryDLQ()
    worker = _worker(dlq)
    worker._process_message = AsyncMock(  # noqa: SLF001
        side_effect=PermanentProcessingError("unknown tenant")
    )

    assert await worker._handle_message(_msg()) is True  # noqa: SLF001
    assert worker._process_message.await_count == 1  # noqa: SLF001
    assert len(dlq.records) == 1
    assert "permanent processing failure" in dlq.records[0].reason


def test_log_only_capture_is_not_reported_as_durable():
    """The default sink is a log line, and the worker must say so.

    ``durable_capture`` is the runtime half of the documented persistence-free
    mode: a committed offset is only evidence of survival when the DLQ is
    storage. The default and an explicitly-injected ``LoggingDLQ`` both report
    false rather than inheriting a claim from the retry machinery.
    """
    for worker in (_worker(), _worker(LoggingDLQ())):
        assert worker.durable_capture is False
        assert worker.get_metrics()["durable_capture"] == 0


def test_a_storage_backed_dlq_reports_durable_capture():
    worker = _worker(PostgresDLQ(lambda: None))
    assert worker.durable_capture is True
    assert worker.get_metrics()["durable_capture"] == 1


@pytest.mark.asyncio
async def test_persistence_free_mode_commits_a_log_only_capture(monkeypatch):
    """The configured exception to the durability invariant, pinned.

    With the default ``LoggingDLQ`` there is nowhere durable to capture to, so
    a successful "capture" is a structured log line and the offset commits.
    The worker still retries and dead-letters, but this mode must not be
    described as loss-proof: ``durable_capture`` is false and ``main.py``
    warns. If the default ever becomes storage-backed, this test is the signal
    that the documented mode changed.
    """
    _retry_settings(monkeypatch, attempts=0)
    worker = _worker()
    worker._process_message = AsyncMock(  # noqa: SLF001
        side_effect=PermanentProcessingError("unknown tenant")
    )
    consumer = _FakeConsumer([_msg(0)])
    worker._consumer = consumer  # noqa: SLF001

    await worker._consume_loop()  # noqa: SLF001

    assert worker.durable_capture is False
    assert len(consumer.commits) == 1
    assert worker.get_metrics()["dead_lettered"] >= 1


@pytest.mark.asyncio
async def test_unhandled_exception_is_captured_not_committed(monkeypatch):
    _retry_settings(monkeypatch, attempts=5)
    dlq = InMemoryDLQ()
    worker = _worker(dlq)
    worker._process_message = AsyncMock(side_effect=RuntimeError("bug in the engine"))  # noqa: SLF001

    assert await worker._handle_message(_msg()) is True  # noqa: SLF001
    assert len(dlq.records) == 1
    assert "unhandled processing error" in dlq.records[0].reason


@pytest.mark.asyncio
async def test_failed_dlq_holds_the_message_without_acknowledging(monkeypatch):
    """When the store and the DLQ are both down, the message is not committed."""

    class ExplodingDLQ:
        async def record(self, dead_letter):  # noqa: ANN001, ARG002
            raise RuntimeError("dlq also down")

    _retry_settings(monkeypatch, attempts=0)
    worker = _worker(ExplodingDLQ())
    worker._process_message = AsyncMock(  # noqa: SLF001
        side_effect=RetryableProcessingError("postgres down")
    )

    task = asyncio.create_task(worker._handle_message(_msg()))  # noqa: SLF001
    await asyncio.sleep(0.05)
    assert not task.done(), "a message with no durable home must not be acknowledged"

    worker._running = False  # noqa: SLF001 — shutdown must break the hold
    worker._stop_event.set()  # noqa: SLF001
    assert await asyncio.wait_for(task, timeout=1.0) is False
    assert worker.get_metrics()["recovery_holds"] >= 1


@pytest.mark.asyncio
async def test_a_dlq_that_reports_failure_holds_the_message_without_acknowledging(monkeypatch):
    """``PostgresDLQ`` does not raise when its pool is down; it returns False.

    Reporting that as success would commit an offset for a message that now
    exists nowhere durable. The consumer must treat an explicit False as a
    failed capture and hold the offset, exactly as it does for an exception.
    """

    class FailingDLQ:
        async def record(self, dead_letter):  # noqa: ANN001, ARG002
            return False

    _retry_settings(monkeypatch, attempts=0)
    worker = _worker(FailingDLQ())
    worker._process_message = AsyncMock(  # noqa: SLF001
        side_effect=RetryableProcessingError("postgres down")
    )

    task = asyncio.create_task(worker._handle_message(_msg()))  # noqa: SLF001
    await asyncio.sleep(0.05)
    assert not task.done(), "a False capture must not be mistaken for a durable one"

    worker._running = False  # noqa: SLF001
    worker._stop_event.set()  # noqa: SLF001
    assert await asyncio.wait_for(task, timeout=1.0) is False
    assert worker.get_metrics()["recovery_holds"] >= 1


def test_a_non_json_record_becomes_a_capture_instead_of_an_iterator_crash():
    """aiokafka applies the deserializer inside the fetch.

    An exception there escapes the ``async for`` and stops consumption, so one
    malformed byte string would halt fusion. The value must become something the
    normal dead-letter path can carry.
    """
    value = _decode_record_value(b"\xffnot json")
    assert isinstance(value, _UnparseableRecord)
    assert "not json" in value.text


def test_the_real_aiokafka_deserializer_boundary_does_not_raise():
    """Exercise aiokafka's own record construction, not just our helper.

    ``PartitionRecords._consumer_record`` is where aiokafka applies
    ``value_deserializer`` while unpacking a fetch. Proving the helper is
    correct is not enough: a raw ``json.loads`` raises *here*, before the
    consume loop can see the record, and that exception ends the iterator.
    """
    fetcher = pytest.importorskip("aiokafka.consumer.fetcher")
    build_record = getattr(fetcher.PartitionRecords, "_consumer_record", None)
    if build_record is None:  # pragma: no cover — future aiokafka layout
        pytest.skip("aiokafka no longer exposes PartitionRecords._consumer_record")

    record = SimpleNamespace(
        key=None,
        value=b"\xffnot json",
        offset=9,
        timestamp=0,
        timestamp_type=0,
        checksum=0,
        headers=[],
    )
    holder = SimpleNamespace(_key_deserializer=None, _value_deserializer=_decode_record_value)

    out = build_record(holder, TopicPartition(settings.kafka_topic_raw_events, 2), record)
    assert isinstance(out.value, _UnparseableRecord)
    assert (out.partition, out.offset) == (2, 9)

    # Negative control: the same boundary with the obvious deserializer raises.
    holder._value_deserializer = lambda raw: json.loads(raw.decode("utf-8"))
    with pytest.raises(UnicodeDecodeError):
        build_record(holder, TopicPartition(settings.kafka_topic_raw_events, 2), record)


@pytest.mark.asyncio
async def test_a_non_json_record_is_dead_lettered_with_its_offset(monkeypatch):
    _retry_settings(monkeypatch, attempts=0)
    dlq = InMemoryDLQ()
    worker = _worker(dlq)
    msg = SimpleNamespace(
        value=_UnparseableRecord(b"{bad json"),
        topic=settings.kafka_topic_raw_events,
        partition=0,
        offset=5,
    )

    assert await worker._handle_message(msg) is True  # noqa: SLF001
    assert len(dlq.records) == 1
    assert dlq.records[0].offset == 5
    assert "not valid JSON" in dlq.records[0].reason


@pytest.mark.asyncio
async def test_a_hold_ends_when_the_dlq_recovers_without_a_restart(monkeypatch):
    """The hold is a retry loop, not a terminal state.

    Once the DLQ can write again the same in-flight message is captured and its
    offset may commit — no process restart required.
    """

    class FlakyDLQ:
        def __init__(self) -> None:
            self.calls = 0

        async def record(self, dead_letter):  # noqa: ANN001, ARG002
            self.calls += 1
            return self.calls >= 3

    _retry_settings(monkeypatch, attempts=0)
    dlq = FlakyDLQ()
    worker = _worker(dlq)
    worker._process_message = AsyncMock(  # noqa: SLF001
        side_effect=RetryableProcessingError("postgres down")
    )

    assert await asyncio.wait_for(worker._handle_message(_msg()), timeout=2.0) is True  # noqa: SLF001
    assert dlq.calls == 3
    assert worker.get_metrics()["recovery_holds"] >= 2


class _FakeConsumer:
    def __init__(self, messages):
        self._messages = list(messages)
        self.commits: list[dict] = []
        self.stopped = False

    def __aiter__(self):  # noqa: ANN204
        return self

    async def __anext__(self):  # noqa: ANN204
        if not self._messages:
            raise StopAsyncIteration
        return self._messages.pop(0)

    async def commit(self, offsets=None):  # noqa: ANN001, ANN201
        self.commits.append(offsets)

    async def stop(self):  # noqa: ANN201
        self.stopped = True


@pytest.mark.asyncio
async def test_consume_loop_commits_only_after_success():
    worker = _worker()
    consumer = _FakeConsumer([_msg(0)])
    worker._consumer = consumer  # noqa: SLF001
    worker._handle_message = AsyncMock(return_value=True)  # noqa: SLF001

    await worker._consume_loop()  # noqa: SLF001
    assert len(consumer.commits) == 1
    # The *next* offset for this partition only. A bare commit() acknowledges
    # every fetched partition and can skip records another partition has not
    # handed to the worker yet.
    assert consumer.commits[0] == {TopicPartition(settings.kafka_topic_raw_events, 0): 1}
    assert worker._loop_done.is_set()  # noqa: SLF001


@pytest.mark.asyncio
async def test_consume_loop_does_not_commit_a_failed_message():
    """The exact old defect: process fails, then the next commit skips it."""
    worker = _worker()
    consumer = _FakeConsumer([_msg(0), _msg(1)])
    worker._consumer = consumer  # noqa: SLF001
    worker._handle_message = AsyncMock(return_value=False)  # noqa: SLF001

    await worker._consume_loop()  # noqa: SLF001
    assert consumer.commits == []
    assert worker._attached is False  # noqa: SLF001
    assert worker._loop_done.is_set()  # noqa: SLF001


@pytest.mark.asyncio
async def test_stop_waits_for_the_in_flight_message_before_closing_clients():
    """Shutdown must not close Kafka underneath a message being persisted."""
    worker = _worker()
    consumer = _FakeConsumer([])
    worker._consumer = consumer  # noqa: SLF001
    worker._loop_done.clear()  # noqa: SLF001 — pretend the loop is in a message
    worker._inflight = 1  # noqa: SLF001

    async def finish_message():  # noqa: ANN202
        await asyncio.sleep(0.05)
        worker._loop_done.set()  # noqa: SLF001

    finish = asyncio.create_task(finish_message())
    started = asyncio.get_running_loop().time()
    await worker.stop()
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed >= 0.04, "stop() closed the clients before the message finished"
    assert consumer.stopped is True
    assert worker._running is False  # noqa: SLF001
    assert worker._stop_event.is_set()  # noqa: SLF001
    await finish


@pytest.mark.asyncio
async def test_stop_is_bounded_when_a_message_never_finishes(monkeypatch):
    """The grace period is finite; the offset is simply left uncommitted."""
    monkeypatch.setattr(settings, "shutdown_grace_seconds", 0.05)
    worker = _worker()
    consumer = _FakeConsumer([])
    worker._consumer = consumer  # noqa: SLF001
    worker._loop_done.clear()  # noqa: SLF001
    worker._inflight = 1  # noqa: SLF001

    started = asyncio.get_running_loop().time()
    await worker.stop()
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed < 1.0
    assert consumer.stopped is True


@pytest.mark.asyncio
async def test_stop_does_not_wait_out_the_grace_period_when_idle(monkeypatch):
    """An idle consume loop is blocked on Kafka; closing it is the wakeup."""
    monkeypatch.setattr(settings, "shutdown_grace_seconds", 5.0)
    worker = _worker()
    consumer = _FakeConsumer([])
    worker._consumer = consumer  # noqa: SLF001
    worker._loop_done.clear()  # noqa: SLF001 — loop is waiting for a record
    worker._inflight = 0  # noqa: SLF001

    started = asyncio.get_running_loop().time()
    await worker.stop()
    elapsed = asyncio.get_running_loop().time() - started

    assert elapsed < 1.0
    assert consumer.stopped is True


@pytest.mark.asyncio
async def test_inflight_stays_positive_through_commit_and_lake_flush():
    """Shutdown decides whether to wait by reading ``_inflight``.

    Decrementing it before the commit (or the lake flush) lets ``stop()`` see an
    idle worker and close Kafka underneath an acknowledgement that is still in
    flight. The counter must stay positive until both have finished.
    """
    worker = _worker()
    observed: dict[str, int] = {}

    class _ObservingConsumer(_FakeConsumer):
        async def commit(self, offsets=None):  # noqa: ANN001, ANN201
            observed["commit"] = worker._inflight  # noqa: SLF001
            await super().commit(offsets)

    class _ObservingLake:
        async def flush_if_stale(self) -> None:
            observed["lake"] = worker._inflight  # noqa: SLF001

    consumer = _ObservingConsumer([_msg(0)])
    worker._consumer = consumer  # noqa: SLF001
    worker._lake = _ObservingLake()  # type: ignore[assignment]  # noqa: SLF001
    worker._handle_message = AsyncMock(return_value=True)  # noqa: SLF001

    await worker._consume_loop()  # noqa: SLF001

    assert observed == {"commit": 1, "lake": 1}
    assert worker._inflight == 0  # noqa: SLF001


def test_retry_backoff_is_bounded_and_jittered(monkeypatch):
    monkeypatch.setattr(settings, "consumer_retry_base_seconds", 0.5)
    monkeypatch.setattr(settings, "consumer_retry_max_seconds", 30.0)
    worker = _worker()

    first = worker._retry_delay(1)  # noqa: SLF001
    assert 0.25 <= first <= 0.5
    # The exponential window is capped; no attempt can sleep past the cap.
    assert all(0.0 < worker._retry_delay(n) <= 30.0 for n in range(1, 40))  # noqa: SLF001
    assert worker._retry_delay(30) >= 15.0  # noqa: SLF001 — capped window, still jittered


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


@pytest.mark.asyncio
async def test_unavailable_persist_raises_retryable_and_does_not_publish():
    alert = _alert()
    fused = _fused(alert)
    worker = FusionWorker(engine=SimpleNamespace(process=AsyncMock(return_value=fused)), sink=AsyncMock())
    worker._sink.persist = AsyncMock(  # noqa: SLF001
        return_value=PersistResult(PersistOutcome.UNAVAILABLE, str(fused.id), retryable=True)
    )
    worker._producer = AsyncMock()  # noqa: SLF001

    with pytest.raises(RetryableProcessingError):
        await worker._fuse_and_persist(alert)  # noqa: SLF001
    worker._producer.send.assert_not_awaited()  # noqa: SLF001


@pytest.mark.asyncio
async def test_permanent_persist_failure_raises_permanent():
    alert = _alert()
    fused = _fused(alert)
    worker = FusionWorker(engine=SimpleNamespace(process=AsyncMock(return_value=fused)), sink=AsyncMock())
    worker._sink.persist = AsyncMock(  # noqa: SLF001
        return_value=PersistResult(PersistOutcome.FAILED, None, retryable=False)
    )
    worker._producer = AsyncMock()  # noqa: SLF001

    with pytest.raises(PermanentProcessingError):
        await worker._fuse_and_persist(alert)  # noqa: SLF001
    worker._producer.send.assert_not_awaited()  # noqa: SLF001


@pytest.mark.asyncio
async def test_publish_failure_after_a_durable_row_is_retryable():
    """The row exists; the notification does not. Re-delivery republishes it."""
    alert = _alert()
    fused = _fused(alert)
    worker = FusionWorker(engine=SimpleNamespace(process=AsyncMock(return_value=fused)), sink=AsyncMock())
    worker._sink.persist = AsyncMock(  # noqa: SLF001
        return_value=PersistResult(PersistOutcome.INSERTED, str(fused.id))
    )
    worker._producer = AsyncMock()  # noqa: SLF001
    worker._producer.send.side_effect = RuntimeError("kafka down")  # noqa: SLF001

    with pytest.raises(RetryableProcessingError):
        await worker._fuse_and_persist(alert)  # noqa: SLF001
    assert worker.get_metrics()["publish_failed"] >= 1


@pytest.mark.asyncio
async def test_alert_sink_duplicate_reconciliation_is_used_by_the_worker():
    """End-to-end at the worker boundary: DUPLICATE must verify the row.

    A sink double is used here; the SQL path itself is covered by
    test_alert_sink.py and the live integration job.
    """
    alert = _alert()
    fused = _fused(alert)
    sink = AlertSink.__new__(AlertSink)

    async def verify(_fused):  # noqa: ANN001, ANN202
        return PersistResult(PersistOutcome.DUPLICATE, str(fused.id), verified=False, retryable=True)

    sink.persist = verify  # type: ignore[method-assign]
    worker = FusionWorker(engine=SimpleNamespace(process=AsyncMock(return_value=fused)), sink=sink)
    worker._producer = AsyncMock()  # noqa: SLF001

    with pytest.raises(RetryableProcessingError):
        await worker._fuse_and_persist(alert)  # noqa: SLF001
    worker._producer.send.assert_not_awaited()  # noqa: SLF001
