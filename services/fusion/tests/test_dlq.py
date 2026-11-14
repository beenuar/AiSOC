"""Phase 5 — dead-letter queue tests."""

from __future__ import annotations

import pytest
from app.services.dlq import DeadLetter, InMemoryDLQ, KafkaDLQ, LoggingDLQ, safe_record


def test_dead_letter_build_truncates_payload_and_keeps_lineage():
    huge = {"blob": "x" * 10000, "n": 1}
    dl = DeadLetter.build(
        topic="aisoc.raw_events",
        reason="test",
        schema_version="v1",
        payload=huge,
        source_event_id="ev-9",
        tenant_id="t-1",
    )
    assert len(dl.payload_excerpt) <= 4000
    assert dl.source_event_id == "ev-9"
    assert dl.tenant_id == "t-1"
    assert dl.ts  # timestamped


def test_dead_letter_build_handles_unserialisable_payload():
    dl = DeadLetter.build(topic="t", reason="r", schema_version="v1", payload=object())
    assert dl.payload_excerpt  # falls back to str(), never raises


@pytest.mark.asyncio
async def test_in_memory_dlq_records():
    dlq = InMemoryDLQ()
    dl = DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={"a": 1})
    ok = await safe_record(dlq, dl)
    assert ok
    assert len(dlq.records) == 1
    assert dlq.records[0].reason == "r"


@pytest.mark.asyncio
async def test_safe_record_is_none_safe():
    assert await safe_record(None, DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={})) is False


@pytest.mark.asyncio
async def test_safe_record_swallows_sink_failure():
    class ExplodingDLQ:
        async def record(self, dead_letter):  # noqa: ANN001, ARG002
            raise RuntimeError("kafka down")

    # A DLQ that itself fails must never propagate — one poison message can't
    # be allowed to crash the consumer.
    ok = await safe_record(ExplodingDLQ(), DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={}))
    assert ok is False


@pytest.mark.asyncio
async def test_safe_record_reports_an_explicit_capture_failure():
    """A sink that cannot persist (notably PostgresDLQ with no pool) returns
    False instead of raising. Reporting that as success would let the consumer
    commit an offset for a message that exists nowhere durable."""

    class FailingDLQ:
        async def record(self, dead_letter):  # noqa: ANN001, ARG002
            return False

    ok = await safe_record(FailingDLQ(), DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={}))
    assert ok is False


@pytest.mark.asyncio
async def test_safe_record_accepts_a_legacy_none_returning_sink():
    """The original protocol returned None. Such a sink raises on failure, so
    None still means the record was accepted."""

    class LegacyDLQ:
        async def record(self, dead_letter):  # noqa: ANN001, ARG002
            return None

    ok = await safe_record(LegacyDLQ(), DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={}))
    assert ok is True


@pytest.mark.asyncio
async def test_logging_dlq_does_not_raise():
    ok = await LoggingDLQ().record(DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={"x": 1}))
    assert ok is True


def test_only_storage_backed_dlqs_claim_durable_capture():
    """A successful ``record`` is not automatically a durable capture.

    The consumer commits an offset after a successful capture. That is only
    safe if the capture outlives the process: a log line and an in-memory list
    do not, and neither does a broker send without an acknowledgement. The flag
    is what lets the worker report the persistence-free mode instead of
    silently implying the invariant holds.
    """
    assert LoggingDLQ.durable is False
    assert InMemoryDLQ.durable is False
    assert KafkaDLQ.durable is True


class _AckFuture:
    """What ``AIOKafkaProducer.send`` returns: a future, not the write."""

    def __init__(self, *, fail: bool = False) -> None:
        self.awaited = False
        self._fail = fail

    def __await__(self):  # noqa: ANN204
        async def _wait() -> None:
            self.awaited = True
            if self._fail:
                raise RuntimeError("broker rejected the write")

        return _wait().__await__()


class _Producer:
    def __init__(self, future: _AckFuture) -> None:
        self.future = future
        self.sent: list[tuple[str, dict]] = []

    async def send(self, topic, *, value):  # noqa: ANN001, ANN201
        self.sent.append((topic, value))
        return self.future


@pytest.mark.asyncio
async def test_kafka_dlq_waits_for_the_broker_acknowledgement():
    """``send`` only enqueues; the future is the acknowledgement.

    Returning True without awaiting it would let the consumer commit an offset
    for a dead letter that a later producer failure can still lose.
    """
    future = _AckFuture()
    producer = _Producer(future)

    ok = await KafkaDLQ(producer).record(DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={}))

    assert ok is True
    assert producer.sent[0][0] == "aisoc.alerts.dlq"
    assert future.awaited is True


@pytest.mark.asyncio
async def test_kafka_dlq_reports_a_failed_acknowledgement_as_a_failed_capture():
    future = _AckFuture(fail=True)
    producer = _Producer(future)

    ok = await safe_record(KafkaDLQ(producer), DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={}))

    assert ok is False
    assert future.awaited is True


@pytest.mark.asyncio
async def test_kafka_dlq_does_not_accept_a_send_without_an_acknowledgement():
    """A producer that returns no future is not evidence of a durable write."""

    class _NoAckProducer:
        async def send(self, topic, *, value):  # noqa: ANN001, ANN201, ARG002
            return None

    ok = await safe_record(KafkaDLQ(_NoAckProducer()), DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={}))

    assert ok is False


@pytest.mark.asyncio
async def test_a_sink_without_the_flag_defaults_to_not_durable():
    """Older/custom sinks cannot inherit durability by omission."""

    class CustomSink:
        async def record(self, dead_letter):  # noqa: ANN001, ARG002
            return True

    assert getattr(CustomSink(), "durable", False) is False


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
