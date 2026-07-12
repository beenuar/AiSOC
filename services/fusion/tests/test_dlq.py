"""Phase 5 — dead-letter queue tests."""

from __future__ import annotations

import pytest
from app.services.dlq import DeadLetter, InMemoryDLQ, LoggingDLQ, safe_record


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
async def test_logging_dlq_does_not_raise():
    await LoggingDLQ().record(DeadLetter.build(topic="t", reason="r", schema_version="v1", payload={"x": 1}))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
