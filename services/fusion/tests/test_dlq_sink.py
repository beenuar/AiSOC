"""A dead-letter queue that can be read, and that cannot stop the pipeline.

Three DLQ implementations existed and none could answer the question a DLQ
exists for. One wrote a log line, one wrote to a Kafka topic with no
consumer, one forgot on restart. Events were dropped correctly and
invisibly — and an invisible drop is indistinguishable from an event that
never arrived, which is the worse possibility and the one nobody
investigates.

The tests are mostly about the failure paths, because that is where a DLQ
earns its place: recording a dropped event must never become a second way
for one bad message to halt consumption.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.dlq import DeadLetter
from app.services.dlq_sink import MAX_EXCERPT, PostgresDLQ, _as_uuid


def _pool(execute: AsyncMock | None = None) -> MagicMock:
    conn = AsyncMock()
    conn.execute = execute or AsyncMock()
    pool = MagicMock()
    acquire = MagicMock()
    acquire.__aenter__ = AsyncMock(return_value=conn)
    acquire.__aexit__ = AsyncMock(return_value=False)
    pool.acquire = MagicMock(return_value=acquire)
    pool._conn = conn
    return pool


def _letter(**overrides) -> DeadLetter:
    base = {
        "topic": "aisoc.raw_events",
        "reason": "schema_validation_failed",
        "schema_version": "v1",
        "payload_excerpt": '{"bad": true}',
        "source_event_id": "evt-1",
        "tenant_id": str(uuid.uuid4()),
    }
    base.update(overrides)
    return DeadLetter(**base)


class TestRecording:
    @pytest.mark.asyncio
    async def test_writes_the_letter(self) -> None:
        pool = _pool()
        await PostgresDLQ(lambda: pool).record(_letter())
        pool._conn.execute.assert_awaited_once()
        args = pool._conn.execute.await_args.args
        assert "aisoc_dead_letters" in args[0]
        assert args[2] == "aisoc.raw_events"
        assert args[3] == "schema_validation_failed"

    @pytest.mark.asyncio
    async def test_the_payload_is_truncated(self) -> None:
        """The payload is untrusted by definition — it is the thing the
        pipeline refused — so storing all of it makes this table an
        unbounded sink for exactly the content that was rejected."""
        pool = _pool()
        await PostgresDLQ(lambda: pool).record(_letter(payload_excerpt="x" * 100_000))
        excerpt = pool._conn.execute.await_args.args[5]
        assert len(excerpt) == MAX_EXCERPT

    @pytest.mark.asyncio
    async def test_no_pool_yet_is_logged_not_crashed(self) -> None:
        """The pool opens during worker startup, after the DLQ is built.
        A dead letter arriving in that window must not raise."""
        await PostgresDLQ(lambda: None).record(_letter())

    @pytest.mark.asyncio
    async def test_a_callable_pool_is_resolved_at_record_time(self) -> None:
        """Resolving eagerly would capture None and silently drop every
        dead letter — the exact failure this class exists to end."""
        pool = _pool()
        holder: list = [None]
        sink = PostgresDLQ(lambda: holder[0])
        holder[0] = pool
        await sink.record(_letter())
        pool._conn.execute.assert_awaited_once()


class TestItCannotStopThePipeline:
    @pytest.mark.asyncio
    async def test_a_database_failure_is_swallowed(self) -> None:
        """The whole point of routing a poison message aside is to keep
        consuming. If recording that decision can raise, the DLQ becomes a
        second way for one bad event to halt everything."""
        pool = _pool(AsyncMock(side_effect=RuntimeError("connection refused")))
        await PostgresDLQ(lambda: pool).record(_letter())  # must not raise

    @pytest.mark.asyncio
    async def test_an_unacquirable_pool_is_swallowed(self) -> None:
        pool = MagicMock()
        pool.acquire = MagicMock(side_effect=RuntimeError("pool exhausted"))
        await PostgresDLQ(lambda: pool).record(_letter())  # must not raise


class TestTenantParsing:
    @pytest.mark.parametrize("bad", ["", None, "not-a-uuid", "12345", "default"])
    def test_a_malformed_tenant_becomes_null_rather_than_losing_the_record(self, bad: str | None) -> None:
        """A malformed envelope can carry a tenant field that is not a
        uuid. Rejecting the record over it would lose the dead letter —
        and the dead letter is the evidence that something is producing
        malformed envelopes."""
        assert _as_uuid(bad) is None

    def test_a_valid_tenant_is_preserved(self) -> None:
        tid = uuid.uuid4()
        assert _as_uuid(str(tid)) == tid

    @pytest.mark.asyncio
    async def test_a_letter_with_no_tenant_is_still_recorded(self) -> None:
        """A message can be rejected before its tenant is known. Recording
        a guess would put another tenant's name on someone else's bad
        data."""
        pool = _pool()
        await PostgresDLQ(lambda: pool).record(_letter(tenant_id=None))
        assert pool._conn.execute.await_args.args[1] is None


def test_it_implements_the_queue_interface() -> None:
    """So it can be swapped in wherever the consumer builds its DLQ,
    rather than becoming a fourth implementation nothing uses."""
    from app.services.dlq import DeadLetterQueue

    assert issubclass(PostgresDLQ, DeadLetterQueue)
