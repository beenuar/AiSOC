"""Replaying a refused message, and refusing to replay a poison one (5b).

The property under test is the one that makes this feature safe rather than
merely possible: a message is re-validated by the validator that refused it,
and one that still fails is refused again instead of being produced. A
replay that skips that check reproduces the outage that filled the queue.

Everything here drives the real `replay_from_offset` with fake broker
clients, so the validation path, the bounds, the ordering and the dry-run
guarantee are all exercised. The broker itself is proved separately, against
a live one.
"""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from app.services.dlq_replay import (
    MAX_REPLAY_MESSAGES,
    ReplayRefused,
    classify,
    replay_from_offset,
)

TOPIC = "aisoc.raw_events"


def _good(event_id: str = "e1") -> dict:
    """An envelope the schema registry accepts."""
    return {
        "schema_version": "v1",
        "tenant_id": str(uuid.uuid4()),
        "ocsf_event": {"class_uid": 2001, "metadata": {"uid": event_id}},
    }


def _poison_missing_ocsf() -> dict:
    return {"schema_version": "v1", "tenant_id": str(uuid.uuid4())}


def _poison_bad_tenant() -> dict:
    return {"schema_version": "v1", "tenant_id": "not-a-uuid", "ocsf_event": {"class_uid": 2001}}


class _FakeConsumer:
    """Serves a fixed set of records from an offset, like a seeked consumer."""

    def __init__(self, records: list[tuple[int, dict]]) -> None:
        self._records = records
        self.stopped = False

    async def getmany(self, *, timeout_ms: int, max_records: int) -> dict:
        batch = [SimpleNamespace(offset=offset, value=value) for offset, value in self._records[:max_records]]
        return {"tp": batch}

    async def stop(self) -> None:
        self.stopped = True


class _FakeProducer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict]] = []
        self.stopped = False

    async def send_and_wait(self, topic: str, *, value: dict) -> None:
        self.sent.append((topic, value))

    async def stop(self) -> None:
        self.stopped = True


def _factories(records: list[tuple[int, dict]]) -> tuple:
    consumer = _FakeConsumer(records)
    producer = _FakeProducer()

    async def consumer_factory(_topic: str, _partition: int, _offset: int):
        return consumer

    async def producer_factory():
        return producer

    return consumer, producer, consumer_factory, producer_factory


class TestThePoisonBatchIsRefusedASecondTime:
    """The whole point. If the cause is not fixed, nothing is produced."""

    @pytest.mark.asyncio
    async def test_a_message_that_still_fails_is_not_produced(self) -> None:
        _, producer, cf, pf = _factories([(10, _poison_missing_ocsf())])

        outcome = await replay_from_offset(
            topic=TOPIC,
            partition=0,
            start_offset=10,
            max_messages=10,
            execute=True,
            consumer_factory=cf,
            producer_factory=pf,
        )

        assert outcome.messages_read == 1
        assert outcome.refused == 1
        assert outcome.produced == 0
        assert producer.sent == []

    @pytest.mark.asyncio
    async def test_the_refusal_reason_is_reported_with_a_count(self) -> None:
        """A list of offsets is data; 'three failed for the same reason' is a finding."""
        records = [(1, _poison_missing_ocsf()), (2, _poison_missing_ocsf()), (3, _poison_bad_tenant())]
        _, _, cf, pf = _factories(records)

        outcome = await replay_from_offset(
            topic=TOPIC,
            partition=0,
            start_offset=1,
            max_messages=10,
            execute=True,
            consumer_factory=cf,
            producer_factory=pf,
        )

        assert outcome.refused == 3
        assert sum(outcome.refusals.values()) == 3
        assert len(outcome.refusals) == 2, outcome.refusals

    @pytest.mark.asyncio
    async def test_a_mixed_batch_produces_only_the_messages_that_now_pass(self) -> None:
        records = [(1, _good("a")), (2, _poison_missing_ocsf()), (3, _good("b"))]
        _, producer, cf, pf = _factories(records)

        outcome = await replay_from_offset(
            topic=TOPIC,
            partition=0,
            start_offset=1,
            max_messages=10,
            execute=True,
            consumer_factory=cf,
            producer_factory=pf,
        )

        assert (outcome.would_pass, outcome.refused, outcome.produced) == (2, 1, 2)
        assert outcome.produced_offsets == [1, 3]
        assert len(producer.sent) == 2

    def test_classify_agrees_with_the_validator_that_refused_it(self) -> None:
        assert classify(_good(), TOPIC)[0] is True
        ok, reason = classify(_poison_missing_ocsf(), TOPIC)
        assert ok is False
        assert "ocsf_event" in reason


class TestDryRunCannotProduce:
    @pytest.mark.asyncio
    async def test_a_dry_run_never_constructs_a_producer(self) -> None:
        """Not 'does not send' — does not exist.

        A preview that holds a live producer is one bug away from being a
        replay, so the guarantee is structural rather than conditional.
        """
        constructed = False

        async def producer_factory():
            nonlocal constructed
            constructed = True
            raise AssertionError("a dry run must not build a producer")

        consumer, _, cf, _ = _factories([(1, _good())])
        outcome = await replay_from_offset(
            topic=TOPIC,
            partition=0,
            start_offset=1,
            max_messages=10,
            execute=False,
            consumer_factory=cf,
            producer_factory=producer_factory,
        )

        assert constructed is False
        assert outcome.executed is False
        assert outcome.would_pass == 1
        assert outcome.produced == 0

    @pytest.mark.asyncio
    async def test_a_dry_run_still_reports_what_would_happen(self) -> None:
        records = [(1, _good("a")), (2, _poison_bad_tenant())]
        _, _, cf, _ = _factories(records)

        outcome = await replay_from_offset(topic=TOPIC, partition=0, start_offset=1, max_messages=10, execute=False, consumer_factory=cf)

        assert outcome.messages_read == 2
        assert outcome.would_pass == 1
        assert outcome.refused == 1


class TestItIsBounded:
    @pytest.mark.asyncio
    async def test_max_messages_caps_what_is_read(self) -> None:
        _, producer, cf, pf = _factories([(i, _good(str(i))) for i in range(50)])

        outcome = await replay_from_offset(
            topic=TOPIC,
            partition=0,
            start_offset=0,
            max_messages=5,
            execute=True,
            consumer_factory=cf,
            producer_factory=pf,
        )

        assert outcome.messages_read == 5
        assert len(producer.sent) == 5

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("kwargs", "fragment"),
        [
            ({"max_messages": 0}, "between 1 and"),
            ({"max_messages": MAX_REPLAY_MESSAGES + 1}, "between 1 and"),
            ({"partition": -1}, "partition must be"),
            ({"start_offset": -1}, "start_offset must be"),
            ({"topic": ""}, "topic is required"),
            ({"topic": "some.other.topic"}, "not a topic this service validates"),
        ],
    )
    async def test_an_unsafe_request_is_refused_before_any_broker_is_touched(self, kwargs: dict, fragment: str) -> None:
        base: dict = {"topic": TOPIC, "partition": 0, "start_offset": 0, "max_messages": 10}

        async def explode(*_args, **_kw):
            raise AssertionError("a refused request must not reach the broker")

        with pytest.raises(ReplayRefused) as excinfo:
            await replay_from_offset(**{**base, **kwargs}, execute=True, consumer_factory=explode, producer_factory=explode)

        assert fragment in str(excinfo.value)


class TestItCleansUpAndSurvivesBadInput:
    @pytest.mark.asyncio
    async def test_both_clients_are_stopped(self) -> None:
        consumer, producer, cf, pf = _factories([(1, _good())])

        await replay_from_offset(
            topic=TOPIC,
            partition=0,
            start_offset=1,
            max_messages=10,
            execute=True,
            consumer_factory=cf,
            producer_factory=pf,
        )

        assert consumer.stopped and producer.stopped

    @pytest.mark.asyncio
    async def test_an_undecodable_message_is_refused_rather_than_crashing_the_replay(self) -> None:
        """One bad message must not cost the other nine their replay."""
        records = [(1, {"__undecodable__": True}), (2, _good("b"))]
        _, producer, cf, pf = _factories(records)

        outcome = await replay_from_offset(
            topic=TOPIC,
            partition=0,
            start_offset=1,
            max_messages=10,
            execute=True,
            consumer_factory=cf,
            producer_factory=pf,
        )

        assert outcome.refused == 1
        assert outcome.produced == 1
