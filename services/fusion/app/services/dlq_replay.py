"""Replay refused messages from a Kafka offset, once the cause is fixed (5b).

Phase 5 gave the pipeline somewhere to put a message it could not process.
It did not give an operator a way to get one back. ``GET
/api/v1/health/dead-letters`` reports the backlog and nothing consumed it,
which makes the dead-letter queue an audit trail rather than a recovery
mechanism.

The obvious implementation is the dangerous one
-----------------------------------------------
"Re-send the dead letters" fails twice over.

It cannot work. ``aisoc_dead_letters`` stores a 2,000-character excerpt, and
that truncation is deliberate: the payload is the thing the pipeline refused,
so it is untrusted by definition and may be large or hostile. The row is a
triage record. The faithful copy is in Kafka, and this reads it from there.

And it should not work like that anyway. Replaying a poison batch into the
same consumer that rejected it reproduces the outage that filled the queue in
the first place. So the safety property here is not a bound or a permission —
those matter and are below — it is this:

    **A message is re-validated before it is produced, by the same validator
    that refused it, and one that still fails is refused again rather than
    replayed.**

That turns "the operator believes they fixed the cause" into something the
machine checks. If the fix did not land, the replay produces nothing and says
how many would still fail. The failure mode it removes is the one where a
confident operator re-injects a thousand messages at 3am and takes the
consumer down a second time.

Four properties, stated because each was a decision
----------------------------------------------------
**Deliberate.** The caller names ``(topic, partition, start_offset)``. There
is no "replay the backlog" and no offset inferred from a row, because a range
somebody chose is a range somebody is accountable for.

**Bounded.** ``max_messages`` is capped at :data:`MAX_REPLAY_MESSAGES` here,
by a CHECK constraint in migration 075, and by the API's own validation. A
read that finds nothing at the offset stops rather than waiting, so a typo'd
offset returns an empty preview instead of hanging.

**Authorised and observable** are the API's half, not this module's: the
operator door carries the permission, stamps the actor and writes the
``aisoc_dlq_replays`` row. This function is the execution, and returns
everything that row needs.

**Dry run is the default** everywhere above this function. ``execute=False``
reads and validates and produces nothing, so the normal way to use this is to
find out what would happen.

Where a replayed message goes
-----------------------------
Back to the topic it came from, so it takes the ordinary path through the
ordinary consumer — nothing about the processing is special-cased for a
replay. That is safe to do twice because ``RawAlert.deterministic_id()`` is
replay-stable and ``alert_sink`` is ``ON CONFLICT (id) DO NOTHING``; the
ClickHouse lake is the known exception and can gain a duplicate row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import structlog

from app.core.config import settings
from app.core.kafka_security import kafka_client_kwargs
from app.services.event_schema import validate_event

logger = structlog.get_logger()

#: Hard ceiling on one replay. Mirrored by a CHECK constraint in migration
#: 075 and by the API's request validation — three layers, because the one
#: that matters is whichever the caller reaches first, and a bound that lives
#: only in a request model is a bound a service-to-service caller skips.
MAX_REPLAY_MESSAGES = 1000

#: How long to wait for messages at the offset before concluding there are
#: none. A replay that blocks forever on an offset past the end of the log is
#: indistinguishable from a slow broker, and an operator cannot tell which.
READ_TIMEOUT_MS = 5_000


@dataclass
class ReplayOutcome:
    """What a replay read, refused and produced."""

    topic: str
    partition: int
    start_offset: int
    max_messages: int
    executed: bool

    messages_read: int = 0
    would_pass: int = 0
    refused: int = 0
    produced: int = 0

    #: Why each refused message was refused, deduplicated with a count. The
    #: list of offsets is a list; "forty-eight still fail schema validation
    #: on the same reason" is a finding.
    refusals: dict[str, int] = field(default_factory=dict)
    #: Offsets actually produced, so the action is reconstructable.
    produced_offsets: list[int] = field(default_factory=list)
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "topic": self.topic,
            "partition": self.partition,
            "start_offset": self.start_offset,
            "max_messages": self.max_messages,
            "executed": self.executed,
            "messages_read": self.messages_read,
            "would_pass": self.would_pass,
            "refused": self.refused,
            "produced": self.produced,
            "refusals": dict(sorted(self.refusals.items(), key=lambda kv: -kv[1])),
            "produced_offsets": self.produced_offsets,
            "error": self.error,
        }


class ReplayRefused(ValueError):
    """The request itself is not one this service will attempt."""


def _validate_request(topic: str, partition: int, start_offset: int, max_messages: int) -> None:
    if not topic:
        raise ReplayRefused("topic is required; a replay names the topic it reads from")
    if partition < 0:
        raise ReplayRefused(f"partition must be >= 0, got {partition}")
    if start_offset < 0:
        raise ReplayRefused(f"start_offset must be >= 0, got {start_offset}")
    if max_messages < 1 or max_messages > MAX_REPLAY_MESSAGES:
        raise ReplayRefused(f"max_messages must be between 1 and {MAX_REPLAY_MESSAGES}, got {max_messages}")
    known = {settings.kafka_topic_raw_events, settings.kafka_topic_alerts_raw}
    if topic not in known:
        # Not a permissions check — a shape check. This service can only
        # re-validate a topic whose schema it knows, and producing to one it
        # cannot validate would skip the property the whole module is for.
        raise ReplayRefused(
            f"'{topic}' is not a topic this service validates ({', '.join(sorted(known))}), so a replay of it could not be re-checked"
        )


def classify(payload: Any, topic: str) -> tuple[bool, str]:
    """Would this message pass the validation that refused it? With the reason."""
    result = validate_event(
        topic,
        payload,
        raw_events_topic=settings.kafka_topic_raw_events,
        alerts_raw_topic=settings.kafka_topic_alerts_raw,
    )
    return result.ok, result.reason


async def replay_from_offset(
    *,
    topic: str,
    partition: int,
    start_offset: int,
    max_messages: int,
    execute: bool = False,
    consumer_factory: Any = None,
    producer_factory: Any = None,
) -> ReplayOutcome:
    """Read a bounded range, re-validate it, and produce only what now passes.

    ``execute=False`` is a true dry run: the producer is never constructed,
    so a preview cannot re-inject anything even if the code below is wrong.

    The factories exist for the tests, which drive the whole path without a
    broker. Production passes neither.
    """
    _validate_request(topic, partition, start_offset, max_messages)
    outcome = ReplayOutcome(
        topic=topic,
        partition=partition,
        start_offset=start_offset,
        max_messages=max_messages,
        executed=execute,
    )

    consumer = await _build_consumer(topic, partition, start_offset, consumer_factory)
    producer = await _build_producer(producer_factory) if execute else None

    try:
        batches = await consumer.getmany(timeout_ms=READ_TIMEOUT_MS, max_records=max_messages)
        records = [record for partition_records in batches.values() for record in partition_records]
        records.sort(key=lambda r: r.offset)

        for record in records[:max_messages]:
            outcome.messages_read += 1
            ok, reason = classify(record.value, topic)
            if not ok:
                # The safety property. The cause is evidently not fixed for
                # this message, so it is refused a second time rather than
                # re-injected into the consumer that refused it first.
                outcome.refused += 1
                outcome.refusals[reason] = outcome.refusals.get(reason, 0) + 1
                continue

            outcome.would_pass += 1
            if producer is None:
                continue
            await producer.send_and_wait(topic, value=record.value)
            outcome.produced += 1
            outcome.produced_offsets.append(record.offset)

        logger.info(
            "dlq_replay.completed",
            topic=topic,
            partition=partition,
            start_offset=start_offset,
            executed=execute,
            read=outcome.messages_read,
            would_pass=outcome.would_pass,
            refused=outcome.refused,
            produced=outcome.produced,
        )
    finally:
        # Both are per-replay and must not outlive it: a leaked consumer keeps
        # a broker connection open for a one-shot read.
        for client in (consumer, producer):
            if client is not None:
                try:
                    await client.stop()
                except Exception as exc:  # noqa: BLE001 — teardown must not mask the outcome
                    logger.warning("dlq_replay.teardown_failed", error=str(exc))

    return outcome


async def _build_consumer(topic: str, partition: int, start_offset: int, factory: Any) -> Any:
    if factory is not None:
        return await factory(topic, partition, start_offset)

    # Imported here so the module is importable — and unit-testable through
    # the factories — in an environment with no Kafka client, which is how
    # the schema-validation half is exercised without a broker.
    from aiokafka import AIOKafkaConsumer, TopicPartition  # noqa: PLC0415

    consumer = AIOKafkaConsumer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        # No group_id, deliberately. A replay must not join the consumer
        # group it is repairing: joining triggers a rebalance on a pipeline
        # already in trouble, and committing offsets from a one-shot read
        # would move the live consumer's position.
        enable_auto_commit=False,
        value_deserializer=_decode,
        **kafka_client_kwargs(),
    )
    await consumer.start()
    target = TopicPartition(topic, partition)
    consumer.assign([target])
    consumer.seek(target, start_offset)
    return consumer


async def _build_producer(factory: Any) -> Any:
    if factory is not None:
        return await factory()

    from aiokafka import AIOKafkaProducer  # noqa: PLC0415

    producer = AIOKafkaProducer(
        bootstrap_servers=settings.kafka_bootstrap_servers,
        value_serializer=_encode,
        **kafka_client_kwargs(),
    )
    await producer.start()
    return producer


def _decode(raw: bytes) -> Any:
    import json  # noqa: PLC0415

    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        # Undecodable is a legitimate answer and must reach the validator as
        # one: it will refuse it, which is the correct outcome and is counted
        # as a refusal rather than crashing the whole replay on one message.
        return {"__undecodable__": True}


def _encode(value: Any) -> bytes:
    import json  # noqa: PLC0415

    return json.dumps(value).encode("utf-8")


__all__ = [
    "MAX_REPLAY_MESSAGES",
    "READ_TIMEOUT_MS",
    "ReplayOutcome",
    "ReplayRefused",
    "classify",
    "replay_from_offset",
]
