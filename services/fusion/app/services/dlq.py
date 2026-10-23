"""Dead-letter queue for the fusion consumer (Phase 5).

A poison message — malformed JSON shape, an unknown schema version, a non-UUID
tenant, or a RawAlert that fails deep validation — must not crash the consumer
and must not vanish. Before Phase 5 the consumer logged a warning and dropped
it (silent data loss the reality audit flagged). Now every such message is
routed here: captured with its reason, schema version, source-event lineage,
and a truncated copy of the payload, so an operator can see exactly what was
rejected and why.

Sinks are pluggable and **fail-soft** — a DLQ that itself throws must never
take down the consumer (that would turn a single poison message into an
outage). :func:`safe_record` wraps every sink call.

* :class:`LoggingDLQ` — default. Emits a structured ``fusion.dead_letter``
  warning. Always available, zero dependencies.
* :class:`InMemoryDLQ` — test double; keeps records in a list.
* :class:`KafkaDLQ` — production option that republishes to a dead-letter
  topic (``aisoc.alerts.dlq``) via the consumer's existing producer, so DLQ
  volume is observable on the same bus as everything else.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

import structlog

logger = structlog.get_logger()

# Cap the stored payload so a pathological megabyte message can't bloat the DLQ
# topic / log line. The reason + lineage are what an operator triages on.
_MAX_PAYLOAD_CHARS = 4000


@dataclass(frozen=True)
class DeadLetter:
    """One rejected message, with everything needed to triage it."""

    topic: str
    reason: str
    schema_version: str
    payload_excerpt: str
    source_event_id: str | None = None
    tenant_id: str | None = None
    #: Where the refused message actually lives. The excerpt above is a
    #: triage record and is truncated on purpose; these are how the faithful
    #: copy is found again for a replay (deferral 5b). Optional because a
    #: dead letter can be raised from a path that never saw a Kafka record.
    partition: int | None = None
    offset: int | None = None
    ts: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    @classmethod
    def build(
        cls,
        *,
        topic: str,
        reason: str,
        schema_version: str,
        payload: Any,
        source_event_id: str | None = None,
        tenant_id: str | None = None,
        partition: int | None = None,
        offset: int | None = None,
    ) -> DeadLetter:
        try:
            excerpt = json.dumps(payload, default=str)[:_MAX_PAYLOAD_CHARS]
        except (TypeError, ValueError):
            excerpt = str(payload)[:_MAX_PAYLOAD_CHARS]
        return cls(
            topic=topic,
            reason=reason,
            schema_version=schema_version,
            payload_excerpt=excerpt,
            source_event_id=source_event_id,
            tenant_id=tenant_id,
            partition=partition,
            offset=offset,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "topic": self.topic,
            "reason": self.reason,
            "schema_version": self.schema_version,
            "payload_excerpt": self.payload_excerpt,
            "source_event_id": self.source_event_id,
            "tenant_id": self.tenant_id,
            "partition": self.partition,
            "offset": self.offset,
            "ts": self.ts,
        }


@runtime_checkable
class DeadLetterQueue(Protocol):
    """A sink for rejected messages.

    Implementations may expose a class attribute ``durable`` saying whether a
    successful ``record`` is *storage* rather than a log line. It is not part
    of the protocol because a data member would make ``issubclass`` unusable
    for a ``runtime_checkable`` protocol; the consumer reads it with
    ``getattr(..., "durable", False)`` and defaults to the honest answer.
    """

    async def record(self, dead_letter: DeadLetter) -> bool | None:
        """Persist/emit a rejected message.

        Return ``False`` when the capture definitively failed. Any other
        result — including the historical ``None`` — is treated as success,
        so an existing sink that only raises on failure keeps working.
        """


class LoggingDLQ:
    """Default sink — structured warning. Alert on ``fusion.dead_letter``."""

    #: A log line is not durable storage. See the protocol attribute.
    durable = False

    async def record(self, dead_letter: DeadLetter) -> bool:
        logger.warning("fusion.dead_letter", **dead_letter.to_dict())
        return True


class InMemoryDLQ:
    """Test double. Keeps records so assertions can inspect them."""

    #: Forgets on restart, so it is not a durable capture either.
    durable = False

    def __init__(self) -> None:
        self.records: list[DeadLetter] = []

    async def record(self, dead_letter: DeadLetter) -> bool:
        self.records.append(dead_letter)
        return True


class KafkaDLQ:
    """Republish to a dead-letter topic via the consumer's producer.

    ``producer`` is the worker's ``AIOKafkaProducer`` (already started). We do
    not own its lifecycle. A send failure raises; :func:`safe_record` turns it
    into ``False`` — a broken DLQ must not wedge the consumer, but it must not
    look like a successful capture either.
    """

    #: ``record`` returns True only after the broker acknowledges the write.
    durable = True

    def __init__(self, producer: Any, topic: str = "aisoc.alerts.dlq") -> None:
        self._producer = producer
        self._topic = topic

    async def record(self, dead_letter: DeadLetter) -> bool:
        # ``AIOKafkaProducer.send`` only enqueues the record: it returns a
        # future that resolves when the broker acknowledges. Awaiting the call
        # alone would report a capture that a later producer failure can still
        # lose, while the consumer commits the offset on the strength of it.
        # ``send_and_wait`` is exactly this pair; using ``send`` keeps the sink
        # compatible with producers (and test doubles) that expose only send.
        future = await self._producer.send(self._topic, value=dead_letter.to_dict())
        await future
        return True


async def safe_record(dlq: DeadLetterQueue | None, dead_letter: DeadLetter) -> bool:
    """Record to the DLQ, swallowing any sink error. Returns True on success.

    A DLQ that raises must never propagate — that would let one poison message
    crash the consumer, the exact failure mode the DLQ exists to prevent. But
    a sink that reports ``False`` (notably :class:`PostgresDLQ` when its pool
    is down) must not be mistaken for a capture: the consumer holds the offset
    uncommitted until a later attempt succeeds.

    ``None`` is accepted as success for backwards compatibility with sinks
    written against the original ``-> None`` protocol.
    """
    if dlq is None:
        return False
    try:
        result = await dlq.record(dead_letter)
        return result is not False
    except Exception as exc:  # noqa: BLE001 — fail-soft by contract
        logger.error("fusion.dlq_sink_failed", error=str(exc), topic=dead_letter.topic, reason=dead_letter.reason)
        return False
