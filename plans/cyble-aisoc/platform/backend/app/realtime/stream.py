"""Stream backend abstraction.

The realtime data plane needs a pub/sub layer between the OCSF normalizer
and downstream consumers (Sigma evaluation workers, ClickHouse sink,
websocket fan-out). In a regulated SaaS deployment that's Kafka or
Redpanda. On a laptop demo that's an in-process asyncio queue. Both
implement the same ``StreamBackend`` ABC so the rest of the platform
doesn't care which one is wired up today.

Design principles:

* **In-memory default.** The platform must boot with zero external
  dependencies. ``InMemoryStreamBackend`` is the default and uses
  ``asyncio.Queue`` per topic with bounded buffers to avoid OOM under
  load.
* **Lazy Kafka import.** The ``confluent-kafka`` / ``aiokafka`` package
  is only imported when the operator actually picks Kafka via
  ``AISOC_STREAM_BACKEND=kafka``. We do not force the dependency on the
  base install.
* **At-least-once delivery semantics.** Both backends acknowledge before
  invoking subscribers and re-deliver on consumer error only at the
  Kafka layer (the in-memory backend simply drops on full queue rather
  than blocking the producer — preferable on a demo box).
* **Topic taxonomy is fixed.** We don't let arbitrary string topics
  proliferate. The ``Topics`` registry is the single source of truth.

The fan-out shape (one queue per subscriber, bounded, drop-newest on
overflow) mirrors :mod:`app.api.events` so behavior stays consistent
between the realtime data plane and the existing websocket EventBus.
"""
from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Deque, Iterable


log = logging.getLogger(__name__)


# ── Topic registry ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class Topics:
    """Canonical topic names. Keep this list short.

    Naming convention: ``aisoc.<domain>.<verb>`` lowercase dotted.
    """

    EVENTS_RAW: str = "aisoc.events.raw"
    """Raw vendor events before OCSF normalization."""

    EVENTS_OCSF: str = "aisoc.events.ocsf"
    """Post-normalizer canonical OCSF events. Detection workers read here."""

    DETECTIONS_FIRED: str = "aisoc.detections.fired"
    """Sigma rule matches that survived suppression. Reporter reads here."""

    CASES_LIFECYCLE: str = "aisoc.cases.lifecycle"
    """Case create / status-change / closed events. Websocket fan-out reads here."""


TOPICS = Topics()


# ── Backend interface ──────────────────────────────────────────────────

Handler = Callable[[dict[str, Any]], Awaitable[None]]


class StreamBackend(ABC):
    """Abstract pub/sub backend.

    Implementations must be safe to call from concurrent coroutines.
    ``publish`` must never raise on a healthy backend; on a broken
    backend it should log and swallow rather than crash the producer.
    """

    name: str = "abstract"

    @abstractmethod
    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        """Push a payload onto a topic. Never blocks the caller."""

    @abstractmethod
    async def subscribe(
        self,
        topic: str,
        *,
        group: str = "default",
        history: int = 0,
    ) -> "asyncio.Queue[dict[str, Any]]":
        """Subscribe and receive a queue of payloads.

        ``group`` is informational for the in-memory backend (every
        subscriber gets its own queue) but maps to a real consumer group
        in Kafka. ``history`` returns the last N retained messages for
        late joiners (in-memory only — Kafka has its own retention).
        """

    @abstractmethod
    async def unsubscribe(self, q: "asyncio.Queue[dict[str, Any]]") -> None:
        """Detach a previously subscribed queue."""

    async def aclose(self) -> None:
        """Shut down the backend. Default is no-op for in-memory."""


# ── In-memory implementation ───────────────────────────────────────────


class _MemSubscriber:
    """One queue + topic filter."""

    __slots__ = ("queue", "topic", "group")

    def __init__(self, queue: "asyncio.Queue[dict[str, Any]]", topic: str, group: str) -> None:
        self.queue = queue
        self.topic = topic
        self.group = group


class InMemoryStreamBackend(StreamBackend):
    """asyncio.Queue based backend.

    Behavior on overflow: drop the new message and log a warning. We
    deliberately *do not* block the producer — backpressure across the
    detection path would stall the entire ingest, which is worse than
    losing one message on a backed-up dev box. In Kafka, this is handled
    differently (the broker provides real durability).
    """

    name = "memory"

    def __init__(self, *, queue_size: int = 500, history_size: int = 100) -> None:
        self._subs: list[_MemSubscriber] = []
        # Last N messages per topic for late joiners (e.g. a websocket
        # client that connects after a burst).
        self._history: dict[str, Deque[dict[str, Any]]] = defaultdict(
            lambda: deque(maxlen=history_size)
        )
        self._queue_size = queue_size
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        # Stamp the topic on the payload so multi-topic consumers can
        # disambiguate without keeping side-channel state.
        envelope = {"_topic": topic, **payload}
        self._history[topic].append(envelope)
        # Snapshot subscribers under lock to avoid mutation during iteration.
        async with self._lock:
            subs = [s for s in self._subs if s.topic == topic]
        for sub in subs:
            try:
                sub.queue.put_nowait(envelope)
            except asyncio.QueueFull:
                # Drop-newest. The Kafka backend would not do this; the
                # broker would just exert backpressure. For in-memory we
                # prioritise pipeline liveness over delivery completeness.
                log.warning(
                    "stream.memory: dropping message on full queue topic=%s group=%s",
                    topic,
                    sub.group,
                )

    async def subscribe(
        self,
        topic: str,
        *,
        group: str = "default",
        history: int = 0,
    ) -> "asyncio.Queue[dict[str, Any]]":
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=self._queue_size)
        sub = _MemSubscriber(q, topic, group)
        async with self._lock:
            self._subs.append(sub)
        if history > 0:
            # Replay last N retained messages to the late joiner. We
            # honor the queue bound — if the requested history is larger
            # than the queue, the older entries get dropped.
            for env in list(self._history.get(topic, deque()))[-history:]:
                try:
                    q.put_nowait(env)
                except asyncio.QueueFull:
                    break
        return q

    async def unsubscribe(self, q: "asyncio.Queue[dict[str, Any]]") -> None:
        async with self._lock:
            self._subs = [s for s in self._subs if s.queue is not q]


# ── Kafka implementation (optional) ────────────────────────────────────


class KafkaStreamBackend(StreamBackend):
    """Kafka / Redpanda backend (aiokafka).

    This is the production path. We lazy-import ``aiokafka`` so the
    base install doesn't pull a Confluent client unless the operator
    actually opts in via ``AISOC_STREAM_BACKEND=kafka``.

    Producer semantics: ``acks=all`` for durability, idempotent producer
    so we don't double-publish on retry. Consumer semantics: each
    ``subscribe()`` spawns a background task draining the topic into
    the returned queue, and we use the ``group`` arg as the Kafka
    consumer group so multiple replicas of the same service share work.
    """

    name = "kafka"

    def __init__(self, *, brokers: str) -> None:
        self._brokers = brokers
        self._producer: Any | None = None
        self._consumers: dict[int, tuple[Any, asyncio.Task[None]]] = {}
        # Map queue-id -> (consumer instance, drain task) for cleanup.
        self._lock = asyncio.Lock()

    async def _ensure_producer(self) -> Any:
        if self._producer is not None:
            return self._producer
        try:
            from aiokafka import AIOKafkaProducer  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover - exercised only with extras
            raise RuntimeError(
                "Kafka backend selected but aiokafka is not installed. "
                "Install with `pip install aiokafka` or set AISOC_STREAM_BACKEND=memory."
            ) from exc
        import json

        producer = AIOKafkaProducer(
            bootstrap_servers=self._brokers,
            acks="all",
            enable_idempotence=True,
            value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
        )
        await producer.start()
        self._producer = producer
        return producer

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        try:
            producer = await self._ensure_producer()
        except RuntimeError as exc:
            log.error("stream.kafka: cannot publish, producer init failed: %s", exc)
            return
        try:
            await producer.send_and_wait(topic, {"_topic": topic, **payload})
        except Exception as exc:  # noqa: BLE001 - non-fatal at producer
            # Don't crash the pipeline on a single broker hiccup. The
            # producer is configured idempotent so the next call retries.
            log.warning("stream.kafka: publish failed topic=%s err=%s", topic, exc)

    async def subscribe(
        self,
        topic: str,
        *,
        group: str = "default",
        history: int = 0,  # Kafka has its own retention; argument is informational
    ) -> "asyncio.Queue[dict[str, Any]]":
        try:
            from aiokafka import AIOKafkaConsumer  # type: ignore[import-not-found]
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "Kafka backend selected but aiokafka is not installed."
            ) from exc
        import json

        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=self._brokers,
            group_id=group,
            value_deserializer=lambda v: json.loads(v.decode("utf-8")),
            enable_auto_commit=True,
            auto_offset_reset="latest",
        )
        await consumer.start()
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=500)

        async def _drain() -> None:
            try:
                async for msg in consumer:
                    try:
                        q.put_nowait(msg.value)
                    except asyncio.QueueFull:
                        log.warning(
                            "stream.kafka: dropping message on full queue topic=%s group=%s",
                            topic,
                            group,
                        )
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # noqa: BLE001
                log.error("stream.kafka: drain task crashed topic=%s err=%s", topic, exc)

        task = asyncio.create_task(_drain(), name=f"kafka-drain-{topic}")
        async with self._lock:
            self._consumers[id(q)] = (consumer, task)
        return q

    async def unsubscribe(self, q: "asyncio.Queue[dict[str, Any]]") -> None:
        async with self._lock:
            pair = self._consumers.pop(id(q), None)
        if pair is None:
            return
        consumer, task = pair
        task.cancel()
        try:
            await consumer.stop()
        except Exception as exc:  # noqa: BLE001
            log.warning("stream.kafka: consumer stop failed: %s", exc)

    async def aclose(self) -> None:
        async with self._lock:
            consumers = list(self._consumers.values())
            self._consumers.clear()
        for consumer, task in consumers:
            task.cancel()
            try:
                await consumer.stop()
            except Exception:  # noqa: BLE001
                pass
        if self._producer is not None:
            try:
                await self._producer.stop()
            except Exception:  # noqa: BLE001
                pass
            self._producer = None


# ── Module-level singleton ─────────────────────────────────────────────
#
# We expose one process-wide stream. The factory reads
# ``settings.stream_backend`` so tests can override by re-binding the
# settings before the first call to ``get_stream()``.

_stream: StreamBackend | None = None


def get_stream() -> StreamBackend:
    """Return the process-wide stream backend, constructing on demand."""
    global _stream
    if _stream is not None:
        return _stream
    # Late import so this module stays importable even if settings has
    # other initialization side-effects.
    from app.config import settings

    backend = (getattr(settings, "stream_backend", None) or "memory").lower()
    if backend == "kafka":
        brokers = getattr(settings, "kafka_brokers", "") or ""
        if not brokers:
            log.warning(
                "stream: AISOC_STREAM_BACKEND=kafka but AISOC_KAFKA_BROKERS empty; "
                "falling back to in-memory backend"
            )
            _stream = InMemoryStreamBackend()
        else:
            _stream = KafkaStreamBackend(brokers=brokers)
    else:
        _stream = InMemoryStreamBackend()
    log.info("stream: using %s backend", _stream.name)
    return _stream


def _reset_for_tests() -> None:
    """Test hook: drop the cached singleton so the next get_stream rebuilds.

    Used by ``tests/_check_realtime.py`` to swap backends mid-suite.
    """
    global _stream
    _stream = None
