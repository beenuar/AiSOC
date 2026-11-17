"""Kafka consumer — reads security events, scores them, emits anomalies.

The consumer reads ``aisoc.raw_events``: the ingest-normalized OCSF envelope
that every connector and webhook already produces. Entity and features are
recovered by :mod:`app.services.feature_extraction`, which also still accepts
the pre-extracted shape below for operators feeding UEBA from their own
pipeline:

  {
    "event_id":       "uuid-string",
    "tenant_id":      "uuid-string",
    "entity_type":    "user" | "device" | "ip",
    "entity_id":      "alice@example.com",
    "event_type":     "login" | "file_access" | "network" | ...,
    "peer_group_id":  "dept:engineering",   // optional
    "features": {
      "hour_of_day":   14,
      "login_count":   3,
      "bytes_sent":    1024000,
      ...
    },
    "ts": "2026-05-03T12:00:00Z"
  }

Anomalies are published to ``ueba.anomalies``:
  {
    "anomaly_id":     "uuid",
    "tenant_id":      "uuid",
    "entity_type":    "user",
    "entity_id":      "alice@example.com",
    "event_type":     "login",
    "anomaly_score":  4.7,
    "risk_level":     "high",
    "features":       {...},
    "detected_at":    "2026-05-03T12:00:01Z"
  }

What happens when the handler raises
------------------------------------

It logs at ``error``, dead-letters the event, and carries on. A single
unprocessable event must not stop the stream, which is already the policy in
``services/fusion`` and ``services/agents`` — one answer across the three
consumers is worth more than a cleverer answer here.

What must never happen again is the previous behaviour. There was no
``except`` at all: the first event that raised left the ``async for``, the
``finally`` stopped the consumer, and the exception went into the task
object. Because the task was held in a module global it was never
garbage-collected, so asyncio never emitted "Task exception was never
retrieved". The container stayed ``running`` with restarts 0, ``/health``
answered 200, and ``/readyz`` answered 200, for as long as anyone left it up.

Continuing is only safe if a subscription that *does* end says so, so this
class tracks whether it is attached and ``app/main.py`` registers that as a
readiness probe.

Detachment and recovery (#1930)
-------------------------------

Earlier revisions deliberately had no reconnect loop, reasoning that a loop
would turn a permanent fault — a missing column, a revoked grant — into an
indefinite retry that reads as ordinary churn. That reasoning was sound about
*message-level* faults, and those are already handled where they occur: a
database error inside the handler is dead-lettered per event, never retried
by the subscription. What the no-loop stance actually cost was the
*subscription-level* transients — a broker that is down for eighteen seconds
at boot ended the task permanently, and ``restart: unless-stopped`` never
acts on a process that is still running. On the deployment that reported
#1930 that was six days and ~827k unscored events.

``run()`` therefore now supervises with the same three-class split as
``services/fusion`` and the Go consumer's streamhealth: transient faults are
retried with capped exponential backoff (escalating to an error naming the
operator action once the streak outlives any transient explanation),
Kafka-permanent faults (bad credentials, missing grants) stop the loop with
the fix on the final log line, and poison messages never reach supervision
because the handler dead-letters them. ``/readyz`` still reports 503 while
detached and recovers on its own when a retry re-attaches.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
import uuid
from typing import Any

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings
from app.core.kafka_security import kafka_client_kwargs
from app.services.dead_letters import DeadLetterSink
from app.services.feature_extraction import extract
from app.services.peer_group import PeerGroupService
from app.services.scoring import ScoringService

try:
    # Declared dependency (pyproject pins aiokafka>=0.10). Module-level so the
    # supervision tests can monkeypatch the constructors, mirroring
    # services/fusion; the guard keeps the module importable without the dep,
    # where run() reports it once and returns.
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
    from aiokafka.errors import (
        AuthenticationFailedError,
        ClusterAuthorizationFailedError,
        GroupAuthorizationFailedError,
        IllegalSaslStateError,
        TopicAuthorizationFailedError,
        UnsupportedSaslMechanismError,
        UnsupportedVersionError,
    )
except ImportError:  # pragma: no cover — exercised only without the dep installed
    AIOKafkaConsumer = None  # type: ignore[assignment,misc]
    AIOKafkaProducer = None  # type: ignore[assignment,misc]
    AuthenticationFailedError = None  # type: ignore[assignment,misc]
    ClusterAuthorizationFailedError = None  # type: ignore[assignment,misc]
    GroupAuthorizationFailedError = None  # type: ignore[assignment,misc]
    IllegalSaslStateError = None  # type: ignore[assignment,misc]
    TopicAuthorizationFailedError = None  # type: ignore[assignment,misc]
    UnsupportedSaslMechanismError = None  # type: ignore[assignment,misc]
    UnsupportedVersionError = None  # type: ignore[assignment,misc]

LOG = logging.getLogger(__name__)

#: Backoff bounds for the supervised consumer (#1930). Module constants so a
#: test can drive the real entry point — ``run()`` — at test speed. Values and
#: rationale mirror services/fusion/app/workers/consumer.py.
SUPERVISOR_INITIAL_BACKOFF_SECONDS = 1.0
SUPERVISOR_MAX_BACKOFF_SECONDS = 60.0

#: How long one uninterrupted failure may keep being called transient before
#: the log escalates to an error naming the operator action.
SUPERVISOR_STUCK_AFTER_SECONDS = 120.0


def permanent_failure_action(exc: BaseException) -> str | None:
    """What an operator must change, or ``None`` when a retry may still work.

    The permanent arm of the three-class split described in the module
    docstring. Everything absent from this table is treated as transient and
    retried; see fusion's copy for why that direction is deliberate.
    """
    table: tuple[tuple[type[BaseException] | None, str], ...] = (
        (
            AuthenticationFailedError,
            "fix the Kafka credentials this service presents (AISOC_KAFKA_SASL_USERNAME / _PASSWORD)",
        ),
        (
            UnsupportedSaslMechanismError,
            "set AISOC_KAFKA_SASL_MECHANISM to a mechanism this broker offers",
        ),
        (
            IllegalSaslStateError,
            "check the SASL mechanism and security protocol agree with the broker's listener",
        ),
        (
            TopicAuthorizationFailedError,
            "grant this principal Read on the raw-events topic and Write on the anomalies topic",
        ),
        (
            GroupAuthorizationFailedError,
            "grant this principal Read on the UEBA consumer group",
        ),
        (
            ClusterAuthorizationFailedError,
            "grant this principal the cluster permissions the broker requires, or point it at a cluster it may use",
        ),
        (
            UnsupportedVersionError,
            "the broker is older than this client requires; upgrade the broker or pin an older aiokafka",
        ),
    )
    for error_type, action in table:
        if error_type is not None and isinstance(exc, error_type):
            return action
    return None


class UEBAKafkaConsumer:
    def __init__(self) -> None:
        self._engine = create_async_engine(settings.database_url, pool_size=5)
        self._session_factory = async_sessionmaker(self._engine, expire_on_commit=False)
        self._running = False
        # True only while the ``async for`` is iterating a started consumer.
        # Read through ``attached`` by the readiness probe; set False in the
        # loop's ``finally`` so every exit path — clean stop, broker loss,
        # unhandled error — is reported the same way.
        self._attached = False
        #: Successful attaches, so the supervisor's stuck-escalation clock
        #: resets after a healthy stretch (#1930).
        self._attach_count = 0
        #: Signalled by stop() so a supervision backoff sleep wakes
        #: immediately instead of making shutdown wait it out (#1930).
        self._stop_event = asyncio.Event()
        self._dlq = DeadLetterSink(self._session_factory)
        self._stats: dict[str, Any] = {
            "processed": 0,
            "handler_failures": 0,
            "dead_lettered": 0,
            "last_error": None,
        }

    @property
    def attached(self) -> bool:
        """Whether this consumer is currently subscribed and iterating."""
        return self._attached

    def stats(self) -> dict[str, Any]:
        """Counters for ``/health``. A copy, so a caller cannot edit them."""
        return dict(self._stats)

    async def _process_message(self, raw: bytes, producer: Any) -> None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            LOG.warning("Invalid JSON message; skipping.")
            return

        # An event with no recoverable entity or no numeric feature is a
        # normal outcome, not an error — most telemetry names no identity, and
        # something with no baseline cannot deviate from one.
        event = extract(msg)
        if event is None:
            return

        entity_type = event.entity_type
        entity_id = event.entity_id
        event_type = event.event_type
        peer_group_id = event.peer_group_id
        features = event.features
        source_event_id = event.source_event_id

        try:
            tenant_id = uuid.UUID(event.tenant_id)
        except ValueError:
            LOG.warning("Invalid tenant_id: %s", event.tenant_id)
            return

        async with self._session_factory() as session:
            async with session.begin():
                # Update peer group if provided
                if peer_group_id:
                    peer_svc = PeerGroupService(session)
                    await peer_svc.update(tenant_id, peer_group_id, entity_type, features)

                scorer = ScoringService(session)
                anomaly = await scorer.score_event(
                    tenant_id=tenant_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    event_type=event_type,
                    features=features,
                    source_event_id=source_event_id,
                    peer_group_id=peer_group_id,
                )

        if anomaly and producer:
            payload = {
                "anomaly_id": str(anomaly.id),
                "tenant_id": str(anomaly.tenant_id),
                "entity_type": anomaly.entity_type,
                "entity_id": anomaly.entity_id,
                "event_type": anomaly.event_type,
                "anomaly_score": anomaly.anomaly_score,
                "risk_level": anomaly.risk_level,
                "features": anomaly.features,
                "peer_group_id": anomaly.peer_group_id,
                "peer_deviation_score": anomaly.peer_deviation_score,
                "detected_at": anomaly.detected_at.isoformat() if anomaly.detected_at else None,
            }
            await producer.send_and_wait(
                settings.kafka_output_topic,
                json.dumps(payload).encode(),
            )
            LOG.info(
                "Anomaly emitted: entity=%s/%s score=%.2f risk=%s",
                entity_type,
                entity_id,
                anomaly.anomaly_score,
                anomaly.risk_level,
            )

    async def run(self) -> None:
        """Consume under supervision until cancelled or stopped (#1930).

        A transient Kafka failure — the commonest being "the broker is not up
        yet" at boot, which used to end this task permanently while the
        container stayed ``running`` — is retried with capped exponential
        backoff. A failure no retry can clear stops the loop with the
        operator action on the final log line. Shutdown is unchanged:
        ``app/main.py`` cancels the task, and the cancellation propagates
        straight through supervision.
        """
        if AIOKafkaConsumer is None:
            LOG.error("aiokafka not installed; Kafka consumer disabled.")
            return

        backoff = SUPERVISOR_INITIAL_BACKOFF_SECONDS
        failing_since: float | None = None
        self._stop_event.clear()
        while not self._stop_event.is_set():
            attached_before = self._attach_count
            try:
                await self._attempt_start()
                return  # consume loop ended on a clean stop request
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — classified below, not swallowed
                if self._stop_event.is_set():
                    return

                action = permanent_failure_action(exc)
                if action is not None:
                    LOG.error(
                        "UEBA Kafka consumer failed permanently (%s: %s). Operator action: %s. "
                        "Supervision stopped because no retry can clear this; /readyz stays 503 "
                        "until the cause is fixed and the service restarted.",
                        type(exc).__name__,
                        exc,
                        action,
                        exc_info=exc,
                    )
                    return

                now = time.monotonic()
                if self._attach_count > attached_before:
                    failing_since = None
                if failing_since is None:
                    failing_since = now
                failing_for = now - failing_since

                if failing_for >= SUPERVISOR_STUCK_AFTER_SECONDS:
                    LOG.error(
                        "UEBA Kafka consumer still cannot attach after %.1fs (%s: %s). Check that "
                        "KAFKA_BOOTSTRAP_SERVERS names a broker this container can resolve and "
                        "reach, and that topic %s exists. Still retrying (backoff %.1fs).",
                        failing_for,
                        type(exc).__name__,
                        exc,
                        settings.kafka_input_topic,
                        backoff,
                        exc_info=exc,
                    )
                else:
                    LOG.warning(
                        "UEBA Kafka consumer crashed, retrying in %.1fs (%s: %s; failing for %.1fs).",
                        backoff,
                        type(exc).__name__,
                        exc,
                        failing_for,
                    )

                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=backoff)
                    return  # stop() was requested during the backoff
                except TimeoutError:
                    pass
                backoff = min(backoff * 2, SUPERVISOR_MAX_BACKOFF_SECONDS)

    async def _attempt_start(self) -> None:
        """One bootstrap/consume/teardown cycle. Raises if it cannot start.

        The ``finally`` covers the bootstrap as well as the consume loop. The
        previous shape started both clients *before* entering its try block,
        so a raise out of ``producer.start()`` left a started consumer that
        nothing would ever stop — harmless once per process, a client leak
        per attempt under supervision.
        """
        consumer = AIOKafkaConsumer(
            settings.kafka_input_topic,
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.kafka_consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=True,
            **kafka_client_kwargs(),
        )
        producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            **kafka_client_kwargs(),
        )
        try:
            await consumer.start()
            await producer.start()
            self._running = True
            self._attached = True
            self._attach_count += 1
            LOG.info("UEBA Kafka consumer started (topic=%s)", settings.kafka_input_topic)

            async for msg in consumer:
                if not self._running:
                    break
                try:
                    await self._process_message(msg.value, producer)
                except Exception as exc:  # noqa: BLE001 — one event must not end the subscription
                    await self._handler_failed(msg, exc)
                else:
                    self._stats["processed"] += 1
        finally:
            # Before the awaits below, not after: ``consumer.stop()`` can
            # itself raise on a broker that has gone away, and readiness must
            # already be reporting detached by then rather than staying 200
            # through a failed teardown. Suppressed so a teardown raise
            # cannot replace the exception the supervisor needs to classify.
            self._attached = False
            with contextlib.suppress(Exception):
                await consumer.stop()
            with contextlib.suppress(Exception):
                await producer.stop()
            LOG.info("UEBA Kafka consumer stopped.")

    async def _handler_failed(self, msg: Any, exc: Exception) -> None:
        """Report one unprocessable event and keep the subscription.

        Loud on purpose. This is the exact point the old code exited from
        without writing anything anywhere, so the log line carries the
        partition and offset needed to find the event again, and
        ``exc_info`` carries the traceback that says which column or grant
        was missing.
        """
        self._stats["handler_failures"] += 1
        self._stats["last_error"] = f"{type(exc).__name__}: {str(exc)[:300]}"

        topic = getattr(msg, "topic", settings.kafka_input_topic)
        partition = getattr(msg, "partition", None)
        offset = getattr(msg, "offset", None)
        raw = getattr(msg, "value", msg)

        LOG.error(
            "UEBA handler failed; event dead-lettered and the subscription kept. topic=%s partition=%s offset=%s error=%s: %s",
            topic,
            partition,
            offset,
            type(exc).__name__,
            exc,
            exc_info=True,
        )

        payload: Any
        try:
            payload = json.loads(raw) if isinstance(raw, bytes | bytearray) else raw
        except (json.JSONDecodeError, UnicodeDecodeError):
            payload = {"undecodable": str(raw)[:500]}

        tenant_id = payload.get("tenant_id") if isinstance(payload, dict) else None
        source_event_id = payload.get("event_id") if isinstance(payload, dict) else None

        recorded = await self._dlq.record(
            topic=str(topic),
            reason=f"{type(exc).__name__}: {str(exc)[:400]}",
            payload=payload,
            tenant_id=str(tenant_id) if tenant_id else None,
            source_event_id=str(source_event_id) if source_event_id else None,
        )
        if recorded:
            self._stats["dead_lettered"] += 1

    def stop(self) -> None:
        # First, so a supervision backoff sleep wakes immediately (#1930).
        self._stop_event.set()
        self._running = False
