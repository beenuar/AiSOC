"""
Kafka consumer worker: reads raw alerts (and, since Phase 3.1, ingest's
normalized OCSF events), runs them through the fusion engine, publishes fused
results back to Kafka, and persists non-duplicate alerts to Postgres.
"""

import asyncio
import contextlib
import json
import random
import time
from typing import Any

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition

from app.core.config import settings
from app.core.kafka_security import kafka_client_kwargs
from app.models.alert import FusionDecision, RawAlert
from app.services.ai_asset_recorder import AiAssetRecorder
from app.services.alert_sink import AlertSink, PersistOutcome, PersistResult
from app.services.detection_engine import DetectionEngine
from app.services.dlq import DeadLetter, DeadLetterQueue, LoggingDLQ, safe_record
from app.services.event_schema import validate_event
from app.services.fusion_engine import FusionEngine
from app.services.lake_writer import LakeWriter
from app.services.promoter import promote_normalized_event
from app.services.scale_hint import compute as compute_scale_hint
from app.services.sessions import DERIVED_IDLE_SECONDS, SessionRef, SessionStore
from app.services.tenant_overlay import OverlayCache
from app.services.ueba_signal import UebaSignalCache
from app.services.windowed_detection import WindowedDetectionEngine

logger = structlog.get_logger()

_METRICS = {
    "processed": 0,
    "duplicates": 0,
    "correlated": 0,
    "new_incidents": 0,
    "promoted": 0,
    "not_promoted": 0,
    "persisted": 0,
    "persist_unavailable": 0,
    "persist_failed": 0,
    "persist_retryable": 0,
    "laked": 0,
    # Events recorded against a session (depth plan 2.4). Counted separately
    # from `laked` so a deployment can see that the session store is working
    # rather than inferring it from alerts that happen to carry an id.
    "sessions": 0,
    "detected": 0,
    "dead_lettered": 0,
    "errors": 0,
    "ai_assets_observed": 0,
    # Durability counters. `retried` counts message-level attempts after a
    # transient failure; `retry_exhausted` counts a message whose bounded
    # budget ran out; `recovery_holds` counts the catastrophic case where the
    # store *and* the DLQ are down and the message is deliberately held
    # uncommitted until one returns.
    "retried": 0,
    "retry_exhausted": 0,
    "recovery_holds": 0,
    "publish_failed": 0,
    # 1 when the configured DLQ is durable storage, 0 in the explicit
    # persistence-free mode (LoggingDLQ). A committed offset is evidence of
    # durable capture only in the first case.
    "durable_capture": 0,
}


class _UnparseableRecord:
    """A Kafka value that is not UTF-8 JSON.

    The deserializer runs inside aiokafka's fetch, before the consume loop sees
    a record, so letting ``json.loads`` raise there ends the iterator and stops
    fusion: one malformed byte string becomes a remote kill switch. Carrying the
    text instead lets the normal dead-letter path capture it with its offset.
    """

    __slots__ = ("text",)

    def __init__(self, raw: bytes | None) -> None:
        self.text = (raw or b"").decode("utf-8", errors="replace")


def _decode_record_value(raw: bytes | None) -> Any:
    """Deserialize a Kafka value, or mark it for the DLQ instead of raising.

    aiokafka applies this while building the record. An exception here is not a
    per-message failure the loop can catch — it propagates out of the iterator
    and terminates consumption.
    """
    try:
        return json.loads((raw or b"").decode("utf-8"))
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        # JSONDecodeError is a ValueError; RecursionError covers a deeply
        # nested body that would otherwise take the iterator down too.
        return _UnparseableRecord(raw)


class RetryableProcessingError(RuntimeError):
    """A transient failure: re-running the message could succeed.

    The consumer must not commit the Kafka offset for this message. The sink
    has already classified the failure (connection lost, timeout, pool
    exhausted); this type is how that classification crosses the service
    boundary without string matching in the loop.
    """


class PermanentProcessingError(RuntimeError):
    """A deterministic failure: a retry would fail the same way.

    Captured by the DLQ and only then committed. Examples: an unknown tenant
    (foreign-key violation) or a row the database rejects as invalid.
    """


#: How often the worker sweeps for derived sessions that have gone quiet.
#: A quarter of the idle window, so a session is closed within roughly
#: DERIVED_IDLE_SECONDS of its last event rather than up to twice that.
SESSION_SWEEP_SECONDS = DERIVED_IDLE_SECONDS / 4


class FusionWorker:
    """Kafka consumer/producer pair that drives the fusion pipeline."""

    def __init__(
        self,
        engine: FusionEngine,
        sink: AlertSink | None = None,
        dlq: DeadLetterQueue | None = None,
        lake: LakeWriter | None = None,
        detector: DetectionEngine | None = None,
        windowed_detector: WindowedDetectionEngine | None = None,
        first_seen: Any | None = None,
        baselines: Any | None = None,
        ueba_cache: UebaSignalCache | None = None,
        overlays: OverlayCache | None = None,
        sessions: SessionStore | None = None,
        ai_assets: AiAssetRecorder | None = None,
    ) -> None:
        self._engine = engine
        self._sink = sink
        self._lake = lake
        self._detector = detector
        self._windowed = windowed_detector
        self._first_seen = first_seen
        #: Depth plan 3.4 behavioural baselines, computed in CORE.
        self._baselines = baselines
        self._ueba_cache = ueba_cache
        #: Depth 6.1 — the observed AI estate. Optional in the same sense the
        #: lake writer is: a deployment that passes nothing behaves exactly
        #: as before, and `main.py` passes one on every profile.
        self._ai_assets = ai_assets
        #: Per-tenant detection tuning (parity 5.4). Optional, so a
        #: deployment that passes nothing behaves exactly as before.
        self._overlays = overlays
        #: Depth plan 2.4. Optional so a deployment without the migration
        #: behaves exactly as before: alerts carry no session context
        #: rather than carrying an invented one.
        self._sessions = sessions
        # A poison message must never vanish silently; default to a structured
        # logging DLQ so persistence-free deployments still get the signal.
        self._dlq: DeadLetterQueue = dlq or LoggingDLQ()
        #: Whether a successful DLQ capture is durable storage. The default
        #: `LoggingDLQ` is not: it emits a line and returns True. In that mode
        #: a committed offset means "processed", not "durably captured", and
        #: the service must say so rather than let the invariant be inferred
        #: from the retry machinery.
        self._durable_capture = bool(getattr(self._dlq, "durable", False))
        _METRICS["durable_capture"] = int(self._durable_capture)
        self._consumer: AIOKafkaConsumer | None = None
        self._producer: AIOKafkaProducer | None = None
        self._running = False
        self._attached = False
        self._flush_task: asyncio.Task | None = None
        #: Signalled by stop() so retry sleeps wake immediately instead of
        #: making shutdown wait out an exponential backoff.
        self._stop_event = asyncio.Event()
        #: Set while the consume loop is running, cleared when it exits. stop()
        #: waits on this so it never closes the Kafka clients underneath an
        #: in-flight message; an unfinished message is left uncommitted.
        self._loop_done = asyncio.Event()
        self._loop_done.set()
        self._inflight = 0

    @property
    def engine(self) -> FusionEngine:
        return self._engine

    @property
    def attached(self) -> bool:
        """Whether the consume loop is currently iterating the subscription.

        ``_running`` is a request ("keep going"); this is an observation ("it
        is going"). Readiness needs the second one: the worker was started as
        a fire-and-forget task and ``/readyz`` latched to 200 next to it, so a
        loop that exited left the service reporting ready forever.
        """
        return self._attached

    @property
    def durable_capture(self) -> bool:
        """Whether a committed offset implies a durable capture on failure.

        False in the explicitly persistence-free mode: the default
        `LoggingDLQ` writes a log line, and a deployment with
        ``AISOC_ALERT_SINK_ENABLED=false`` persists no alert rows either. The
        retry/hold machinery still runs, but it cannot make a log line durable.
        """
        return self._durable_capture

    async def start(self) -> None:
        self._stop_event.clear()
        topics = [settings.kafka_topic_alerts_raw]
        # Subscribe to raw_events when EITHER promotion or lake archival needs
        # it — the lake must fill even if promotion is turned off.
        if settings.event_promotion_enabled or self._lake is not None or self._detector is not None or self._windowed is not None:
            topics.append(settings.kafka_topic_raw_events)
        # Phase A4 — also consume the UEBA behavioral-anomaly stream so the
        # per-entity signal cache stays warm for fuse-time boosting.
        if self._ueba_cache is not None:
            topics.append(settings.kafka_topic_ueba_anomalies)
        self._consumer = AIOKafkaConsumer(
            *topics,
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.kafka_consumer_group,
            auto_offset_reset="latest",
            # At-least-once: commit offsets only AFTER a message is fully
            # processed (see _consume_loop), not on a background timer that could
            # commit an in-flight message before processing finishes.
            enable_auto_commit=False,
            value_deserializer=_decode_record_value,
            **kafka_client_kwargs(),
        )
        self._producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            **kafka_client_kwargs(),
        )
        await self._consumer.start()
        await self._producer.start()
        if self._sink is not None:
            await self._sink.start()
        if self._lake is not None or self._sessions is not None:
            if self._lake is not None:
                await self._lake.start()
            # Low-traffic safety net: a single buffered event would otherwise
            # wait for the NEXT message before flush_if_stale runs. A background
            # ticker guarantees the lake batch flushes by age even when idle.
            #
            # The same ticker closes idle derived sessions. A derived session
            # ends when the activity stops, so nothing on the event path can
            # ever close one -- the closing condition is the *absence* of an
            # event. Without a ticker every derived session would stay open
            # forever and "what else did this sitting do" would accumulate
            # months of unrelated activity under one id.
            self._flush_task = asyncio.create_task(self._periodic_flush())
        self._running = True
        if not self._durable_capture:
            logger.warning(
                "fusion.persistence_free_mode",
                dlq=type(self._dlq).__name__,
                alert_sink=self._sink is not None,
                detail=(
                    "no durable DLQ is configured; dead letters are log-only and a committed offset means processed, not durably captured"
                ),
            )
        logger.info(
            "Fusion worker started",
            consumer_group=settings.kafka_consumer_group,
            input_topics=topics,
            output_topic=settings.kafka_topic_alerts_fused,
            alert_sink=self._sink is not None,
            lake_writer=self._lake is not None,
        )
        await self._consume_loop()

    async def _periodic_flush(self) -> None:
        interval = max(0.5, settings.lake_batch_max_age_seconds)
        # Elapsed wall-clock rather than a tick count, because the two
        # cadences are set independently: a tick count derived from the
        # lake's flush interval silently changes the sweep period whenever
        # someone tunes the lake, which is a coupling nobody would expect
        # from either setting's name.
        last_sweep = time.monotonic()
        try:
            while self._running:
                await asyncio.sleep(interval)
                if self._lake is not None:
                    await self._lake.flush_if_stale()
                if self._ai_assets is not None:
                    await self._ai_assets.flush_if_stale()
                if self._sessions is None:
                    continue
                now = time.monotonic()
                if now - last_sweep < SESSION_SWEEP_SECONDS:
                    continue
                last_sweep = now
                closed = await self._sessions.close_idle()
                if closed:
                    logger.info("Closed idle derived sessions", closed=closed)
        except asyncio.CancelledError:  # pragma: no cover — shutdown path
            pass

    async def stop(self) -> None:
        self._running = False
        # Wake any retry/backoff sleep. Without this a 30s backoff would make
        # every rolling restart look like a hang.
        self._stop_event.set()
        if self._flush_task is not None:
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                _ = await self._flush_task  # await the cancellation to settle
            self._flush_task = None

        # Let an in-flight message finish (and, if it succeeded, commit)
        # before tearing the clients down. Closing Kafka underneath the loop
        # was a race: the message could be half-processed while its offset
        # looked committed. On timeout we proceed with the offset uncommitted
        # so Kafka re-delivers it.
        #
        # Only wait when a message is actually in flight. An idle loop is
        # blocked in the consumer iterator and cannot observe `_running`; if
        # we waited on it here, every clean shutdown would burn the full grace
        # period for a message that does not exist. Closing the consumer below
        # wakes that iterator instead.
        if not self._loop_done.is_set() and self._inflight > 0:
            try:
                await asyncio.wait_for(self._loop_done.wait(), timeout=max(0.0, settings.shutdown_grace_seconds))
            except TimeoutError:
                logger.warning(
                    "fusion.shutdown_grace_expired",
                    grace_seconds=settings.shutdown_grace_seconds,
                    inflight=self._inflight,
                    detail="in-flight message left uncommitted; Kafka will re-deliver it",
                )

        if self._consumer:
            await self._consumer.stop()
        if self._producer:
            await self._producer.stop()
        if self._sink is not None:
            await self._sink.stop()
        if self._lake is not None:
            await self._lake.stop()
        # Flush the inventory buffer on the way out, so a clean shutdown does
        # not discard up to 30 seconds of sightings.
        if self._ai_assets is not None:
            await self._ai_assets.flush()
        logger.info("Fusion worker stopped", metrics=_METRICS, inflight=self._inflight)

    async def _consume_loop(self) -> None:
        # `start()` is the only caller and assigns `_consumer` before getting
        # here. Bound locally so that invariant is stated where it is relied
        # on: iterating or committing a None consumer would otherwise be an
        # AttributeError inside the message loop, reported as a processing
        # failure rather than as the startup bug it is.
        consumer = self._consumer
        if consumer is None:  # pragma: no cover — unreachable via start()
            raise RuntimeError("fusion consume loop started before the Kafka consumer")
        # Attached for as long as this loop is iterating; read by the
        # readiness probe app/main.py registers. Cleared in the ``finally`` so
        # every exit path reports the same way, including one that raises.
        self._attached = True
        self._loop_done.clear()
        try:
            async for msg in consumer:
                if not self._running or self._stop_event.is_set():
                    break
                self._inflight += 1
                try:
                    handled = await self._handle_message(msg)

                    if not handled:
                        # The message could not be made durable and could not
                        # be captured. Do not commit: leaving the offset
                        # untouched is the only outcome that guarantees Kafka
                        # re-delivers it.
                        logger.error(
                            "fusion.message_not_durable",
                            topic=msg.topic,
                            partition=msg.partition,
                            offset=msg.offset,
                            detail="offset not committed; the message will be re-delivered",
                        )
                        break

                    # At-least-once: commit only after the message is handled
                    # (validated + laked + promoted, or dead-lettered). A crash
                    # before this line re-delivers the in-flight message on
                    # restart instead of losing it. Commit failure => reprocess
                    # on restart.
                    #
                    # Commit *this* partition's next offset, not every consumed
                    # position. ``commit()`` with no argument acknowledges all
                    # partitions up to the fetcher's position, which can include
                    # records from another partition that have been fetched but
                    # not handled yet. That is the same skip-ahead defect this
                    # loop exists to prevent, one partition over.
                    checkpoint = {TopicPartition(msg.topic, msg.partition): msg.offset + 1}
                    try:
                        await consumer.commit(checkpoint)
                    except Exception as commit_exc:  # noqa: BLE001
                        logger.warning("fusion.commit_failed", error=str(commit_exc))

                    # Flush any stale lake batch so archival isn't stranded
                    # during a low-traffic window (batch fills by size OR age).
                    #
                    # Guarded, because this await sat outside the per-message
                    # try/except: a ClickHouse outage raising here left the
                    # ``async for`` entirely and stopped fusion consuming, with
                    # the archive fault reported as nothing at all. Archival
                    # falling behind must not cost the alert path.
                    if self._lake is not None:
                        try:
                            await self._lake.flush_if_stale()
                        except Exception as flush_exc:  # noqa: BLE001 — the lake is not the alert path
                            _METRICS["errors"] += 1
                            logger.error("fusion.lake_flush_failed", error=str(flush_exc), exc_info=True)
                finally:
                    # Decremented only after commit and lake flush. ``stop()``
                    # uses this counter to decide whether it must wait: hitting
                    # zero while a commit is still in flight would let shutdown
                    # close the consumer underneath it.
                    self._inflight -= 1

                if not self._running or self._stop_event.is_set():
                    break
        finally:
            self._attached = False
            self._loop_done.set()

    async def _handle_message(self, msg: Any) -> bool:
        """Process one Kafka record, returning whether its offset may commit.

        Transient failures are retried with exponential backoff + jitter. When
        the bounded budget is exhausted the message is captured by the DLQ; if
        the DLQ is also unreachable the message is held (and never committed)
        until either store returns, because the alternative — committing a
        message that exists nowhere durable — is the silent loss this loop
        exists to prevent.

        ``False`` means "do not commit"; the consume loop stops rather than
        racing ahead of an un-durable offset.
        """
        if isinstance(msg.value, _UnparseableRecord):
            # The deserializer could not parse this record, so it never became
            # a dict the pipeline could validate. Capture it like any other
            # poison message; a failed capture holds the offset.
            return await self._dead_letter_or_hold(
                topic=msg.topic,
                payload=msg.value.text,
                reason="kafka value is not valid JSON",
                partition=msg.partition,
                offset=msg.offset,
            )

        attempt = 0
        max_retries = max(0, settings.consumer_max_retries)
        while True:
            if not self._running or self._stop_event.is_set():
                return False
            try:
                await self._process_message(
                    msg.value,
                    topic=msg.topic,
                    partition=msg.partition,
                    offset=msg.offset,
                )
                return True
            except asyncio.CancelledError:
                raise
            except RetryableProcessingError as exc:
                attempt += 1
                if attempt <= max_retries:
                    _METRICS["retried"] += 1
                    delay = self._retry_delay(attempt)
                    logger.warning(
                        "fusion.message_retry",
                        attempt=attempt,
                        max_retries=max_retries,
                        retry_in_seconds=round(delay, 2),
                        topic=msg.topic,
                        partition=msg.partition,
                        offset=msg.offset,
                        error=str(exc),
                    )
                    if not await self._sleep_with_shutdown(delay):
                        return False
                    continue

                _METRICS["retry_exhausted"] += 1
                logger.error(
                    "fusion.retry_exhausted",
                    attempts=attempt,
                    topic=msg.topic,
                    partition=msg.partition,
                    offset=msg.offset,
                    error=str(exc),
                )
                captured = await self._dead_letter_or_hold(
                    topic=msg.topic,
                    payload=msg.value,
                    reason=f"transient processing failure after {attempt} attempts: {exc}",
                    partition=msg.partition,
                    offset=msg.offset,
                )
                return captured
            except PermanentProcessingError as exc:
                # `persist_failed` is incremented by the sink path itself;
                # counting it here too would double-report one rejected row.
                _METRICS["errors"] += 1
                return await self._dead_letter_or_hold(
                    topic=msg.topic,
                    payload=msg.value,
                    reason=f"permanent processing failure: {exc}",
                    partition=msg.partition,
                    offset=msg.offset,
                )
            except Exception as exc:
                # An unexpected exception is not safe to commit past: the old
                # loop logged it and then committed the *next* message's
                # offset, skipping this one permanently. Capture it instead.
                _METRICS["errors"] += 1
                logger.error(
                    "fusion.unhandled_processing_error",
                    topic=msg.topic,
                    partition=msg.partition,
                    offset=msg.offset,
                    error=str(exc),
                    exc_info=True,
                )
                return await self._dead_letter_or_hold(
                    topic=msg.topic,
                    payload=msg.value,
                    reason=f"unhandled processing error: {exc}",
                    partition=msg.partition,
                    offset=msg.offset,
                )

    def _retry_delay(self, attempt: int) -> float:
        """Capped exponential backoff with jitter.

        ``attempt`` is 1-based. The upper half of the exponential window is
        used so retries do not all land on the same millisecond; the cap means
        a long outage settles into a steady probe rather than unbounded waits.
        """
        base = max(0.0, settings.consumer_retry_base_seconds)
        cap = max(base, settings.consumer_retry_max_seconds)
        window = min(cap, base * (2 ** min(attempt - 1, 16)))
        return window * (0.5 + random.random() * 0.5)

    async def _sleep_with_shutdown(self, seconds: float) -> bool:
        """Sleep, waking early on shutdown. False means shutdown was requested."""
        if seconds <= 0:
            await asyncio.sleep(0)
            return self._running and not self._stop_event.is_set()
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=seconds)
        except TimeoutError:
            return self._running
        return False

    async def _dead_letter_or_hold(self, **kwargs: Any) -> bool:
        """Capture a message, or hold it uncommitted while the DLQ is down.

        Returns True only once the message is in a durable capture (or the
        logging DLQ, which is the configured sink and always succeeds). A
        failure to capture is *not* a licence to commit.
        """
        while self._running and not self._stop_event.is_set():
            if await self._dead_letter(**kwargs):
                return True
            _METRICS["recovery_holds"] += 1
            logger.critical(
                "fusion.recovery_hold",
                topic=kwargs.get("topic"),
                partition=kwargs.get("partition"),
                offset=kwargs.get("offset"),
                reason=kwargs.get("reason"),
                retry_in_seconds=settings.consumer_recovery_retry_seconds,
                detail="primary store and DLQ unavailable; message held uncommitted",
            )
            if not await self._sleep_with_shutdown(max(0.1, settings.consumer_recovery_retry_seconds)):
                return False
        return False

    async def _dead_letter(
        self,
        *,
        topic: str,
        payload,
        reason: str,
        schema_version: str = "v1",
        source_event_id: str | None = None,
        tenant_id: str | None = None,
        partition: int | None = None,
        offset: int | None = None,
    ) -> bool:
        """Route a poison message to the DLQ instead of dropping it silently.

        ``partition`` and ``offset`` are carried through because the excerpt
        stored alongside them is a triage record, not the event: replaying a
        refused message means re-reading it from Kafka, and these are the only
        way back to it (deferral 5b).

        Returns whether the capture succeeded. Callers deciding whether to
        commit must use the answer: a failed DLQ write is not a capture.
        """
        recorded = await safe_record(
            self._dlq,
            DeadLetter.build(
                topic=topic,
                reason=reason,
                schema_version=schema_version,
                payload=payload,
                source_event_id=source_event_id,
                tenant_id=tenant_id,
                partition=partition,
                offset=offset,
            ),
        )
        if recorded:
            _METRICS["dead_lettered"] += 1
        return recorded

    async def _process_message(
        self, payload: dict, topic: str | None = None, partition: int | None = None, offset: int | None = None
    ) -> None:
        resolved_topic = topic or settings.kafka_topic_alerts_raw

        # Phase A4 — UEBA anomaly stream: warm the per-entity signal cache and
        # return (these are behavioral signals, not alerts).
        if self._ueba_cache is not None and topic == settings.kafka_topic_ueba_anomalies:
            await self._ueba_cache.record(payload)
            return

        # Phase 5 — schema-validate the envelope BEFORE the promoter sees it.
        # A malformed / mis-versioned / mis-tenanted message is dead-lettered
        # (captured with its reason + lineage), never silently dropped.
        validation = validate_event(
            resolved_topic,
            payload,
            raw_events_topic=settings.kafka_topic_raw_events,
            alerts_raw_topic=settings.kafka_topic_alerts_raw,
        )
        if not validation.ok:
            if not await self._dead_letter(
                topic=resolved_topic,
                payload=payload,
                reason=validation.reason,
                schema_version=validation.schema_version,
                source_event_id=validation.source_event_id,
                tenant_id=validation.tenant_id,
                partition=partition,
                offset=offset,
            ):
                # A refused message whose capture failed is still unhandled.
                # Returning here would let the loop commit its offset.
                raise PermanentProcessingError(f"dead-letter capture failed for {validation.reason}")
            return

        # Declared ahead of the branch because the tail call below is shared.
        # A vendor-asserted finding on the alerts topic is not a normalized
        # event and has no session: None reaches the sink, which renders no
        # session context rather than attaching the previous event's.
        session: SessionRef | None = None

        if topic == settings.kafka_topic_raw_events:
            # Depth plan 2.4 — record the session this event belongs to before
            # anything else reads the event, so the lake row, the alert and the
            # graph node all carry the same session id. `session.go` derived
            # the key; this is the stateful half that counts the events and
            # walks the assumed-role chain. It returns None, not an error, for
            # an event whose source names no session — and that stays None all
            # the way to the console rather than becoming a session of one.
            if self._sessions is not None and validation.tenant_id:
                session = await self._sessions.record_event(str(validation.tenant_id), payload)
                if session is not None:
                    _METRICS["sessions"] += 1
                    # Stamped onto the event so the lake row carries the same
                    # id as the Postgres row and the graph node, which is what
                    # lets a hunt join the three without any of them having
                    # agreed on anything at write time.
                    payload["activity"]["session"]["id"] = str(session.id)

            # Phase A1 — archive EVERY normalized event into the ClickHouse lake
            # first, independent of the promotion decision below. A non-promoted
            # Medium event still has to be queryable via /lake/sql.
            if self._lake is not None and await self._lake.write_event(payload, topic=resolved_topic, partition=partition, offset=offset):
                _METRICS["laked"] += 1

            # Depth 6.1 — the observed AI estate is built here rather than by
            # a separate worker reading the lake, for one reason: this is the
            # branch every normalized event already travels on the default
            # profile. A reader of the lake would be a second service CORE
            # does not start, and the inventory page would be empty on the
            # deployment most likely to have an ungoverned AI estate.
            if self._ai_assets is not None:
                _METRICS["ai_assets_observed"] += await self._ai_assets.observe(payload)

            # Resolved once and shared by both engines. Parity 5.4: without
            # the overlay the stateless engine evaluated the shared corpus and
            # nothing else, so a tenant who disabled a noisy rule in the
            # console kept receiving its alerts while the console showed it
            # disabled. The windowed engine reads it for the same reason and
            # for its allowlist booleans.
            overlay = None
            if self._overlays is not None and validation.tenant_id and (self._detector is not None or self._windowed is not None):
                overlay = await self._overlays.get(str(validation.tenant_id))

            # Phase A2 — run the executable detection corpus against the live
            # event. Each firing rule becomes a RawAlert routed through fusion,
            # so telemetry that isn't a vendor-asserted finding still alerts.
            #
            # One event firing N rules produces N alert rows, deliberately
            # (issue #1244 reported one Sysmon event becoming five or six).
            # Each row names the rule that fired, carries that rule's severity
            # and category, and is dispositioned on its own: collapsing them
            # would mean picking one rule's verdict to stand for the others,
            # and an analyst who closes "suspicious PowerShell" has not
            # thereby closed "LSASS access". `Correlator.correlate` already
            # groups them into one incident on
            # {tenant}:{entity}:{tactic} for the console, which is where the
            # N-into-1 view belongs.
            if self._detector is not None:
                for hit in await self._detector.evaluate_async(payload, overlay, self._first_seen, self._baselines):
                    det_alert = self._detector.build_alert(payload, hit)
                    if det_alert is not None:
                        _METRICS["detected"] += 1
                        await self._fuse_and_persist(det_alert, source_event_id=validation.source_event_id, session=session)

            # Wave 2 — stateful/windowed detections (brute force, spray, scans)
            # count this event into its sliding window and fire once on threshold.
            if self._windowed is not None:
                for hit in await self._windowed.evaluate(payload, overlay):
                    win_alert = self._windowed.build_alert(payload, hit)
                    if win_alert is not None:
                        _METRICS["detected"] += 1
                        await self._fuse_and_persist(win_alert, source_event_id=validation.source_event_id, session=session)

            # Ingest-normalized OCSF event — run the deterministic promotion
            # policy (see app/services/promoter.py). Non-promoted events are
            # dropped here by design; the detect stage (above) owns rule eval.
            alert = promote_normalized_event(payload)
            if alert is None:
                _METRICS["not_promoted"] += 1
                return
            _METRICS["promoted"] += 1
        else:
            try:
                alert = RawAlert.model_validate(payload)
            except Exception as exc:
                # Deep validation failure — dead-letter it (the schema layer
                # only caught gross shape); never silently drop.
                reason = f"RawAlert validation failed: {exc}"
                if not await self._dead_letter(
                    topic=resolved_topic,
                    payload=payload,
                    reason=reason,
                    schema_version=validation.schema_version,
                    source_event_id=validation.source_event_id,
                    tenant_id=validation.tenant_id,
                    partition=partition,
                    offset=offset,
                ):
                    raise PermanentProcessingError(f"dead-letter capture failed for {reason}") from exc
                return

        await self._fuse_and_persist(alert, source_event_id=validation.source_event_id, session=session)

    async def _fuse_and_persist(self, alert: RawAlert, *, source_event_id: str | None = None, session: SessionRef | None = None) -> None:
        """Run one RawAlert through fusion, persist it, then publish it.

        Issue #568: the canonical, replay-stable alert id and source-event
        provenance are stamped on the RawAlert *before* fusion, so ``FusedAlert.id``
        (derived from ``alert.id``) matches the persisted ``alerts.id`` row.
        Persist runs *before* publish so the published envelope carries the
        durable row id + a truthful persistence outcome downstream can trust.
        """
        # Stamp source-event provenance + canonical id (issue #568).
        if source_event_id and source_event_id not in alert.source_event_ids:
            alert.source_event_ids.append(source_event_id)
        alert.id = alert.deterministic_id()

        fused = await self._engine.process(alert)
        _METRICS["processed"] += 1

        # Depth plan 2.4. Attached after fusion rather than before, because
        # fusion builds the FusedAlert and anything set on the RawAlert first
        # would have to survive that construction — which is the kind of
        # assumption that holds until someone adds a field.
        if session is not None:
            fused.session_id = session.id
            fused.session_key_kind = session.key_kind
            fused.originating_human = session.originating_human

        if fused.fusion_decision == FusionDecision.DUPLICATE:
            _METRICS["duplicates"] += 1
        elif fused.fusion_decision == FusionDecision.CORRELATED:
            _METRICS["correlated"] += 1
        else:
            _METRICS["new_incidents"] += 1

        # Persist FIRST (Phase 3.1 sink). Fail-soft + idempotent — see
        # app/services/alert_sink.py. Duplicates are handled inside.
        result = PersistResult(PersistOutcome.UNAVAILABLE, str(fused.id))
        if self._sink is not None:
            result = await self._sink.persist(fused)
            if result.outcome is PersistOutcome.INSERTED:
                _METRICS["persisted"] += 1
            elif result.outcome is PersistOutcome.UNAVAILABLE:
                _METRICS["persist_unavailable"] += 1
                _METRICS["persist_retryable"] += 1
            elif result.outcome is PersistOutcome.FAILED:
                _METRICS["persist_failed"] += 1
                if result.retryable:
                    _METRICS["persist_retryable"] += 1

            if not result.durable:
                # The offset must not move until the row is known to exist.
                # A transient failure is retried (with the Kafka message still
                # uncommitted); a permanent one is dead-lettered by the loop.
                if result.retryable or result.outcome is PersistOutcome.UNAVAILABLE:
                    raise RetryableProcessingError(f"alert {fused.id} not durable: {result.outcome.value}")
                raise PermanentProcessingError(f"alert {fused.id} rejected by the alert store: {result.outcome.value}")

        # Publish fused alert (even duplicates, so downstream can track),
        # carrying the durable row id + persistence outcome (issue #568).
        # Publishing only after durability means a downstream consumer never
        # sees a row id that does not exist in Postgres.
        envelope = fused.model_dump(mode="json")
        envelope["alert_row_id"] = result.alert_id
        envelope["persist_outcome"] = result.outcome.value
        producer = self._producer
        if producer is None:  # pragma: no cover — assigned by start()
            raise RuntimeError("fusion produced a fused alert before the Kafka producer started")
        try:
            await asyncio.wait_for(
                producer.send(
                    settings.kafka_topic_alerts_fused,
                    value=envelope,
                ),
                timeout=max(0.1, settings.kafka_send_timeout_seconds),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The row is durable but the notification is not. Retrying the
            # message republishes it; the sink's duplicate reconciliation
            # makes that a no-op at the database.
            _METRICS["publish_failed"] += 1
            raise RetryableProcessingError(f"fused alert publish failed: {exc}") from exc

    @staticmethod
    def get_metrics() -> dict:
        return dict(_METRICS)

    async def consumer_lag(self) -> int | None:
        """Total backlog across the partitions this replica is assigned.

        ``None`` when it cannot be read — no consumer, no assignment yet,
        or a broker that did not answer. Deliberately not zero: an
        unreadable backlog reported as no backlog is how a stalled
        consumer looks healthy, which is the defect this service has
        shipped before.
        """
        consumer = self._consumer
        if consumer is None:
            return None
        try:
            assignment = consumer.assignment()
            if not assignment:
                return None
            total = 0
            for partition in assignment:
                end = await consumer.position(partition)
                highwater = consumer.highwater(partition)
                if end is None or highwater is None:
                    return None
                total += max(0, highwater - end)
            return total
        except Exception as exc:  # noqa: BLE001 — a lag read must never stop the consumer
            logger.warning("fusion.lag_unreadable", error=str(exc))
            return None

    async def scale_hint(self) -> dict:
        """The autoscaling signal, for an operator's HPA or KEDA scaler.

        AiSOC publishes this and does not act on it; ADR-0012 records
        why. The per-replica budget is derived from the published
        realistic-mix run rather than chosen, so the number relates to a
        measurement someone can go and check.
        """
        return compute_scale_hint(await self.consumer_lag()).as_dict()
