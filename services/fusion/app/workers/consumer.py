"""
Kafka consumer worker: reads raw alerts (and, since Phase 3.1, ingest's
normalized OCSF events), runs them through the fusion engine, publishes fused
results back to Kafka, and persists non-duplicate alerts to Postgres.
"""

import asyncio
import contextlib
import json

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from app.core.config import settings
from app.models.alert import FusionDecision, RawAlert
from app.services.alert_sink import AlertSink, PersistOutcome, PersistResult
from app.services.detection_engine import DetectionEngine
from app.services.dlq import DeadLetter, DeadLetterQueue, LoggingDLQ, safe_record
from app.services.event_schema import validate_event
from app.services.fusion_engine import FusionEngine
from app.services.lake_writer import LakeWriter
from app.services.promoter import promote_normalized_event
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
    "laked": 0,
    "detected": 0,
    "dead_lettered": 0,
    "errors": 0,
}


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
        ueba_cache: UebaSignalCache | None = None,
    ) -> None:
        self._engine = engine
        self._sink = sink
        self._lake = lake
        self._detector = detector
        self._windowed = windowed_detector
        self._ueba_cache = ueba_cache
        # A poison message must never vanish silently; default to a structured
        # logging DLQ so persistence-free deployments still get the signal.
        self._dlq: DeadLetterQueue = dlq or LoggingDLQ()
        self._consumer: AIOKafkaConsumer | None = None
        self._producer: AIOKafkaProducer | None = None
        self._running = False
        self._flush_task: asyncio.Task | None = None

    @property
    def engine(self) -> FusionEngine:
        return self._engine

    async def start(self) -> None:
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
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        )
        self._producer = AIOKafkaProducer(
            bootstrap_servers=settings.kafka_bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        )
        await self._consumer.start()
        await self._producer.start()
        if self._sink is not None:
            await self._sink.start()
        if self._lake is not None:
            await self._lake.start()
            # Low-traffic safety net: a single buffered event would otherwise
            # wait for the NEXT message before flush_if_stale runs. A background
            # ticker guarantees the lake batch flushes by age even when idle.
            self._flush_task = asyncio.create_task(self._periodic_flush())
        self._running = True
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
        try:
            while self._running:
                await asyncio.sleep(interval)
                if self._lake is not None:
                    await self._lake.flush_if_stale()
        except asyncio.CancelledError:  # pragma: no cover — shutdown path
            pass

    async def stop(self) -> None:
        self._running = False
        if self._flush_task is not None:
            self._flush_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                _ = await self._flush_task  # await the cancellation to settle
            self._flush_task = None
        if self._consumer:
            await self._consumer.stop()
        if self._producer:
            await self._producer.stop()
        if self._sink is not None:
            await self._sink.stop()
        if self._lake is not None:
            await self._lake.stop()
        logger.info("Fusion worker stopped", metrics=_METRICS)

    async def _consume_loop(self) -> None:
        async for msg in self._consumer:
            if not self._running:
                break
            try:
                await self._process_message(msg.value, topic=msg.topic)
            except Exception as exc:
                _METRICS["errors"] += 1
                logger.error("Failed to process message", error=str(exc), exc_info=True)
            else:
                # At-least-once: commit only after the message is handled
                # (validated + laked + promoted, or dead-lettered). A crash
                # before this line re-delivers the in-flight message on restart
                # instead of losing it. Commit failure => reprocess on restart.
                try:
                    await self._consumer.commit()
                except Exception as commit_exc:  # noqa: BLE001
                    logger.warning("fusion.commit_failed", error=str(commit_exc))
            # Flush any stale lake batch so archival isn't stranded during a
            # low-traffic window (batch fills by size OR age).
            if self._lake is not None:
                await self._lake.flush_if_stale()

    async def _dead_letter(
        self,
        *,
        topic: str,
        payload,
        reason: str,
        schema_version: str = "v1",
        source_event_id: str | None = None,
        tenant_id: str | None = None,
    ) -> None:
        """Route a poison message to the DLQ instead of dropping it silently."""
        _METRICS["dead_lettered"] += 1
        await safe_record(
            self._dlq,
            DeadLetter.build(
                topic=topic,
                reason=reason,
                schema_version=schema_version,
                payload=payload,
                source_event_id=source_event_id,
                tenant_id=tenant_id,
            ),
        )

    async def _process_message(self, payload: dict, topic: str | None = None) -> None:
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
            await self._dead_letter(
                topic=resolved_topic,
                payload=payload,
                reason=validation.reason,
                schema_version=validation.schema_version,
                source_event_id=validation.source_event_id,
                tenant_id=validation.tenant_id,
            )
            return

        if topic == settings.kafka_topic_raw_events:
            # Phase A1 — archive EVERY normalized event into the ClickHouse lake
            # first, independent of the promotion decision below. A non-promoted
            # Medium event still has to be queryable via /lake/sql.
            if self._lake is not None and await self._lake.write_event(payload):
                _METRICS["laked"] += 1

            # Phase A2 — run the executable detection corpus against the live
            # event. Each firing rule becomes a RawAlert routed through fusion,
            # so telemetry that isn't a vendor-asserted finding still alerts.
            if self._detector is not None:
                for hit in self._detector.evaluate(payload):
                    det_alert = self._detector.build_alert(payload, hit)
                    if det_alert is not None:
                        _METRICS["detected"] += 1
                        await self._fuse_and_persist(det_alert, source_event_id=validation.source_event_id)

            # Wave 2 — stateful/windowed detections (brute force, spray, scans)
            # count this event into its sliding window and fire once on threshold.
            if self._windowed is not None:
                for hit in await self._windowed.evaluate(payload):
                    win_alert = self._windowed.build_alert(payload, hit)
                    if win_alert is not None:
                        _METRICS["detected"] += 1
                        await self._fuse_and_persist(win_alert, source_event_id=validation.source_event_id)

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
                await self._dead_letter(
                    topic=resolved_topic,
                    payload=payload,
                    reason=f"RawAlert validation failed: {exc}",
                    schema_version=validation.schema_version,
                    source_event_id=validation.source_event_id,
                    tenant_id=validation.tenant_id,
                )
                return

        await self._fuse_and_persist(alert, source_event_id=validation.source_event_id)

    async def _fuse_and_persist(self, alert: RawAlert, *, source_event_id: str | None = None) -> None:
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
            elif result.outcome is PersistOutcome.FAILED:
                _METRICS["persist_failed"] += 1

        # Publish fused alert (even duplicates, so downstream can track),
        # carrying the durable row id + persistence outcome (issue #568).
        envelope = fused.model_dump(mode="json")
        envelope["alert_row_id"] = result.alert_id
        envelope["persist_outcome"] = result.outcome.value
        await self._producer.send(
            settings.kafka_topic_alerts_fused,
            value=envelope,
        )

    @staticmethod
    def get_metrics() -> dict:
        return dict(_METRICS)
