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
from app.services.alert_sink import AlertSink
from app.services.dlq import DeadLetter, DeadLetterQueue, LoggingDLQ, safe_record
from app.services.event_schema import validate_event
from app.services.fusion_engine import FusionEngine
from app.services.lake_writer import LakeWriter
from app.services.promoter import promote_normalized_event

logger = structlog.get_logger()

_METRICS = {
    "processed": 0,
    "duplicates": 0,
    "correlated": 0,
    "new_incidents": 0,
    "promoted": 0,
    "not_promoted": 0,
    "persisted": 0,
    "laked": 0,
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
    ) -> None:
        self._engine = engine
        self._sink = sink
        self._lake = lake
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
        if settings.event_promotion_enabled or self._lake is not None:
            topics.append(settings.kafka_topic_raw_events)
        self._consumer = AIOKafkaConsumer(
            *topics,
            bootstrap_servers=settings.kafka_bootstrap_servers,
            group_id=settings.kafka_consumer_group,
            auto_offset_reset="latest",
            enable_auto_commit=True,
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
                await self._flush_task
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

            # Ingest-normalized OCSF event — run the deterministic promotion
            # policy (see app/services/promoter.py). Non-promoted events are
            # dropped here by design; the detect stage owns rule evaluation.
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

        # Lineage — trace each fused alert back to its source event + schema.
        logger.debug(
            "fusion.lineage",
            topic=resolved_topic,
            schema_version=validation.schema_version,
            source_event_id=validation.source_event_id,
        )

        fused = await self._engine.process(alert)
        _METRICS["processed"] += 1

        if fused.fusion_decision == FusionDecision.DUPLICATE:
            _METRICS["duplicates"] += 1
        elif fused.fusion_decision == FusionDecision.CORRELATED:
            _METRICS["correlated"] += 1
        else:
            _METRICS["new_incidents"] += 1

        # Publish fused alert (even duplicates, so downstream can track)
        await self._producer.send(
            settings.kafka_topic_alerts_fused,
            value=fused.model_dump(mode="json"),
        )

        # Persist to the alert store (Phase 3.1). Fail-soft + idempotent —
        # see app/services/alert_sink.py. Duplicates are skipped inside.
        if self._sink is not None:
            if await self._sink.persist(fused) is not None:
                _METRICS["persisted"] += 1

    @staticmethod
    def get_metrics() -> dict:
        return dict(_METRICS)
