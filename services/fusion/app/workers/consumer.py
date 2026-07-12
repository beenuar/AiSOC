"""
Kafka consumer worker: reads raw alerts (and, since Phase 3.1, ingest's
normalized OCSF events), runs them through the fusion engine, publishes fused
results back to Kafka, and persists non-duplicate alerts to Postgres.
"""

import json

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer

from app.core.config import settings
from app.models.alert import FusionDecision, RawAlert
from app.services.alert_sink import AlertSink
from app.services.fusion_engine import FusionEngine
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
    "errors": 0,
}


class FusionWorker:
    """Kafka consumer/producer pair that drives the fusion pipeline."""

    def __init__(self, engine: FusionEngine, sink: AlertSink | None = None) -> None:
        self._engine = engine
        self._sink = sink
        self._consumer: AIOKafkaConsumer | None = None
        self._producer: AIOKafkaProducer | None = None
        self._running = False

    @property
    def engine(self) -> FusionEngine:
        return self._engine

    async def start(self) -> None:
        topics = [settings.kafka_topic_alerts_raw]
        if settings.event_promotion_enabled:
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
        self._running = True
        logger.info(
            "Fusion worker started",
            consumer_group=settings.kafka_consumer_group,
            input_topics=topics,
            output_topic=settings.kafka_topic_alerts_fused,
            alert_sink=self._sink is not None,
        )
        await self._consume_loop()

    async def stop(self) -> None:
        self._running = False
        if self._consumer:
            await self._consumer.stop()
        if self._producer:
            await self._producer.stop()
        if self._sink is not None:
            await self._sink.stop()
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

    async def _process_message(self, payload: dict, topic: str | None = None) -> None:
        if topic == settings.kafka_topic_raw_events:
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
                logger.warning("Invalid alert payload", error=str(exc))
                _METRICS["errors"] += 1
                return

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
