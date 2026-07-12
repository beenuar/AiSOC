"""Phase 5 — the fusion consumer dead-letters poison messages (never drops).

Before Phase 5 the consumer logged a warning and dropped a malformed message —
silent data loss. These tests drive ``FusionWorker._process_message`` directly
(no Kafka) with an in-memory DLQ and prove: a valid event is processed and the
DLQ stays empty; every poison shape is captured in the DLQ with a reason; and a
DLQ that itself fails does not crash the consumer.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.core.config import settings
from app.models.alert import FusionDecision
from app.services.dlq import InMemoryDLQ
from app.workers.consumer import FusionWorker

pytestmark = pytest.mark.asyncio

TENANT = "00000000-0000-0000-0000-000000000001"
RAW_EVENTS = settings.kafka_topic_raw_events
ALERTS_RAW = settings.kafka_topic_alerts_raw


def _valid_raw_event() -> dict:
    return {
        "tenant_id": TENANT,
        "ocsf_event": {
            "class_uid": 2001,
            "category_uid": 2,
            "severity_id": 5,
            "message": "Credential dumping",
            "metadata": {"uid": "ev-1", "product": {"name": "Falcon", "vendor_name": "CrowdStrike"}},
        },
    }


def _worker_with_dlq() -> tuple[FusionWorker, InMemoryDLQ]:
    dlq = InMemoryDLQ()
    engine = SimpleNamespace(
        process=AsyncMock(
            return_value=SimpleNamespace(
                fusion_decision=FusionDecision.NEW_ALERT,
                model_dump=lambda mode="json": {"id": "fused-1"},
            )
        )
    )
    worker = FusionWorker(engine=engine, sink=None, dlq=dlq)
    worker._producer = AsyncMock()  # noqa: SLF001 — test drives the internals
    return worker, dlq


async def test_valid_event_is_processed_and_not_dead_lettered():
    worker, dlq = _worker_with_dlq()
    await worker._process_message(_valid_raw_event(), topic=RAW_EVENTS)  # noqa: SLF001
    assert dlq.records == []
    worker._engine.process.assert_awaited_once()  # noqa: SLF001
    worker._producer.send.assert_awaited_once()  # noqa: SLF001


async def test_missing_ocsf_event_is_dead_lettered_not_dropped():
    worker, dlq = _worker_with_dlq()
    await worker._process_message({"tenant_id": TENANT}, topic=RAW_EVENTS)  # noqa: SLF001
    assert len(dlq.records) == 1
    assert "ocsf_event" in dlq.records[0].reason
    worker._engine.process.assert_not_awaited()  # noqa: SLF001


async def test_unknown_schema_version_is_dead_lettered():
    worker, dlq = _worker_with_dlq()
    poison = _valid_raw_event()
    poison["schema_version"] = "v99"
    await worker._process_message(poison, topic=RAW_EVENTS)  # noqa: SLF001
    assert len(dlq.records) == 1
    assert "unknown schema_version" in dlq.records[0].reason


async def test_non_uuid_tenant_is_dead_lettered_with_lineage():
    worker, dlq = _worker_with_dlq()
    poison = _valid_raw_event()
    poison["tenant_id"] = "not-a-uuid"
    poison["ocsf_event"].pop("tenant_uid", None)
    await worker._process_message(poison, topic=RAW_EVENTS)  # noqa: SLF001
    assert len(dlq.records) == 1
    assert dlq.records[0].source_event_id == "ev-1"


async def test_invalid_raw_alert_is_dead_lettered_not_silently_dropped():
    worker, dlq = _worker_with_dlq()
    # Missing every required RawAlert field — deep Pydantic validation fails.
    await worker._process_message({"tenant_id": TENANT, "nonsense": True}, topic=ALERTS_RAW)  # noqa: SLF001
    assert len(dlq.records) == 1
    assert "RawAlert validation failed" in dlq.records[0].reason
    worker._engine.process.assert_not_awaited()  # noqa: SLF001


async def test_dead_letter_never_crashes_the_consumer_when_sink_fails():
    class ExplodingDLQ:
        async def record(self, dead_letter):  # noqa: ANN001, ARG002
            raise RuntimeError("dlq sink down")

    engine = SimpleNamespace(process=AsyncMock())
    worker = FusionWorker(engine=engine, sink=None, dlq=ExplodingDLQ())
    worker._producer = AsyncMock()  # noqa: SLF001
    # Poison message + failing DLQ: must return cleanly, not raise.
    await worker._process_message({"tenant_id": TENANT}, topic=RAW_EVENTS)  # noqa: SLF001
