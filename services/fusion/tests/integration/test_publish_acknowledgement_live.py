"""Fused-alert delivery, against a real broker.

``tests/test_publish_acknowledgement.py`` proves the worker waits for the
future its double hands back. What it cannot prove is that a *real*
``AIOKafkaProducer`` behaves the way the double models it -- that ``send``
returns before the record is delivered, and that the delivery outcome is only
in the returned future. That is the premise the whole fix rests on, so it is
worth asserting against a broker rather than against a transcription of the
documentation.

The second test is the one that matters most and the one no double can
really stand in for: a record sent to a topic the broker will refuse. The
enqueue succeeds, the refusal arrives afterwards, and only code that awaits
the future ever learns about it.

Skips cleanly when no broker is reachable, and says so rather than passing
quietly.

    docker run -d --name aisoc-p4-redpanda -p 59092:9092 \\
        docker.redpanda.com/redpandadata/redpanda:v24.2.7 \\
        redpanda start --mode dev-container --smp 1 --memory 1G \\
        --kafka-addr PLAINTEXT://0.0.0.0:9092 \\
        --advertise-kafka-addr PLAINTEXT://127.0.0.1:59092

    AISOC_TEST_KAFKA=127.0.0.1:59092 pytest tests/integration/test_publish_acknowledgement_live.py
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from app.core.config import settings
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_sink import PersistOutcome, PersistResult
from app.workers.consumer import FusionWorker, RetryableProcessingError

BROKER = os.getenv("AISOC_TEST_KAFKA", "").strip()
pytestmark = pytest.mark.skipif(not BROKER, reason="set AISOC_TEST_KAFKA=host:port to run the live delivery proof")


#: Bigger than a broker's default 1 MiB ``max.message.bytes``, and the whole
#: point of raising it. aiokafka checks ``max_request_size`` *itself*, inside
#: ``send``, and raises there — which is an enqueue-stage failure that the
#: original code caught perfectly well. Leaving the client limit at its
#: default produced a live test that passed against the defect: see the
#: refusal test below. Raising it past the broker's limit is what moves the
#: rejection to where the defect actually lives.
_CLIENT_REQUEST_LIMIT = 8 * 1024 * 1024


@pytest_asyncio.fixture
async def producer():  # noqa: ANN201
    aiokafka = pytest.importorskip("aiokafka")
    client = aiokafka.AIOKafkaProducer(
        bootstrap_servers=BROKER,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: None if k is None else str(k).encode("utf-8"),
        max_request_size=_CLIENT_REQUEST_LIMIT,
    )
    await client.start()
    yield client
    await client.stop()


def _worker(producer, topic: str):  # noqa: ANN001, ANN202
    alert = RawAlert(
        tenant_id="00000000-0000-0000-0000-000000000001",
        source="CrowdStrike Falcon",
        title="Credential dumping via LSASS access",
        severity=AlertSeverity.CRITICAL,
        src_ip="10.20.30.40",
        hostname="WIN-DC01",
    )
    alert.id = alert.deterministic_id()
    fused = FusedAlert(id=alert.id, tenant_id=alert.tenant_id, fusion_decision=FusionDecision.NEW_ALERT, alert=alert)
    worker = FusionWorker(engine=SimpleNamespace(process=AsyncMock(return_value=fused)), sink=AsyncMock())  # type: ignore[arg-type]
    worker._sink.persist = AsyncMock(return_value=PersistResult(PersistOutcome.INSERTED, str(fused.id)))  # type: ignore[method-assign, union-attr]  # noqa: SLF001
    worker._producer = producer  # noqa: SLF001
    return worker, alert


@pytest.mark.asyncio
async def test_a_real_producer_returns_before_the_record_is_delivered(producer, monkeypatch):  # noqa: ANN001
    """The premise, measured rather than quoted.

    If ``send`` resolved only once the broker had the record, the original
    code would have been correct and there would be nothing to fix. It does
    not: the coroutine returns as soon as the record is in the accumulator,
    and the delivery result is in the future it hands back.
    """
    topic = f"aisoc-p4-live-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(settings, "kafka_topic_alerts_fused", topic)

    future = await producer.send(topic, value={"probe": True}, key="k")
    enqueued_but_undelivered = not future.done()
    metadata = await future

    assert enqueued_but_undelivered, "send resolved only after delivery; the two-stage premise would not hold"
    assert metadata.topic == topic


@pytest.mark.asyncio
async def test_a_fused_alert_reaches_the_broker_under_its_alert_id(producer, monkeypatch):  # noqa: ANN001
    """The happy path end to end: published, acknowledged, and keyed."""
    aiokafka = pytest.importorskip("aiokafka")
    topic = f"aisoc-p4-live-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(settings, "kafka_topic_alerts_fused", topic)
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 20.0)
    worker, alert = _worker(producer, topic)

    await worker._fuse_and_persist(alert)  # noqa: SLF001

    consumer = aiokafka.AIOKafkaConsumer(topic, bootstrap_servers=BROKER, auto_offset_reset="earliest", group_id=None)
    await consumer.start()
    try:
        record = await asyncio.wait_for(consumer.getone(), timeout=20.0)
    finally:
        await consumer.stop()

    assert record.key.decode() == str(alert.id), "every copy of one alert must carry one key"
    body = json.loads(record.value.decode())
    assert body["alert_row_id"] == str(alert.id)
    assert body["persist_outcome"] == "inserted"


@pytest.mark.asyncio
async def test_a_refusal_that_arrives_after_the_enqueue_is_reported(producer, monkeypatch):  # noqa: ANN001
    """The defect, reproduced against a real broker.

    A record between the client's request limit and the broker's message
    limit is accepted into the accumulator and refused on delivery. Code
    that awaits only the enqueue returns cleanly here, the consumer commits
    the input offset, and the alert row sits in Postgres with nothing ever
    published for it.

    The first version of this test used the *default* ``max_request_size``
    and a 2 MiB record, and it passed against the defect. aiokafka enforces
    that limit itself, inside ``send``, so the rejection happened at the
    enqueue -- which the original code caught, correctly, because an
    enqueue-stage exception was the one failure it could see. A live test
    exercising the wrong stage is worse than no live test, so the client
    limit is raised past the broker's and the negative control is what
    established that it now discriminates.
    """
    topic = f"aisoc-p4-live-{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(settings, "kafka_topic_alerts_fused", topic)
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 20.0)
    worker, alert = _worker(producer, topic)
    # Comfortably inside the 8 MiB client limit and comfortably past the
    # broker's 1 MiB one, so the enqueue succeeds and the broker refuses.
    alert.description = "A" * (3 * 1024 * 1024)

    before = worker.get_metrics()["publish_failed"]
    with pytest.raises(RetryableProcessingError):
        await worker._fuse_and_persist(alert)  # noqa: SLF001

    assert worker.get_metrics()["publish_failed"] == before + 1
