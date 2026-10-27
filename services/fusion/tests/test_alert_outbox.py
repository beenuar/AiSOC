"""An acknowledged message must never leave an alert row without a notification.

The gap these pin
-----------------
``_fuse_and_persist`` persists first and publishes second, and the consumer
commits the input offset only after the message is handled. Two orderings
follow, and before this change only one of them recovered:

* Crash between the durable row and the publish -- the offset never moved, so
  Kafka re-delivers and the publish is retried. Covered already.
* The publish fails until the retry budget runs out -- the message is then
  dead-lettered, which is a durable capture, so the **offset commits**. The
  alert row exists, the offset is past the source event, and nothing will ever
  publish the envelope. A dead letter is a triage record; nothing re-drives it.

The second case is permanent loss of the notification for an alert that is
sitting in Postgres, which is how an alert becomes invisible to auto-triage
with every surface reporting success.

The SQL itself is covered against a real Postgres in
``tests/integration/test_alert_outbox_live.py``. These drive the worker and
the relay over an in-memory journal that implements the same contract, so the
*decisions* -- journal before acknowledging, clear on a duplicate, recover on
restart -- are pinned without a container.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from app.core.config import settings
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_outbox import NotificationRelay, PendingNotification
from app.services.alert_sink import PersistOutcome, PersistResult
from app.services.dlq import InMemoryDLQ
from app.workers.consumer import FusionWorker
from tests.kafka_doubles import TwoStageProducer

TENANT = "00000000-0000-0000-0000-000000000001"


class InMemoryOutbox:
    """The journal contract, in memory.

    Deliberately not a mock: ``record`` returning False is a decision the
    worker must act on, and a mock that answers True to everything would make
    the unrecoverable case untestable.
    """

    def __init__(self, *, writable: bool = True) -> None:
        self.rows: dict[tuple[str, str], PendingNotification] = {}
        self.writable = writable
        self.cleared: list[tuple[str, str]] = []
        self._next_id = 1

    @property
    def available(self) -> bool:
        return self.writable

    async def record(self, *, tenant_id, alert_id, topic, key, payload, error) -> bool:  # noqa: ANN001
        if not self.writable:
            return False
        existing = self.rows.get((tenant_id, alert_id))
        attempts = existing.attempts + 1 if existing else 1
        self.rows[(tenant_id, alert_id)] = PendingNotification(
            id=existing.id if existing else self._next_id,
            tenant_id=tenant_id,
            alert_id=alert_id,
            topic=topic,
            key=key,
            payload=payload,
            attempts=attempts,
        )
        if existing is None:
            self._next_id += 1
        return True

    async def clear(self, *, tenant_id, alert_id) -> None:  # noqa: ANN001
        self.cleared.append((tenant_id, alert_id))
        self.rows.pop((tenant_id, alert_id), None)

    async def claim(self, *, limit, lease_seconds, grace_seconds) -> list[PendingNotification]:  # noqa: ANN001, ARG002
        return list(self.rows.values())[:limit]

    async def resolve(self, ids) -> None:  # noqa: ANN001
        for key, row in list(self.rows.items()):
            if row.id in ids:
                del self.rows[key]

    async def record_attempt_failed(self, outbox_id, error) -> None:  # noqa: ANN001, ARG002
        return None

    async def backlog(self) -> tuple[int | None, float | None]:
        return len(self.rows), (0.0 if self.rows else None)


def _alert() -> RawAlert:
    return RawAlert(
        tenant_id=TENANT,
        source="CrowdStrike Falcon",
        title="Credential dumping via LSASS access",
        severity=AlertSeverity.CRITICAL,
        src_ip="10.20.30.40",
        hostname="WIN-DC01",
    )


def _worker(producer, outbox, *, outcome=PersistOutcome.INSERTED):  # noqa: ANN001, ANN201
    alert = _alert()
    alert.id = alert.deterministic_id()
    fused = FusedAlert(id=alert.id, tenant_id=alert.tenant_id, fusion_decision=FusionDecision.NEW_ALERT, alert=alert)
    worker = FusionWorker(
        engine=SimpleNamespace(process=AsyncMock(return_value=fused)),
        sink=AsyncMock(),
        dlq=InMemoryDLQ(),
        outbox=outbox,
    )
    worker._sink.persist = AsyncMock(return_value=PersistResult(outcome, str(fused.id)))  # noqa: SLF001
    worker._producer = producer  # noqa: SLF001
    worker._running = True  # noqa: SLF001
    worker._stop_event.clear()  # noqa: SLF001
    return worker, alert


def _msg(offset: int = 0) -> SimpleNamespace:
    """A record that genuinely reaches the publish.

    The whole point is the ordering between a durable row and its
    notification, so the message has to travel the real promotion path
    rather than being short-circuited into ``_fuse_and_persist``.
    """
    return SimpleNamespace(
        value={
            "tenant_id": TENANT,
            "ocsf_event": {
                "class_uid": 2001,
                "category_uid": 2,
                "severity_id": 5,
                "message": "Credential dumping",
                "metadata": {"uid": "ev-1", "product": {"name": "Falcon", "vendor_name": "CrowdStrike"}},
            },
        },
        topic=settings.kafka_topic_raw_events,
        partition=0,
        offset=offset,
    )


@pytest.mark.asyncio
async def test_an_undelivered_notification_is_recoverable_once_the_offset_commits(monkeypatch):
    """The acceptance case. Retries exhaust, the message is acknowledged, and
    the alert must still be deliverable afterwards.

    ``_handle_message`` returning True is what lets the consume loop commit
    the offset. After that point Kafka will never hand this record over
    again, so if the journal is empty here the alert's notification is gone
    for good while the alert row sits in Postgres looking fine.
    """
    monkeypatch.setattr(settings, "consumer_max_retries", 1)
    monkeypatch.setattr(settings, "consumer_retry_base_seconds", 0.0)
    monkeypatch.setattr(settings, "consumer_retry_max_seconds", 0.0)
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 1.0)

    outbox = InMemoryOutbox()
    producer = TwoStageProducer(ack_error=RuntimeError("broker refused the record"))
    worker, alert = _worker(producer, outbox)

    acknowledged = await worker._handle_message(_msg())  # noqa: SLF001

    assert acknowledged is True, "a dead-lettered message is acknowledged; that is the existing contract"
    assert len(outbox.rows) == 1, "the offset is about to commit and nothing can re-deliver this alert"
    pending = next(iter(outbox.rows.values()))
    assert pending.alert_id == str(alert.id)
    assert pending.key == str(alert.id)
    assert pending.payload["alert_row_id"] == str(alert.id)
    await producer.drain()


@pytest.mark.asyncio
async def test_the_dead_letter_says_the_notification_is_the_thing_that_was_lost(monkeypatch):
    """A journal that cannot be written must not read as an ordinary retry.

    The alert row is durable, so an operator looking for a missing alert
    finds one and concludes the pipeline is healthy. The reason has to name
    the notification.
    """
    monkeypatch.setattr(settings, "consumer_max_retries", 0)
    monkeypatch.setattr(settings, "consumer_retry_base_seconds", 0.0)
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 1.0)

    outbox = InMemoryOutbox(writable=False)
    producer = TwoStageProducer(ack_error=RuntimeError("broker refused the record"))
    worker, _ = _worker(producer, outbox)

    before = worker.get_metrics()["notifications_unrecoverable"]
    assert await worker._handle_message(_msg()) is True  # noqa: SLF001

    assert worker.get_metrics()["notifications_unrecoverable"] == before + 1
    captured = worker._dlq.records  # noqa: SLF001
    assert len(captured) == 1
    assert "notification was neither published nor journalled" in captured[0].reason
    await producer.drain()


@pytest.mark.asyncio
async def test_the_relay_delivers_a_journalled_notification(monkeypatch):
    """Restart recovery: a pending row becomes a real published record."""
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 1.0)
    outbox = InMemoryOutbox()
    failing = TwoStageProducer(ack_error=RuntimeError("broker down"))
    worker, alert = _worker(failing, outbox)
    monkeypatch.setattr(settings, "consumer_max_retries", 0)
    monkeypatch.setattr(settings, "consumer_retry_base_seconds", 0.0)
    await worker._handle_message(_msg())  # noqa: SLF001
    await failing.drain()
    assert len(outbox.rows) == 1

    # The broker comes back. A new producer stands in for the restart.
    healthy = TwoStageProducer()
    worker._producer = healthy  # noqa: SLF001
    relay = NotificationRelay(outbox, worker._publish_recovered, grace_seconds=0.0)  # noqa: SLF001

    delivered = await relay.drain_once()

    assert delivered == 1
    assert outbox.rows == {}, "a delivered notification must leave the journal"
    assert len(healthy.enqueued) == 1
    assert healthy.enqueued[0]["key"] == str(alert.id)
    assert healthy.futures[0].done(), "the relay must wait for the broker like the inline path does"
    assert worker.get_metrics()["notifications_recovered"] >= 1
    await healthy.drain()


@pytest.mark.asyncio
async def test_the_relay_leaves_the_row_pending_when_the_broker_is_still_down(monkeypatch):
    """A failed recovery attempt must not look like a delivery."""
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 1.0)
    outbox = InMemoryOutbox()
    await outbox.record(
        tenant_id=TENANT, alert_id=str(_alert().deterministic_id()), topic="t", key="k", payload={"id": "x"}, error="first failure"
    )
    producer = TwoStageProducer(ack_error=RuntimeError("still down"))
    worker, _ = _worker(producer, outbox)
    relay = NotificationRelay(outbox, worker._publish_recovered, grace_seconds=0.0)  # noqa: SLF001

    delivered = await relay.drain_once()

    assert delivered == 0
    assert len(outbox.rows) == 1, "an undelivered notification must stay pending"
    assert relay.failures == 1
    await producer.drain()


@pytest.mark.asyncio
async def test_a_duplicate_clears_a_journal_row_an_inline_retry_already_delivered(monkeypatch):
    """The relay must not republish what a retry has already published.

    DUPLICATE is the one persist outcome meaning the alert already existed,
    so it is the only path where an earlier attempt can have journalled it.
    """
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 1.0)
    outbox = InMemoryOutbox()
    producer = TwoStageProducer()
    worker, alert = _worker(producer, outbox, outcome=PersistOutcome.DUPLICATE)
    await outbox.record(
        tenant_id=TENANT, alert_id=str(alert.id), topic="t", key=str(alert.id), payload={"id": "x"}, error="earlier failure"
    )

    await worker._fuse_and_persist(alert)  # noqa: SLF001

    assert outbox.rows == {}, "the retry delivered it; the relay must not send it again"
    assert (TENANT, str(alert.id)) in outbox.cleared
    await producer.drain()


@pytest.mark.asyncio
async def test_an_inserted_alert_does_not_touch_the_journal(monkeypatch):
    """The happy path pays nothing.

    A new alert cannot have a pending journal row, so clearing one would be
    a round trip per alert for an outcome that is impossible.
    """
    monkeypatch.setattr(settings, "kafka_send_timeout_seconds", 1.0)
    outbox = InMemoryOutbox()
    producer = TwoStageProducer()
    worker, alert = _worker(producer, outbox, outcome=PersistOutcome.INSERTED)

    await worker._fuse_and_persist(alert)  # noqa: SLF001

    assert outbox.cleared == []
    assert outbox.rows == {}
    await producer.drain()
