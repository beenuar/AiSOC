"""A real replay, against a real broker.

The unit tests drive `replay_from_offset` with fake clients, which proves the
validation, the bounds and the dry-run guarantee but says nothing about the
part most likely to be wrong: assigning a partition, seeking to an offset,
and reading only from there. A consumer that silently reads from the
beginning of the log would pass every unit test in the suite and re-inject
the whole topic in production.

So this seeks past a message and asserts it was not read.

Skips cleanly when no broker is reachable, and says so rather than passing
quietly — a skipped integration test that reads like a pass is how a
never-executed gate stays green.

    docker run -d --name aisoc-5b-redpanda -p 19092:19092 \
        docker.redpanda.com/redpandadata/redpanda:v24.2.7 \
        redpanda start --overprovisioned --smp 1 --memory 512M \
        --node-id 0 --check=false \
        --kafka-addr PLAINTEXT://0.0.0.0:19092 \
        --advertise-kafka-addr PLAINTEXT://127.0.0.1:19092

    AISOC_TEST_KAFKA=127.0.0.1:19092 pytest tests/integration/test_dlq_replay_live.py
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid

import pytest

BROKER = os.getenv("AISOC_TEST_KAFKA", "").strip()
pytestmark = pytest.mark.skipif(not BROKER, reason="set AISOC_TEST_KAFKA=host:port to run the live replay proof")

TOPIC = "aisoc.raw_events"


def _good(uid: str) -> dict:
    return {
        "schema_version": "v1",
        "tenant_id": str(uuid.uuid4()),
        "ocsf_event": {"class_uid": 2001, "metadata": {"uid": uid}},
    }


def _poison() -> dict:
    """Refused for the same reason the pipeline refuses it: no ocsf_event."""
    return {"schema_version": "v1", "tenant_id": str(uuid.uuid4())}


async def _produce(messages: list[dict]) -> list[int]:
    from aiokafka import AIOKafkaProducer

    producer = AIOKafkaProducer(bootstrap_servers=BROKER, value_serializer=lambda v: json.dumps(v).encode())
    await producer.start()
    try:
        return [(await producer.send_and_wait(TOPIC, value=m)).offset for m in messages]
    finally:
        await producer.stop()


@pytest.fixture(autouse=True)
def _point_settings_at_the_test_broker(monkeypatch: pytest.MonkeyPatch):
    from app.core import config

    monkeypatch.setattr(config.settings, "kafka_bootstrap_servers", BROKER)
    yield


@pytest.mark.asyncio
async def test_a_real_replay_seeks_refuses_and_produces() -> None:
    from app.services.dlq_replay import replay_from_offset

    # Three messages: one before the replay window, one poison, one good.
    offsets = await _produce([_good("before-the-window"), _poison(), _good("fixed")])
    before, poison_offset, good_offset = offsets
    await asyncio.sleep(0.5)

    # ── Dry run from the poison offset ───────────────────────────────────
    preview = await replay_from_offset(topic=TOPIC, partition=0, start_offset=poison_offset, max_messages=10, execute=False)

    # The seek actually happened: the message before the window was not read.
    assert preview.messages_read == 2, (
        f"read {preview.messages_read} — the consumer did not honour the seek to {poison_offset} (offset {before} should be excluded)"
    )
    assert preview.refused == 1
    assert preview.would_pass == 1
    assert preview.produced == 0, "a dry run produced a message"

    # ── Execute, and confirm only the valid one lands ────────────────────
    result = await replay_from_offset(topic=TOPIC, partition=0, start_offset=poison_offset, max_messages=10, execute=True)
    assert result.refused == 1, "the poison message was not refused a second time"
    assert result.produced == 1
    assert result.produced_offsets == [good_offset]

    # The replayed message is really on the topic, one past the original tail.
    await asyncio.sleep(0.5)
    tail = await replay_from_offset(topic=TOPIC, partition=0, start_offset=good_offset + 1, max_messages=10, execute=False)
    assert tail.messages_read == 1, "the produced message is not on the topic"
    assert tail.would_pass == 1


@pytest.mark.asyncio
async def test_an_offset_past_the_end_returns_empty_rather_than_hanging() -> None:
    """A typo'd offset must be a fast empty answer, not an indefinite wait."""
    from app.services.dlq_replay import replay_from_offset

    outcome = await asyncio.wait_for(
        replay_from_offset(topic=TOPIC, partition=0, start_offset=10_000_000, max_messages=10, execute=False),
        timeout=30,
    )
    assert outcome.messages_read == 0
    assert outcome.produced == 0
