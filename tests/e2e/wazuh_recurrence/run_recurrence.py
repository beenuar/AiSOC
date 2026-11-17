#!/usr/bin/env python3
"""Distinct Wazuh documents survive the real ingest/fusion transport.

Run only against a disposable test stack. This creates a synthetic tenant,
submits three test documents through authenticated HTTP, observes Kafka's
fused notifications, and checks the database after each notification. No
alert is inserted by the test, and neither normalizer is reimplemented.

Generate the input using the connectors service's locked environment::

    PYTHONPATH=services/connectors python tests/e2e/wazuh_recurrence/run_recurrence.py \
        --emit-fixtures > /tmp/wazuh-recurrence.json

Then run in the fusion service's locked environment against the running
ingest, Kafka, Redis and Postgres services::

    python tests/e2e/wazuh_recurrence/run_recurrence.py \
        --fixtures /tmp/wazuh-recurrence.json --ingest-url http://localhost:8081

The verifier uses DATABASE_URL, REDIS_URL, KAFKA_BOOTSTRAP_SERVERS and
AISOC_SERVICE_TOKEN (or AISOC_INGEST_TOKEN), matching the deployed services.
The Redis URL must name fusion's database. Only this test tenant's cache
keys are expired; the two timestamps are more than 24 hours apart without
making CI wait a day for the same cache state.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def emit_fixtures() -> None:
    """Use the production connector, before Go sees the canonical envelope."""
    from app.connectors.wazuh import WazuhConnector

    run_id = uuid.uuid4().hex
    title = f"Synthetic Wazuh recurrence [{run_id}]"
    connector = WazuhConnector("https://indexer.invalid", "test", "test")
    timestamps = ["2026-11-16T02:57:34.421Z", "2026-11-16T02:58:00.000Z", "2026-11-17T03:11:51.099Z"]
    events = []
    for number, timestamp in enumerate(timestamps, 1):
        hit = {
            "_id": f"{run_id}-document-{number}",
            "_index": "wazuh-alerts-4.x-test",
            "_source": {
                "@timestamp": timestamp,
                "agent": {"id": "002", "name": f"recurrence-{run_id[:12]}"},
                "rule": {"id": "110300", "level": 12, "description": title, "groups": ["test"]},
                "full_log": "Synthetic HTTP authentication failure: 401",
                "is_synthetic": True,
            },
        }
        events.append(connector.normalize(hit))
    original_replay_title = f"{title} original replay"
    original_replay_hit = {
        "_id": f"{run_id}-original-only",
        "_index": "wazuh-alerts-4.x-test",
        "_source": {
            "@timestamp": timestamps[0],
            "agent": {"id": "002", "name": f"recurrence-{run_id[:12]}"},
            "rule": {"id": "110301", "level": 12, "description": original_replay_title, "groups": ["test"]},
            "full_log": "Synthetic HTTP authentication failure: 401",
            "is_synthetic": True,
        },
    }
    print(
        json.dumps(
            {
                "tenant_id": str(uuid.uuid4()),
                "connector_id": str(uuid.uuid4()),
                "title": title,
                "timestamps": timestamps,
                "events": events,
                "original_replay_title": original_replay_title,
                "original_replay_event": connector.normalize(original_replay_hit),
            }
        )
    )


def _required(name: str, fallback: str = "") -> str:
    value = os.environ.get(name, fallback).strip()
    if not value:
        raise RuntimeError(f"{name} must be set for the disposable test stack")
    return value


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


async def verify(fixtures: dict[str, Any], ingest_url: str, timeout: float) -> None:
    import asyncpg
    import httpx
    import redis.asyncio as aioredis
    from aiokafka import AIOKafkaConsumer

    tenant = uuid.UUID(fixtures["tenant_id"])
    title = fixtures["title"]
    dsn = _required("DATABASE_URL").replace("postgresql+asyncpg://", "postgresql://", 1)
    token = _required("AISOC_INGEST_TOKEN", os.environ.get("AISOC_SERVICE_TOKEN", ""))
    redis = aioredis.from_url(_required("REDIS_URL"))
    conn = await asyncpg.connect(dsn)
    consumer = AIOKafkaConsumer(
        os.environ.get("KAFKA_TOPIC_ALERTS_FUSED", "aisoc.alerts.fused"),
        bootstrap_servers=_required("KAFKA_BOOTSTRAP_SERVERS"),
        group_id=None,
        auto_offset_reset="latest",
        enable_auto_commit=False,
        value_deserializer=lambda value: json.loads(value.decode()),
    )
    await consumer.start()
    # Resolve positions before HTTP writes so auto_offset_reset=latest cannot
    # move past a fast reply when getone() runs for the first time.
    await consumer.getmany(timeout_ms=100)
    cache_keys: set[str] = set()
    created = False
    try:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
            tenant,
            f"Synthetic recurrence test {tenant}",
            f"recurrence-{tenant.hex}",
        )
        created = True
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:

            async def deliver(number: int) -> dict[str, Any]:
                response = await client.post(
                    f"{ingest_url.rstrip('/')}/v1/ingest/batch",
                    headers={"Authorization": f"Bearer {token}", "X-Tenant-ID": str(tenant)},
                    json={
                        "connector_id": fixtures["connector_id"],
                        "connector_type": "wazuh",
                        "source_format": "json",
                        "events": [fixtures["events"][number]],
                    },
                )
                assert response.status_code == 200, f"ingest refused the test event: HTTP {response.status_code}: {response.text}"
                assert response.json()["accepted"] == 1, response.text
                async with asyncio.timeout(timeout):
                    while True:
                        record = await consumer.getone()
                        envelope = record.value
                        if envelope.get("tenant_id") == str(tenant) and envelope.get("alert", {}).get("title") == title:
                            assert envelope["persist_outcome"] in {"inserted", "duplicate"}, envelope
                            if envelope.get("incident_id"):
                                cache_keys.add(f"aisoc:fusion:incident:{envelope['incident_id']}")
                            return envelope

            async def state() -> Any:
                rows = await conn.fetch(
                    """SELECT a.id, a.dedup_hash, a.event_time, a.created_at,
                              a.first_seen, a.last_seen, a.source_event_ids,
                              COALESCE(o.occurrence_count, 1) AS occurrence_count,
                              o.first_seen AS occurrence_first_seen, o.last_seen AS occurrence_last_seen,
                              o.payload_ids
                         FROM alerts a
                         LEFT JOIN alert_occurrences o ON o.tenant_id = a.tenant_id AND o.alert_id = a.id
                        WHERE a.tenant_id = $1 AND a.title = $2""",
                    tenant,
                    title,
                )
                assert len(rows) == 1, f"expected one surviving alert, found {len(rows)}"
                return rows[0]

            first = await deliver(0)
            initial = await state()
            assert initial["occurrence_count"] == 1, dict(initial)
            dedup_key = f"aisoc:fusion:dedup:{initial['dedup_hash']}"
            cache_keys.add(dedup_key)
            assert await redis.exists(dedup_key), "first alert never registered the real Redis dedup key"

            second = await deliver(1)
            after_second = await state()
            assert second["fusion_decision"] == "duplicate", "the warm Redis cache path was not exercised"
            assert after_second["occurrence_count"] == 2, dict(after_second)
            print("[PASS] two Wazuh documents became one alert with two occurrences (warm Redis)", flush=True)

            # Actual expiry, scoped to this tenant: the late recurrence must
            # enter the Postgres fallback with both Redis windows absent.
            async for key in redis.scan_iter(match=f"aisoc:fusion:correlation:{tenant}:*"):
                cache_keys.add(key.decode())
            if first.get("incident_id"):
                cache_keys.add(f"aisoc:fusion:incident:{first['incident_id']}")
            for key in cache_keys:
                await redis.pexpire(key, 1)
            async with asyncio.timeout(timeout):
                while await redis.exists(*cache_keys):
                    await asyncio.sleep(0.01)

            third = await deliver(2)
            after_third = await state()
            assert third["fusion_decision"] == "new_incident", "expired Redis caches did not exercise the insert fallback"
            assert third["persist_outcome"] == "duplicate", "Postgres did not resolve the surviving alert"
            assert after_third["occurrence_count"] == 3, (
                f"three distinct Wazuh documents counted as {after_third['occurrence_count']}; "
                "a rule id must not become the source-event replay key"
            )
            ids = [item["alert"]["source_event_ids"][0] for item in (first, second, third)]
            assert len(set(ids)) == 3, f"Go ingest assigned colliding event ids: {ids}"
            assert {item["alert_row_id"] for item in (first, second, third)} == {str(initial["id"])}, "surviving alert id changed"
            print("[PASS] next-day Wazuh recurrence counted as three after both Redis windows expired", flush=True)

            first_time, _, latest_time = [datetime.fromisoformat(value.replace("Z", "+00:00")) for value in fixtures["timestamps"]]
            assert first_time.tzinfo == UTC
            assert after_third["first_seen"] == after_third["occurrence_first_seen"] == first_time, dict(after_third)
            assert after_third["last_seen"] == after_third["occurrence_last_seen"] == latest_time, dict(after_third)
            assert after_third["event_time"] == initial["event_time"], "recurrence rewrote the original event time"
            assert after_third["created_at"] == initial["created_at"], "recurrence rewrote creation time"
            assert set(ids) <= set(_json(after_third["source_event_ids"])), dict(after_third)
            print("[PASS] alert and occurrence windows agree; original event and creation times are preserved", flush=True)

            for number in (0, 1, 2, 2):
                replay = await deliver(number)
                assert replay["alert"]["source_event_ids"][0] == ids[number], "a replay minted a new source-event id"
                after_replay = await state()
                assert after_replay["occurrence_count"] == 3, dict(after_replay)
                assert after_replay["last_seen"] == latest_time, dict(after_replay)
            print("[PASS] replays of original and repeated documents leave the count and latest time unchanged", flush=True)

            # A separate alert tests an original replay before any genuine
            # repeat, without letting that earlier defect hide the main
            # three-document recurrence assertion above.
            title = fixtures["original_replay_title"]
            fixtures["events"][0] = fixtures["original_replay_event"]
            original = await deliver(0)
            assert original["persist_outcome"] == "inserted", original
            await deliver(0)
            after_original_replay = await state()
            assert after_original_replay["occurrence_count"] == 1, dict(after_original_replay)
            cache_keys.add(f"aisoc:fusion:dedup:{after_original_replay['dedup_hash']}")
            print("[PASS] replaying an original before any recurrence does not invent a second occurrence", flush=True)
    finally:
        await consumer.stop()
        if created:
            await conn.execute("DELETE FROM tenants WHERE id = $1", tenant)
        async for key in redis.scan_iter(match=f"aisoc:fusion:correlation:{tenant}:*"):
            cache_keys.add(key.decode())
        if cache_keys:
            await redis.delete(*cache_keys)
        await redis.aclose()
        await conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-fixtures", action="store_true")
    parser.add_argument("--fixtures", type=Path)
    parser.add_argument("--ingest-url", default=os.environ.get("AISOC_INGEST_URL", "http://localhost:8081"))
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()
    if args.emit_fixtures:
        emit_fixtures()
        return 0
    if args.fixtures is None:
        parser.error("--fixtures is required unless --emit-fixtures is used")
    fixtures = json.loads(args.fixtures.read_text(encoding="utf-8"))
    asyncio.run(verify(fixtures, args.ingest_url, args.timeout))
    return 0


if __name__ == "__main__":
    sys.exit(main())
