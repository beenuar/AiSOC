"""Native ClickHouse regressions; opt in with AISOC_TEST_CLICKHOUSE=1.

Uses the configured raw_events schema, a connection-local temporary table,
and pytest's temporary spool. No rows are inserted into the production lake.
"""

from __future__ import annotations

import asyncio
import os
import threading
import uuid

import pytest
from app.core.config import settings
from app.services import lake_writer
from clickhouse_driver import Client

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(os.getenv("AISOC_TEST_CLICKHOUSE") != "1", reason="requires an explicit ClickHouse test opt-in"),
]


@pytest.mark.parametrize("cancel", [False, True], ids=["concurrent", "cancelled"])
async def test_native_flush_has_one_owner(tmp_path, monkeypatch, cancel):
    client = Client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        database=settings.clickhouse_database,
        user=settings.clickhouse_user,
        password=settings.clickhouse_password,
    )
    started, release = threading.Event(), threading.Event()
    calls = []
    tasks = []

    class GatedClient:
        def execute(self, sql, rows, **kwargs):
            calls.append(len(rows))
            if len(calls) == 1:
                started.set()
                assert release.wait(5), "test insertion release timed out"
            return client.execute(sql, rows, **kwargs)

    try:
        client.execute("CREATE TEMPORARY TABLE lake_flush_regression AS aisoc.raw_events")
        monkeypatch.setattr(lake_writer, "_INSERT_SQL", lake_writer._INSERT_SQL.replace("aisoc.raw_events", "lake_flush_regression"))
        writer = lake_writer.LakeWriter(host="unused", spool_dir=str(tmp_path / "spool"), batch_size=100, client_factory=GatedClient)
        await writer.start()
        tenant = str(uuid.uuid4())
        for _ in range(2):
            event_id = str(uuid.uuid4())
            assert await writer.write_event(
                {
                    "id": event_id,
                    "tenant_id": tenant,
                    "ocsf_event": {
                        "tenant_uid": tenant,
                        "class_uid": 4001,
                        "category_uid": 4,
                        "severity_id": 2,
                        "time": "2026-01-01T00:00:00Z",
                        "metadata": {"uid": event_id, "product": {"name": "isolated-writer-test"}},
                    },
                }
            )
        first = asyncio.create_task(writer.flush())
        tasks.append(first)
        assert await asyncio.to_thread(started.wait, 3)
        if cancel:
            first.cancel()
        second = asyncio.create_task(writer.flush())
        tasks.append(second)
        await asyncio.sleep(0.1)
        early_calls = len(calls)
        release.set()
        results = await asyncio.gather(*tasks, return_exceptions=True)
        assert early_calls == 1, "concurrent flushes entered the same native connection"
        if cancel:
            assert isinstance(results[0], asyncio.CancelledError)
        else:
            assert results[0] is None
        assert results[1] is None
        count, unique = client.execute("SELECT count(), uniqExact(event_id) FROM lake_flush_regression")[0]
        assert unique == 2
        assert writer._spool.rows_on_disk() == 0
        if not cancel:
            assert count == 2, "concurrent flushes archived the same batch twice"
        # Cancellation can replay a completed insert; stable identities make
        # those physical duplicates collapsible by the existing read contract.
    finally:
        release.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        client.disconnect()
