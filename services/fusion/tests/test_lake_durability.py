"""Lake archival must have a recovery boundary of its own.

The defect these pin
--------------------
``LakeWriter.write_event`` appends to ``self._buffer`` -- a plain list -- and
returns ``True``. Its own docstring admits that True means "accepted for
archival, not that it is already durable". The consumer uses that return only
to bump a counter and commits the input Kafka offset regardless, so the offset
advances on the strength of an in-memory list.

Three consequences, all of them silent:

* A hard kill loses the whole buffer. ``stop()`` is honest and counts retained
  rows as dropped, but SIGKILL does not run ``stop()``.
* ``_enforce_buffer_capacity`` discards the **oldest** rows on overflow. It
  says so loudly, but their offsets were committed long before, so nothing
  can replay them.
* Archival rides entirely on the fusion consumer-group offset. There is no
  lake checkpoint and no spool, so "the lake is behind" and "the lake has a
  permanent hole" are indistinguishable.

The machinery for recovery already exists and nothing triggers it:
``_fallback_event_id`` derives a replay-stable id from the Kafka coordinates
and the table is read with ``LIMIT 1 BY event_id``, so a replay *would*
deduplicate. The missing half is a reason to replay.

Raising ``max_buffer_rows`` is not a fix and these tests are written so that
it cannot pass as one: the capacity case asserts back-pressure, not headroom.
"""

from __future__ import annotations

import json
import uuid

import pytest
from app.services.lake_writer import LakeWriter

TENANT = "00000000-0000-0000-0000-000000000001"


def _event(uid: str = "ev-1") -> dict:
    return {
        "tenant_id": TENANT,
        "id": uid,
        "ocsf_event": {
            "tenant_uid": TENANT,
            "class_uid": 4001,
            "category_uid": 4,
            "severity_id": 2,
            "time": "2026-10-27T00:00:00Z",
            "metadata": {"uid": uid, "product": {"name": "Falcon"}},
        },
    }


class _DownClickHouse:
    """A server that is unreachable, the way the driver reports it."""

    def __init__(self) -> None:
        self.inserted: list[dict] = []

    def execute(self, sql, rows=None, **kwargs):  # noqa: ANN001, ANN201, ARG002
        raise ConnectionError("connection refused")

    def disconnect(self) -> None:
        return None


class _UpClickHouse:
    def __init__(self) -> None:
        self.inserted: list[dict] = []

    def execute(self, sql, rows=None, **kwargs):  # noqa: ANN001, ANN201, ARG002
        self.inserted.extend(rows or [])
        return []

    def disconnect(self) -> None:
        return None


def _writer(tmp_path, client, **kwargs):  # noqa: ANN001, ANN201
    return LakeWriter(
        host="localhost",
        batch_size=kwargs.pop("batch_size", 2),
        client_factory=lambda: client,
        spool_dir=str(tmp_path / "spool"),
        **kwargs,
    )


@pytest.mark.asyncio
async def test_an_accepted_event_is_on_disk_before_the_offset_can_commit(tmp_path):
    """``write_event`` returning True must mean "survives this process".

    The consumer commits the input offset after this returns. If True only
    means "appended to a list", the offset has moved for an event that exists
    nowhere but RAM.
    """
    writer = _writer(tmp_path, _DownClickHouse(), batch_size=50)
    await writer.start()

    assert await writer.write_event(_event("ev-1"), topic="aisoc.raw_events", partition=0, offset=7) is True

    assert writer.spooled_rows == 1, "the event must be recorded somewhere that outlives the process"
    assert writer.metrics()["spool_rows"] == 1


@pytest.mark.asyncio
async def test_a_hard_kill_before_a_flush_does_not_lose_the_archive(tmp_path):
    """SIGKILL: no ``stop()``, no graceful flush, nothing in Python's hands.

    Modelled by abandoning the writer object entirely and building a new one
    over the same spool directory, which is what a restarted process sees.
    """
    down = _DownClickHouse()
    writer = _writer(tmp_path, down, batch_size=50)
    await writer.start()
    for n in range(5):
        await writer.write_event(_event(f"ev-{n}"), topic="aisoc.raw_events", partition=0, offset=n)
    del writer  # the process is gone; nothing ran

    up = _UpClickHouse()
    restarted = _writer(tmp_path, up, batch_size=50)
    await restarted.start()
    await restarted.flush()

    assert len(up.inserted) == 5, "every event accepted before the kill must reach the lake on restart"
    assert restarted.metrics()["rows_recovered"] == 5


@pytest.mark.asyncio
async def test_a_replayed_event_keeps_one_identity(tmp_path):
    """Recovery must not inflate hunts, usage figures or aggregations.

    The spool can hand the same event to ClickHouse twice (it is replayed
    after a crash whose offset commit may or may not have landed), so the
    identity has to be a function of the event, not of the attempt.
    """
    up = _UpClickHouse()
    writer = _writer(tmp_path, up, batch_size=50)
    await writer.start()
    await writer.write_event(_event("ev-1"), topic="aisoc.raw_events", partition=0, offset=3)
    await writer.flush()
    first = up.inserted[0]["event_id"]

    replayed = _writer(tmp_path, up, batch_size=50)
    await replayed.start()
    await replayed.write_event(_event("ev-1"), topic="aisoc.raw_events", partition=0, offset=3)
    await replayed.flush()

    assert len(up.inserted) == 2
    assert up.inserted[1]["event_id"] == first, "a replayed event must collapse under LIMIT 1 BY event_id"


@pytest.mark.asyncio
async def test_capacity_exhaustion_applies_back_pressure_instead_of_dropping(tmp_path):
    """The explicit non-fix: more memory is not durability.

    At capacity the writer must refuse the event so the consumer holds the
    Kafka offset -- Kafka's retention is the back-pressure buffer, and it is
    orders of magnitude more durable than any in-process cap. Discarding the
    oldest rows, which is what the buffer did, loses events whose offsets
    were committed minutes earlier.
    """
    writer = _writer(tmp_path, _DownClickHouse(), batch_size=50, max_spool_bytes=600)
    await writer.start()

    accepted = 0
    for n in range(200):
        if await writer.write_event(_event(f"ev-{n}"), topic="aisoc.raw_events", partition=0, offset=n):
            accepted += 1
        else:
            break

    assert accepted < 200, "capacity must be reachable, or the test proves nothing"
    assert writer.metrics()["capacity_refusals"] >= 1
    assert writer.metrics()["rows_dropped"] == 0, "back-pressure, not discard: nothing may be lost at the cap"


@pytest.mark.asyncio
async def test_a_refused_event_stops_the_offset_committing(tmp_path):
    """The consumer half of the contract.

    Archival having its own durable boundary is only worth anything if the
    consumer reads it. A refused event must raise so the message is retried
    with its offset uncommitted.
    """
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from app.workers.consumer import FusionWorker, RetryableProcessingError

    writer = _writer(tmp_path, _DownClickHouse(), batch_size=50, max_spool_bytes=1)
    await writer.start()
    worker = FusionWorker(engine=SimpleNamespace(process=AsyncMock()), lake=writer)

    with pytest.raises(RetryableProcessingError):
        await worker._process_message(  # noqa: SLF001
            _event("ev-1"), topic="aisoc.raw_events", partition=0, offset=11
        )


@pytest.mark.asyncio
async def test_a_clickhouse_outage_does_not_stop_the_alert_pipeline(tmp_path):
    """The other half: an archive fault must not cost the alert path.

    A ClickHouse outage is absorbed by the spool. Only a spool that cannot
    accept the event is allowed to apply back-pressure.
    """
    writer = _writer(tmp_path, _DownClickHouse(), batch_size=1)
    await writer.start()

    for n in range(20):
        assert await writer.write_event(_event(f"ev-{n}"), topic="aisoc.raw_events", partition=0, offset=n) is True

    assert writer.metrics()["spool_rows"] == 20
    assert writer.metrics()["rows_dropped"] == 0


@pytest.mark.asyncio
async def test_an_extended_outage_drains_when_the_store_returns(tmp_path):
    down, up = _DownClickHouse(), _UpClickHouse()
    client = {"current": down}
    writer = LakeWriter(
        host="localhost",
        batch_size=5,
        reconnect_base_seconds=0.0,
        reconnect_max_seconds=0.0,
        client_factory=lambda: client["current"],
        spool_dir=str(tmp_path / "spool"),
    )
    await writer.start()
    for n in range(12):
        await writer.write_event(_event(f"ev-{n}"), topic="aisoc.raw_events", partition=0, offset=n)
    assert writer.metrics()["spool_rows"] == 12

    client["current"] = up
    writer._client = None  # noqa: SLF001 — the reconnect the backoff would do
    await writer.flush()

    assert len(up.inserted) == 12
    assert writer.metrics()["spool_rows"] == 0, "a drained backlog must leave the spool"


@pytest.mark.asyncio
async def test_a_batch_the_server_keeps_rejecting_is_quarantined_not_deleted(tmp_path):
    """Unrecoverable is a place, not a deletion.

    A schema mismatch is not a transport fault and must not be retried
    forever, but discarding the rows makes the gap unrecoverable even once
    someone fixes the schema. They go somewhere an operator can replay them
    from, and the count is exposed.
    """

    class _RejectingClickHouse:
        def execute(self, sql, rows=None, **kwargs):  # noqa: ANN001, ANN201, ARG002
            raise ValueError("Unknown column nonsense_column")

        def disconnect(self) -> None:
            return None

    writer = _writer(tmp_path, _RejectingClickHouse(), batch_size=1, max_data_failures=2)
    await writer.start()
    for n in range(3):
        await writer.write_event(_event(f"ev-{n}"), topic="aisoc.raw_events", partition=0, offset=n)
        await writer.flush()

    metrics = writer.metrics()
    assert metrics["quarantined_rows"] >= 1
    quarantined = list((tmp_path / "spool" / "quarantine").glob("*.jsonl"))
    assert quarantined, "a rejected batch must be readable again after the schema is fixed"
    recovered = [json.loads(line) for line in quarantined[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    assert recovered and uuid.UUID(recovered[0]["event_id"])


@pytest.mark.asyncio
async def test_graceful_shutdown_leaves_a_recoverable_backlog_not_a_loss(tmp_path):
    """``stop()`` used to count retained rows as dropped. They are not dropped
    any more -- they are on disk, and the next start replays them."""
    down = _DownClickHouse()
    writer = _writer(tmp_path, down, batch_size=50)
    await writer.start()
    for n in range(4):
        await writer.write_event(_event(f"ev-{n}"), topic="aisoc.raw_events", partition=0, offset=n)
    await writer.stop()

    assert writer.metrics()["rows_dropped"] == 0, "a spooled row is a backlog, not a loss"

    up = _UpClickHouse()
    restarted = _writer(tmp_path, up, batch_size=50)
    await restarted.start()
    await restarted.flush()
    assert len(up.inserted) == 4
