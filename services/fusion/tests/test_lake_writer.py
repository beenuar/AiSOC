"""Phase A1 — ClickHouse lake writer tests.

Proves the OCSF->column mapping, batching (size + age + stop flush), IP/UUID
coercion, and the fail-soft contract (a ClickHouse outage retains the batch,
reconnects without a restart, and never raises into the consumer; only
overflow or repeated data errors discard rows, with an explicit counter).
Uses a fake client so no live ClickHouse is needed; the live-container
assertion is the integration.yml gate.
"""

from __future__ import annotations

import uuid

import pytest
from app.services.lake_writer import LakeWriter, event_to_row

pytestmark = pytest.mark.asyncio

TENANT = "11111111-1111-1111-1111-111111111111"


def _message(**ocsf_overrides) -> dict:
    ocsf = {
        "class_uid": 2001,
        "category_uid": 2,
        "severity_id": 5,
        "severity": "Critical",
        "time": "2026-07-12T08:00:00Z",
        "metadata": {"product": {"name": "Falcon", "vendor_name": "CrowdStrike"}},
        "device": {"name": "WIN-DC01"},
        "actor": {"user": {"name": "svc-backup"}},
        "src_endpoint": {"ip": "10.20.30.40", "port": 51515},
        "dst_endpoint": {"ip": "203.0.113.9", "port": 443},
        "file": {"fingerprints": [{"value": "a" * 64}], "path": "/tmp/x"},
        "mitre_attck": [{"technique_id": "T1003", "tactic_names": ["Credential Access"]}],
        "raw_data": "raw log line",
    }
    ocsf.update(ocsf_overrides)
    return {"id": "22222222-2222-2222-2222-222222222222", "tenant_id": TENANT, "ocsf_event": ocsf}


class _FakeClient:
    def __init__(self) -> None:
        self.inserted: list[dict] = []
        self.fail = False
        self.error = "clickhouse down"

    def execute(self, sql, rows=None, **kwargs):  # noqa: ANN001
        if self.fail:
            raise RuntimeError(self.error)
        if rows:
            self.inserted.extend(rows)
        return []

    def disconnect(self):  # noqa: D401
        pass


def _writer_with_fake(**kw) -> tuple[LakeWriter, _FakeClient]:
    w = LakeWriter(host="x", **kw)
    fake = _FakeClient()
    w._client = fake  # noqa: SLF001 — inject fake, skip start()
    return w, fake


# ── Mapping ──────────────────────────────────────────────────────────────────


async def test_event_to_row_maps_core_fields():
    row = event_to_row(_message())
    assert row is not None
    assert row["tenant_id"] == TENANT
    assert row["class_uid"] == 2001
    assert row["severity_id"] == 5
    assert row["source_ip"] == "10.20.30.40"
    assert row["dest_ip"] == "203.0.113.9"
    assert row["user_name"] == "svc-backup"
    assert row["src_hostname"] == "WIN-DC01"
    assert row["hash_sha256"] == "a" * 64
    assert row["connector_type"] == "Falcon"
    assert row["mitre_techniques"] == ["T1003"]
    assert row["mitre_tactics"] == ["Credential Access"]
    assert row["event_id"] == "22222222-2222-2222-2222-222222222222"
    assert "10.20.30.40" in row["iocs"]


async def test_missing_ip_coerced_to_null_ipv6():
    row = event_to_row(_message(src_endpoint={}, dst_endpoint={}))
    assert row["source_ip"] == "::"
    assert row["dest_ip"] == "::"


async def test_a_non_uuid_event_id_gets_a_deterministic_uuid():
    """The mapping must still yield a bindable id, and it must be stable.

    A random id generated at buffer time was stable across a retry but not
    across a process restart: replaying the same Kafka message after a crash
    produced a second lake identity, so `LIMIT 1 BY event_id` could not
    collapse it.
    """
    msg = _message()
    msg["id"] = "not-a-uuid"
    first = event_to_row(msg)
    second = event_to_row(msg)
    assert first["event_id"] is not None
    assert uuid.UUID(first["event_id"])
    assert first["event_id"] == second["event_id"]
    # Different ingest ids stay distinct.
    other = _message()
    other["id"] = "another-id"
    assert event_to_row(other)["event_id"] != first["event_id"]


async def test_no_ocsf_or_bad_tenant_returns_none():
    assert event_to_row({"tenant_id": TENANT}) is None
    assert event_to_row({"tenant_id": "nope", "ocsf_event": {"class_uid": 1}}) is None


# ── Batching + flush ─────────────────────────────────────────────────────────


async def test_flushes_when_batch_full():
    w, fake = _writer_with_fake(batch_size=3)
    for _ in range(3):
        await w.write_event(_message())
    assert len(fake.inserted) == 3
    assert w.rows_written == 3
    assert w.metrics()["buffered"] == 0


async def test_buffers_until_full():
    w, fake = _writer_with_fake(batch_size=5)
    await w.write_event(_message())
    await w.write_event(_message())
    assert fake.inserted == []  # not yet flushed
    assert w.metrics()["buffered"] == 2


async def test_stop_flushes_remaining():
    w, fake = _writer_with_fake(batch_size=100)
    await w.write_event(_message())
    await w.stop()
    assert len(fake.inserted) == 1


async def test_stop_counts_rows_it_could_not_flush_as_dropped():
    """A row still buffered when the process exits is not durable.

    Logging it without incrementing `rows_dropped` leaves the metric claiming
    the archive gap did not happen.
    """
    w, fake = _writer_with_fake(batch_size=100, reconnect_base_seconds=0, reconnect_max_seconds=0)
    fake.fail = True
    await w.write_event(_message())
    await w.stop()
    assert w.metrics()["rows_dropped"] == 1


async def test_flush_if_stale_flushes_old_buffer():
    w, fake = _writer_with_fake(batch_size=100, batch_max_age_seconds=0.0)
    await w.write_event(_message())
    await w.flush_if_stale()
    assert len(fake.inserted) == 1


async def test_a_non_uuid_ingest_id_still_binds_every_column():
    """The driver cannot leave a column to its DEFAULT.

    `clickhouse-driver` builds a RowOrientedBlock from the INSERT's column list
    and reads ``row[name]`` for each one. The old writer omitted ``event_id``
    when ingest's id was not a UUID, so the block raised ``KeyError`` before a
    byte was sent; the batch was then retried as a *data* error and eventually
    dropped, taking valid rows in the same batch with it.
    """
    block_module = pytest.importorskip("clickhouse_driver.block")
    from app.services.lake_writer import _COLUMNS

    w, fake = _writer_with_fake(batch_size=2)
    msg = _message()
    msg["id"] = "not-a-uuid"
    await w.write_event(_message())  # a valid row in the same batch
    await w.write_event(msg)  # triggers the flush

    assert len(fake.inserted) == 2
    for row in fake.inserted:
        assert row["event_id"]
        uuid.UUID(row["event_id"])
        # Exactly what the real client does in send_data(): the row must carry
        # a key for every column named in the INSERT.
        block_module.RowOrientedBlock([(c, "String") for c in _COLUMNS], [row], types_check=False)


async def test_a_generated_event_id_is_stable_across_a_retry():
    """A retry re-sends the same buffered row.

    A fresh id per attempt would leave `LIMIT 1 BY event_id` unable to collapse
    a batch that was partially sent before the failure.
    """
    w, fake = _writer_with_fake(batch_size=1, reconnect_base_seconds=0, reconnect_max_seconds=0)
    msg = _message()
    msg["id"] = "not-a-uuid"
    fake.fail = True
    await w.write_event(msg)
    generated = w._buffer[0]["event_id"]  # noqa: SLF001 — the retained row
    assert generated

    fake.fail = False
    w._client = fake  # noqa: SLF001 — skip the reconnect delay
    await w.flush()
    assert fake.inserted[0]["event_id"] == generated


async def test_a_non_uuid_ingest_id_is_stable_across_a_process_restart():
    """The same Kafka message replayed by a new process keeps one identity.

    This is the restart half of the retry test above. Ingest normally emits
    UUIDs, but the topic accepts envelopes from other producers; those used to
    receive `uuid.uuid4()` per process, so a crash-and-replay archived the same
    event twice with two identities.
    """
    msg = _message()
    msg["id"] = "not-a-uuid"

    before, fake_before = _writer_with_fake(batch_size=1)
    await before.write_event(msg)

    after, fake_after = _writer_with_fake(batch_size=1)  # a fresh process
    await after.write_event(msg)

    assert fake_before.inserted[0]["event_id"] == fake_after.inserted[0]["event_id"]


async def test_an_event_with_no_id_uses_stable_kafka_coordinates():
    """An envelope with no ingest id is identified by where it lives.

    Replaying the same partition/offset after a restart must resolve to the
    same id, while a different offset is a different event even when the body
    is byte-identical.
    """
    msg = _message()
    del msg["id"]
    assert event_to_row(msg)["event_id"] is None  # mapping alone has no identity

    first, fake_first = _writer_with_fake(batch_size=1)
    await first.write_event(msg, topic="aisoc.raw_events", partition=3, offset=42)

    replay, fake_replay = _writer_with_fake(batch_size=1)
    await replay.write_event(msg, topic="aisoc.raw_events", partition=3, offset=42)

    other, fake_other = _writer_with_fake(batch_size=1)
    await other.write_event(msg, topic="aisoc.raw_events", partition=3, offset=43)

    assert fake_first.inserted[0]["event_id"] == fake_replay.inserted[0]["event_id"]
    assert fake_other.inserted[0]["event_id"] != fake_first.inserted[0]["event_id"]


# ── Fail-soft ────────────────────────────────────────────────────────────────


async def test_flush_failure_retains_batch_and_never_raises():
    """A ClickHouse outage must not silently discard the archive batch.

    The old writer dropped it. The batch is now retained and retried; the
    failure is still visible in `flush_failures`.
    """
    w, fake = _writer_with_fake(batch_size=2, reconnect_base_seconds=0, reconnect_max_seconds=0)
    fake.fail = True
    await w.write_event(_message())
    await w.write_event(_message())  # triggers flush -> fails
    assert w.flush_failures == 1
    assert w.rows_written == 0
    assert w.metrics()["buffered"] == 2  # retained for the next attempt

    # Recovery: the same batch is written once ClickHouse accepts it, with no
    # process restart and no loss.
    fake.fail = False
    w._client = fake  # noqa: SLF001 — skip the reconnect delay in this unit test
    await w.flush()
    assert len(fake.inserted) == 2
    assert w.rows_written == 2
    assert w.metrics()["buffered"] == 0


async def test_buffer_overflow_drops_oldest_rows_explicitly():
    """Retention is bounded; overflow is counted rather than silent."""
    w, fake = _writer_with_fake(batch_size=1, max_buffer_rows=2, reconnect_base_seconds=0, reconnect_max_seconds=0)
    fake.fail = True
    for _ in range(3):
        await w.write_event(_message())  # each write attempts a flush, all fail
    metrics = w.metrics()
    assert metrics["buffered"] == 2
    assert metrics["rows_dropped"] == 1


async def test_data_errors_are_bounded_and_dropped_loudly():
    """A batch the server keeps rejecting must not grow forever.

    Connection errors are retained (the store is down, the rows may be fine);
    non-connection errors are retried a bounded number of times and then
    dropped with `rows_dropped` incremented.
    """
    w, fake = _writer_with_fake(
        batch_size=2,
        max_data_failures=2,
        reconnect_base_seconds=0,
        reconnect_max_seconds=0,
    )
    fake.fail = True
    fake.error = "Code: 47. DB::Exception: missing column tenant_id"
    await w.write_event(_message())
    await w.write_event(_message())  # first data failure
    w._client = fake  # noqa: SLF001 — retry without waiting for reconnect
    await w.flush()  # second data failure reaches the bound
    assert w.flush_failures == 2
    assert w.metrics()["buffered"] == 0
    assert w.metrics()["rows_dropped"] == 2


async def test_connect_failure_is_retried_instead_of_permanently_disabling():
    """A missing ClickHouse is recoverable; only a missing driver is final."""
    clients = [_FakeClient()]
    calls = {"n": 0}

    def factory():  # noqa: ANN202
        calls["n"] += 1
        return clients[0]

    w = LakeWriter(
        host="x",
        batch_size=1,
        reconnect_base_seconds=0,
        reconnect_max_seconds=0,
        client_factory=factory,
    )
    await w.start()
    assert calls["n"] == 1
    await w.write_event(_message())
    assert w.rows_written == 1

    # Simulate a dropped connection: the next flush rebuilds the client from
    # the factory rather than disabling the writer.
    w._client = None  # noqa: SLF001
    clients[0].fail = True
    await w.write_event(_message())  # fails, drops its client
    clients[0].fail = False
    w._next_reconnect_at = 0.0  # noqa: SLF001 — eligible immediately
    await w.flush()
    assert calls["n"] >= 2
    assert w.rows_written == 2
    assert await w.write_event(_message()) is True  # still enabled, not disabled


async def test_disabled_writer_is_noop():
    w = LakeWriter(host="x")
    w._disabled = True  # noqa: SLF001
    assert await w.write_event(_message()) is False
    await w.flush()  # no raise


# ── depth plan 2.2: the activity projection ────────────────────────────────


def _with_activity(**activity_overrides) -> dict:
    activity = {
        "actor": {
            "kind": "api_token",
            "kind_source": "actor.callerType",
            "id": "arn:aws:iam::123456789012:user/deploy",
            "on_behalf_of": "alice@example.com",
        },
        "action": "create.access.key",
        "resource": {"type": "AWS::IAM::User", "id": "arn:aws:iam::123456789012:user/x", "owner": "123456789012"},
        "location": {
            "ip": "8.8.8.8",
            "country_code": "SE",
            "asn": 1299,
            "as_org": "Arelion",
            "reputation": 72.5,
            "reputation_known": True,
            "client": {"raw": "aws-cli/2.15.30", "family": "aws-cli", "version": "2.15.30", "category": "cli"},
        },
        "outcome": "failure",
    }
    activity.update(activity_overrides)
    return _message(activity=activity)


async def test_activity_projection_lands_in_its_own_columns():
    """The projection is columns, not only a slice of the ocsf_json blob.

    A hunt for "every action by a non-human actor from a new ASN" has to be
    an indexed scan; JSONExtract over a ZSTD column cannot use an index.
    """
    row = event_to_row(_with_activity())
    assert row is not None
    assert row["actor_kind"] == "api_token"
    assert row["actor_kind_source"] == "actor.callerType"
    assert row["actor_on_behalf_of"] == "alice@example.com"
    assert row["action"] == "create.access.key"
    assert row["resource_type"] == "AWS::IAM::User"
    assert row["resource_owner"] == "123456789012"
    assert row["src_country_code"] == "SE"
    assert row["src_asn"] == 1299
    assert row["src_as_org"] == "Arelion"
    assert row["src_reputation"] == pytest.approx(72.5)
    assert row["src_reputation_known"] == 1
    assert row["client_family"] == "aws-cli"
    assert row["client_category"] == "cli"
    assert row["client_raw"] == "aws-cli/2.15.30"
    assert row["outcome"] == "failure"


async def test_an_event_with_no_projection_still_inserts():
    """The insert is positional, so a missing key would shift every column
    after it. An event from before the projection, or replayed off an older
    topic, has no `activity` block and must still land."""
    row = event_to_row(_message())
    assert row is not None
    assert set(row) >= {"actor_kind", "action", "src_asn", "outcome"}
    assert row["actor_kind"] == ""
    assert row["src_asn"] == 0
    assert row["src_reputation_known"] == 0


async def test_an_unanswered_reputation_is_not_a_clean_one():
    """A clean verdict and an unreachable enrichment service both produce
    0.0. Only the flag separates them, and a surface rendering 0 as "clean"
    when nobody answered is a fabricated confidence."""
    row = event_to_row(_with_activity(location={"ip": "8.8.8.8", "reputation": 0.0, "reputation_known": False}))
    assert row is not None
    assert row["src_reputation"] == pytest.approx(0.0)
    assert row["src_reputation_known"] == 0

    answered = event_to_row(_with_activity(location={"ip": "8.8.8.8", "reputation": 0.0, "reputation_known": True}))
    assert answered is not None
    assert answered["src_reputation_known"] == 1


async def test_every_declared_column_is_present_in_every_row():
    """_INSERT_SQL is built by joining _COLUMNS and the driver reads the row
    positionally, so a row missing one key inserts every later value into the
    wrong column."""
    from app.services.lake_writer import _COLUMNS

    for message in (_with_activity(), _message()):
        row = event_to_row(message)
        assert row is not None
        missing = [c for c in _COLUMNS if c not in row]
        assert not missing, f"row is missing declared columns: {missing}"


async def test_an_attacker_chosen_user_agent_is_bounded():
    """The raw agent is kept deliberately, which means an attacker chooses
    the length of a string that reaches a lake column."""
    row = event_to_row(_with_activity(location={"client": {"raw": "x" * 50_000}}))
    assert row is not None
    assert len(row["client_raw"]) <= 1024
