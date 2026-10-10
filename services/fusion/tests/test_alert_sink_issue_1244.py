"""The alert row carries the entities fusion computed, and records dedup.

Issue #1244, two independent gaps in what ``AlertSink`` writes.

**affected_hosts / affected_users / affected_ips were never written.** The
columns have existed since migration 042, the ORM maps them, the alerts
endpoint serialises them and five readers filter on them — and the only
writer in the tree was ``seed_demo.py``, so every one of those readers saw
``[]`` on a real alert and a populated list on a seeded one. Fusion already
derives the same host, user and IPs for ``entities`` and ``iocs``; it just
did not name the columns in its INSERT.

**A deduplicated event left no trace.** ``source_event_ids`` is the column
the funnel's "Correlation Instances" tile counts (``jsonb_array_length >= 2``
in ``services/api/app/api/v1/endpoints/metrics.py``), and the only writer
appends one id before the insert. When a second event dedups onto an alert the
insert is filtered by ``WHERE NOT EXISTS`` and the second event's id is
dropped on the floor, so the predicate could never be satisfied and the tile
read 0 by construction — "522 events formed 0 correlation instances" on a
pipeline that was deduplicating the whole time.
"""

from __future__ import annotations

import json
import re
import uuid
from contextlib import asynccontextmanager

import pytest
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_sink import AlertSink, PersistOutcome

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
CONNECTOR = uuid.UUID("00000000-0000-0000-0000-0000000000c1")


def _fused(
    decision: FusionDecision = FusionDecision.NEW_ALERT,
    *,
    source_event_ids: list[str] | None = None,
) -> FusedAlert:
    raw = RawAlert(
        tenant_id=TENANT,
        source="CrowdStrike Falcon",
        title="Credential dumping via LSASS access",
        severity=AlertSeverity.CRITICAL,
        src_ip="10.20.30.40",
        dst_ip="10.20.30.99",
        hostname="WIN-DC01",
        username="svc-backup",
        mitre_techniques=["T1003"],
        connector_id=CONNECTOR,
        connector_type="crowdstrike_falcon",
        source_event_ids=["evt-1"] if source_event_ids is None else list(source_event_ids),
        ocsf_class_uid=2004,
    )
    raw.id = raw.deterministic_id()
    return FusedAlert(id=raw.id, tenant_id=TENANT, fusion_decision=decision, alert=raw)


class _StubConn:
    """Records every statement, and answers fetchrow with a scripted row."""

    def __init__(self, row):
        self._row = row
        self.calls: list[tuple] = []

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        return self._row

    async def execute(self, sql, *args):
        self.calls.append((sql, args))
        return "UPDATE 1"


class _StubPool:
    def __init__(self, row):
        self.conn = _StubConn(row)

    @asynccontextmanager
    async def _acquire(self):
        yield self.conn

    def acquire(self):
        return self._acquire()


def _insert_statement(pool: _StubPool) -> tuple[str, tuple]:
    for sql, args in pool.conn.calls:
        if "INSERT INTO alerts" in sql:
            return sql, args
    raise AssertionError(f"no INSERT INTO alerts issued; calls={[c[0][:40] for c in pool.conn.calls]}")


def _split_top_level(expr_list: str) -> list[str]:
    """Split a SELECT list on commas that are not inside parentheses.

    `COALESCE($17, NOW())` is one expression, not two.
    """
    out: list[str] = []
    depth = 0
    current = ""
    for char in expr_list:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        if char == "," and depth == 0:
            out.append(current.strip())
            current = ""
            continue
        current += char
    if current.strip():
        out.append(current.strip())
    return out


def _column_value(sql: str, args: tuple, column: str):
    """Read one column's bound value by name, via the placeholder it selects.

    By name rather than by position: a positional assertion silently follows
    the wrong value the moment a column is inserted ahead of it, which is the
    drift `_insert_args` exists to prevent. Column index and argument index
    are *not* the same — `status` is selected as the literal `'new'` and
    consumes no placeholder — so the column list is zipped against the SELECT
    list and the `$N` is read off the matching expression.
    """
    head, _, tail = sql.partition("INSERT INTO alerts (")
    assert head is not None and tail, "not an alerts INSERT"
    columns = [c.strip() for c in tail.split(")", 1)[0].split(",")]
    select_list = tail.split("SELECT", 1)[1].split("WHERE NOT EXISTS", 1)[0]
    exprs = _split_top_level(select_list)
    assert len(columns) == len(exprs), f"{len(columns)} columns against {len(exprs)} select expressions"
    assert column in columns, f"{column} is not in the INSERT column list: {columns}"

    expr = exprs[columns.index(column)]
    match = re.match(r"\$(\d+)", expr)
    assert match, f"{column} is selected as {expr!r}, not a bound parameter"
    return args[int(match.group(1)) - 1]


# ── affected_* are written from the entities fusion already computes ──────


@pytest.mark.asyncio
async def test_affected_hosts_users_and_ips_are_persisted() -> None:
    fused = _fused()
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    result = await sink.persist(fused)
    assert result.outcome is PersistOutcome.INSERTED

    sql, args = _insert_statement(pool)
    assert json.loads(_column_value(sql, args, "affected_hosts")) == ["WIN-DC01"]
    assert json.loads(_column_value(sql, args, "affected_users")) == ["svc-backup"]
    assert json.loads(_column_value(sql, args, "affected_ips")) == ["10.20.30.40", "10.20.30.99"]


@pytest.mark.asyncio
async def test_absent_entities_persist_as_empty_lists_not_nulls() -> None:
    """The columns are ``JSONB NOT NULL DEFAULT '[]'`` — a NULL would fail."""
    bare = RawAlert(tenant_id=TENANT, source="ingest", title="No entities anywhere")
    bare.id = bare.deterministic_id()
    fused = FusedAlert(id=bare.id, tenant_id=TENANT, fusion_decision=FusionDecision.NEW_ALERT, alert=bare)
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    await sink.persist(fused)

    sql, args = _insert_statement(pool)
    for column in ("affected_hosts", "affected_users", "affected_ips"):
        assert json.loads(_column_value(sql, args, column)) == [], column


@pytest.mark.asyncio
async def test_the_batch_path_writes_the_same_columns() -> None:
    """`persist_many` shares `_insert_args`; prove it rather than assume it."""
    fused = _fused()
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    await sink.persist_many([fused])

    sql, args = _insert_statement(pool)
    assert json.loads(_column_value(sql, args, "affected_hosts")) == ["WIN-DC01"]


# ── a deduplicated event is recorded on the row it deduped onto ───────────


@pytest.mark.asyncio
async def test_a_dedup_hit_records_the_second_events_id() -> None:
    """The defect behind "522 events formed 0 correlation instances"."""
    pool = _StubPool(row=None)  # WHERE NOT EXISTS filtered the insert out
    sink = AlertSink("postgresql://x")
    sink._pool = pool
    fused = _fused(source_event_ids=["evt-2"])

    result = await sink.persist(fused)
    assert result.outcome is PersistOutcome.DUPLICATE

    updates = [(sql, args) for sql, args in pool.conn.calls if sql.strip().upper().startswith("UPDATE ALERTS")]
    assert updates, (
        "a deduplicated event left no trace on the alert it deduped onto, so "
        "source_event_ids can never reach length 2 and the Correlation "
        "Instances tile is a structural zero"
    )
    sql, args = updates[0]
    assert "source_event_ids" in sql
    assert TENANT in args
    assert fused.alert.fingerprint() in args
    assert "evt-2" in json.dumps(args, default=str)


@pytest.mark.asyncio
async def test_a_fusion_decided_duplicate_is_also_recorded() -> None:
    """Fusion's own DUPLICATE verdict returns before the insert is attempted."""
    pool = _StubPool(row=None)
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    result = await sink.persist(_fused(FusionDecision.DUPLICATE, source_event_ids=["evt-3"]))
    assert result.outcome is PersistOutcome.DUPLICATE

    updates = [(sql, args) for sql, args in pool.conn.calls if sql.strip().upper().startswith("UPDATE ALERTS")]
    assert updates, "fusion's in-memory dedup verdict also loses the source event id"
    assert "evt-3" in json.dumps(updates[0][1], default=str)


@pytest.mark.asyncio
async def test_an_insert_that_succeeded_issues_no_dedup_update() -> None:
    """The extra round trip is paid only when there is something to record."""
    fused = _fused()
    pool = _StubPool(row={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    await sink.persist(fused)

    updates = [sql for sql, _ in pool.conn.calls if sql.strip().upper().startswith("UPDATE ALERTS")]
    assert updates == []


@pytest.mark.asyncio
async def test_an_event_with_no_source_id_issues_no_dedup_update() -> None:
    pool = _StubPool(row=None)
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    await sink.persist(_fused(source_event_ids=[]))

    updates = [sql for sql, _ in pool.conn.calls if sql.strip().upper().startswith("UPDATE ALERTS")]
    assert updates == []


@pytest.mark.asyncio
async def test_a_duplicate_verdict_survives_an_unreachable_database() -> None:
    """Recording the provenance must not make DUPLICATE depend on the DB.

    Fusion decided; an outage changes only whether we can write the id down.
    The early return has to stay ahead of `_ensure_pool`, or a DUPLICATE
    starts reporting UNAVAILABLE and the consumer retries a decision that
    was already made.
    """
    sink = AlertSink("postgresql://nope:nope@127.0.0.1:1/none")
    sink._pool = None

    result = await sink.persist(_fused(FusionDecision.DUPLICATE))
    assert result.outcome is PersistOutcome.DUPLICATE


@pytest.mark.asyncio
async def test_a_failing_dedup_update_does_not_change_the_outcome() -> None:
    """Recording provenance is best-effort; it must never cost the verdict."""

    class _BoomConn(_StubConn):
        async def execute(self, sql, *args):
            self.calls.append((sql, args))
            raise RuntimeError("connection reset")

    pool = _StubPool(row=None)
    pool.conn = _BoomConn(row=None)
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    result = await sink.persist(_fused(source_event_ids=["evt-4"]))
    assert result.outcome is PersistOutcome.DUPLICATE
