"""Concurrent writers must not persist two visible rows for one fingerprint.

Migration 120 adds the database-level guarantee: a partial unique index
``uq_alerts_tenant_dedup`` on ``alerts(tenant_id, dedup_hash)``. These tests
exercise the sink's half of that contract with scripted connections — the
loser of the race gets a ``UniqueViolationError`` from the INSERT and must
resolve the winner's row instead of reporting a failure (which would
dead-letter an alert that is already durable) or writing a second alert.

They are deterministic statement-level tests, **not** proof of live PostgreSQL
concurrency. The real-container insert path is gated by
``.github/workflows/integration.yml``; no PostgreSQL instance was available in
this environment. What is pinned here is the sink's handling of the error the
index produces, the tenant scope of the key, and the migration's shape and
precondition.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import asyncpg
import pytest
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_sink import (
    _DEDUP_UNIQUE_INDEX,
    AlertSink,
    PersistOutcome,
)

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")
OTHER_TENANT = uuid.UUID("00000000-0000-0000-0000-000000000002")

MIGRATION = Path(__file__).resolve().parents[3] / "services" / "api" / "migrations" / "120_alerts_tenant_dedup_unique.sql"


class _FixedFingerprintAlert(RawAlert):
    """A raw alert whose dedup hash is supplied rather than derived.

    ``RawAlert.fingerprint()`` includes the tenant, so two tenants cannot
    naturally produce the same hash. The database index is still scoped by
    tenant, and this subclass lets the test prove that the sink passes the
    tenant through rather than relying on the hash alone.
    """

    fixed_fingerprint: str

    def fingerprint(self) -> str:
        return self.fixed_fingerprint


def _fused(
    *,
    tenant: uuid.UUID = TENANT,
    fingerprint: str | None = None,
    decision: FusionDecision = FusionDecision.NEW_ALERT,
) -> FusedAlert:
    common = {
        "tenant_id": tenant,
        "source": "CrowdStrike Falcon",
        "title": "Credential dumping via LSASS access",
        "severity": AlertSeverity.CRITICAL,
        "src_ip": "10.20.30.40",
        "hostname": "WIN-DC01",
        "username": "svc-backup",
        "mitre_techniques": ["T1003"],
        "source_event_ids": ["evt-1"],
    }
    raw: RawAlert
    if fingerprint is None:
        raw = RawAlert(**common)
    else:
        raw = _FixedFingerprintAlert(**common, fixed_fingerprint=fingerprint)
    raw.id = raw.deterministic_id()
    return FusedAlert(id=raw.id, tenant_id=tenant, fusion_decision=decision, alert=raw)


def _dedup_conflict() -> asyncpg.UniqueViolationError:
    exc = asyncpg.UniqueViolationError('duplicate key value violates unique constraint "uq_alerts_tenant_dedup"')
    exc.constraint_name = _DEDUP_UNIQUE_INDEX
    return exc


def _other_unique_conflict() -> asyncpg.UniqueViolationError:
    exc = asyncpg.UniqueViolationError('duplicate key value violates unique constraint "uq_alerts_tenant_idempotency"')
    exc.constraint_name = "uq_alerts_tenant_idempotency"
    return exc


class _Pool:
    def __init__(self, conn: object) -> None:
        self.conn = conn

    @asynccontextmanager
    async def _acquire(self):
        yield self.conn

    def acquire(self):
        return self._acquire()


class _RaceConn:
    """Answers the INSERT with a scripted outcome and the SELECT with a row."""

    def __init__(self, insert_outcome, surviving):
        self._insert_outcome = insert_outcome
        self._surviving = surviving
        self.calls: list[tuple] = []

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        lowered = sql.lower().lstrip()
        if lowered.startswith("select") and "from alerts" in lowered and "dedup_hash" in lowered:
            return self._surviving
        if isinstance(self._insert_outcome, BaseException):
            raise self._insert_outcome
        return self._insert_outcome

    async def execute(self, sql, *args):
        self.calls.append((sql, args))
        return "UPDATE 1"


class _IndexConn:
    """A tiny model of the unique index, not PostgreSQL.

    It enforces uniqueness on ``(tenant_id, dedup_hash)`` so the test can pin
    the key the sink relies on. It is deliberately not described as a live
    concurrency test.
    """

    def __init__(self) -> None:
        self.rows: dict[tuple[uuid.UUID, str], uuid.UUID] = {}
        self.calls: list[tuple] = []

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        lowered = sql.lower().lstrip()
        if lowered.startswith("select") and "from alerts" in lowered and "dedup_hash" in lowered:
            key = (args[0], args[1])
            row_id = self.rows.get(key)
            return {"id": row_id} if row_id is not None else None

        # _INSERT_SQL: $1 = id, $2 = tenant_id, $11 = dedup_hash.
        key = (args[1], args[10])
        if key in self.rows:
            raise _dedup_conflict()
        self.rows[key] = args[0]
        return {"id": args[0]}

    async def execute(self, sql, *args):
        self.calls.append((sql, args))
        return "UPDATE 1"


def _inserts(conn: object) -> list[str]:
    return [sql for sql, _ in conn.calls if "INSERT INTO alerts" in sql]


@pytest.mark.asyncio
async def test_losing_writer_resolves_the_winner_instead_of_inserting_a_second_row():
    """The race the unique index closes: different ids, same tenant + hash."""
    first = _fused(fingerprint="same-fingerprint")
    # A writer that supplies its own id (not the deterministic one) still has
    # the same logical alert. This is the case the primary-key conflict alone
    # could not catch.
    second = first.model_copy(update={"id": uuid.uuid4()})
    assert second.id != first.id

    conn = _IndexConn()
    sink = AlertSink("postgresql://x")
    sink._pool = _Pool(conn)

    inserted = await sink.persist(first)
    raced = await sink.persist(second)

    assert inserted.outcome is PersistOutcome.INSERTED
    assert raced.outcome is PersistOutcome.DUPLICATE
    assert raced.alert_id == str(first.id), "the loser must return the durable winner id"
    assert raced.verified is True
    assert raced.durable is True
    assert len(conn.rows) == 1, "the unique index must leave exactly one visible row"


@pytest.mark.asyncio
async def test_an_unnamed_unique_conflict_still_resolves_the_visible_row():
    """Drivers that do not name the index must not turn a dedup into a loss."""
    fused = _fused(fingerprint="unnamed-conflict")
    exc = asyncpg.UniqueViolationError("duplicate key value violates unique constraint")
    assert exc.constraint_name is None

    conn = _RaceConn(exc, surviving={"id": fused.id})
    sink = AlertSink("postgresql://x")
    sink._pool = _Pool(conn)

    result = await sink.persist(fused)

    assert result.outcome is PersistOutcome.DUPLICATE
    assert result.alert_id == str(fused.id)
    assert result.verified is True


@pytest.mark.asyncio
async def test_conflict_without_a_visible_winner_is_retryable_not_durable():
    """An ambiguous conflict must not be reported as a successful duplicate."""
    fused = _fused(fingerprint="ambiguous")
    conn = _RaceConn(_dedup_conflict(), surviving=None)
    sink = AlertSink("postgresql://x")
    sink._pool = _Pool(conn)

    result = await sink.persist(fused)

    assert result.outcome is PersistOutcome.FAILED
    assert result.retryable is True
    assert result.verified is False
    assert result.durable is False


@pytest.mark.asyncio
async def test_replay_after_an_unresolved_conflict_resolves_the_visible_row():
    """A retry after the ambiguous window must settle on the winner, not fail."""
    fused = _fused(fingerprint="replay")

    first_conn = _RaceConn(_dedup_conflict(), surviving=None)
    first_sink = AlertSink("postgresql://x")
    first_sink._pool = _Pool(first_conn)
    first = await first_sink.persist(fused)
    assert first.outcome is PersistOutcome.FAILED
    assert first.retryable is True

    # On the retry the winner's row is visible, so the WHERE NOT EXISTS guard
    # filters the insert and the reconciliation read resolves it.
    second_conn = _RaceConn(None, surviving={"id": fused.id})
    second_sink = AlertSink("postgresql://x")
    second_sink._pool = _Pool(second_conn)
    second = await second_sink.persist(fused)

    assert second.outcome is PersistOutcome.DUPLICATE
    assert second.alert_id == str(fused.id)
    assert second.verified is True


@pytest.mark.asyncio
async def test_unrelated_unique_violation_is_not_converted_into_a_duplicate():
    """Only the dedup index means duplicate; other constraints stay errors."""
    fused = _fused(fingerprint="other-constraint")
    conn = _RaceConn(_other_unique_conflict(), surviving={"id": uuid.uuid4()})
    sink = AlertSink("postgresql://x")
    sink._pool = _Pool(conn)

    result = await sink.persist(fused)

    assert result.outcome is PersistOutcome.FAILED
    assert result.retryable is False, "a constraint violation is not retryable"
    assert result.durable is False
    assert len(_inserts(conn)) == 1, "the sink must not retry the insert inside one persist call"


@pytest.mark.asyncio
async def test_two_tenants_with_the_same_fingerprint_both_persist():
    """Uniqueness is per tenant, not per hash alone."""
    conn = _IndexConn()
    sink = AlertSink("postgresql://x")
    sink._pool = _Pool(conn)

    first = await sink.persist(_fused(tenant=TENANT, fingerprint="shared-hash"))
    second = await sink.persist(_fused(tenant=OTHER_TENANT, fingerprint="shared-hash"))

    assert first.outcome is PersistOutcome.INSERTED
    assert second.outcome is PersistOutcome.INSERTED
    assert len(conn.rows) == 2
    assert {key[0] for key in conn.rows} == {TENANT, OTHER_TENANT}


@pytest.mark.asyncio
async def test_batch_path_has_the_same_conflict_semantics():
    """`persist_many` must not drift from `persist` on the dedup conflict."""
    first = _fused(fingerprint="batch-race")
    second = first.model_copy(update={"id": uuid.uuid4()})

    conn = _IndexConn()
    sink = AlertSink("postgresql://x")
    sink._pool = _Pool(conn)

    results = await sink.persist_many([first, second])

    assert [r.outcome for r in results] == [
        PersistOutcome.INSERTED,
        PersistOutcome.DUPLICATE,
    ]
    assert results[1].alert_id == str(first.id)
    assert results[1].verified is True
    assert len(conn.rows) == 1


def test_migration_is_a_partial_unique_index_scoped_per_tenant():
    sql = MIGRATION.read_text(encoding="utf-8")

    assert _DEDUP_UNIQUE_INDEX in sql
    assert "CREATE UNIQUE INDEX IF NOT EXISTS uq_alerts_tenant_dedup" in sql
    assert "ON alerts (tenant_id, dedup_hash)" in sql
    assert "WHERE dedup_hash IS NOT NULL" in sql


def test_migration_refuses_existing_duplicates_without_rewriting_rows():
    sql = MIGRATION.read_text(encoding="utf-8")
    upper = sql.upper()

    assert "GROUP BY tenant_id, dedup_hash" in sql
    assert "HAVING count(*) > 1" in sql
    assert "RAISE EXCEPTION" in sql
    assert "DELETE FROM ALERTS" not in upper
    assert "UPDATE ALERTS" not in upper
    assert "TRUNCATE" not in upper


def test_migration_rejects_an_invalid_index_left_by_a_failed_concurrent_build():
    """`IF NOT EXISTS` must not mistake an invalid index for a guarantee."""
    sql = MIGRATION.read_text(encoding="utf-8")

    assert "indisvalid" in sql
    assert "index uq_alerts_tenant_dedup exists but is invalid" in sql
