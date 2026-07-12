"""Unit tests for the Phase 3.1 fused-alert → Postgres sink.

Covers the skip/fail-soft decision logic with a stub pool. The real-container
insert path is gated by `.github/workflows/integration.yml`
(scripts/integration/spine_test.py) — asserting SQL against a live Postgres,
not a mock.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import pytest
from app.models.alert import (
    AlertSeverity,
    FusedAlert,
    FusionDecision,
    RawAlert,
)
from app.services.alert_sink import AlertSink, _asyncpg_dsn, _entities, _iocs

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000001")


def _fused(decision: FusionDecision = FusionDecision.NEW_ALERT) -> FusedAlert:
    raw = RawAlert(
        tenant_id=TENANT,
        source="CrowdStrike Falcon",
        title="Credential dumping via LSASS access",
        severity=AlertSeverity.CRITICAL,
        src_ip="10.20.30.40",
        hostname="WIN-DC01",
        username="svc-backup",
        mitre_techniques=["T1003"],
    )
    return FusedAlert(
        id=raw.id,
        tenant_id=TENANT,
        fusion_decision=decision,
        alert=raw,
    )


class _StubConn:
    def __init__(self, row):
        self._row = row
        self.calls: list[tuple] = []

    async def fetchrow(self, sql, *args):
        self.calls.append((sql, args))
        return self._row


class _StubPool:
    def __init__(self, row):
        self.conn = _StubConn(row)

    @asynccontextmanager
    async def _acquire(self):
        yield self.conn

    def acquire(self):
        return self._acquire()


def test_dsn_strips_sqlalchemy_driver():
    assert _asyncpg_dsn("postgresql+asyncpg://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"
    assert _asyncpg_dsn("postgresql://u:p@h:5432/db") == "postgresql://u:p@h:5432/db"


def test_iocs_and_entities_extraction():
    fused = _fused()
    iocs = _iocs(fused)
    assert {"type": "ip", "value": "10.20.30.40"} in iocs
    entities = _entities(fused)
    assert {"type": "host", "value": "WIN-DC01"} in entities
    assert {"type": "user", "value": "svc-backup"} in entities


@pytest.mark.asyncio
async def test_duplicate_decision_is_never_persisted():
    sink = AlertSink("postgresql://x")
    sink._pool = _StubPool(row={"id": uuid.uuid4()})  # would succeed if called
    result = await sink.persist(_fused(FusionDecision.DUPLICATE))
    assert result is None
    assert sink._pool.conn.calls == []


@pytest.mark.asyncio
async def test_new_alert_is_inserted_with_fingerprint():
    row_id = uuid.uuid4()
    pool = _StubPool(row={"id": row_id})
    sink = AlertSink("postgresql://x")
    sink._pool = pool

    fused = _fused()
    result = await sink.persist(fused)

    assert result == str(row_id)
    (sql, args) = pool.conn.calls[0]
    assert "INSERT INTO alerts" in sql
    assert "WHERE NOT EXISTS" in sql  # idempotency guard
    assert args[0] == TENANT
    assert args[9] == fused.alert.fingerprint()  # dedup_hash


@pytest.mark.asyncio
async def test_dedup_hit_returns_none():
    pool = _StubPool(row=None)  # WHERE NOT EXISTS filtered the insert out
    sink = AlertSink("postgresql://x")
    sink._pool = pool
    assert await sink.persist(_fused()) is None


@pytest.mark.asyncio
async def test_db_unavailable_degrades_without_raising(monkeypatch):
    sink = AlertSink("postgresql://nope:nope@127.0.0.1:1/none")

    async def _fail_start():
        sink._pool = None

    monkeypatch.setattr(sink, "start", _fail_start)
    # Must not raise — fail-soft is the contract.
    assert await sink.persist(_fused()) is None


@pytest.mark.asyncio
async def test_persist_exception_is_swallowed():
    class _BoomPool(_StubPool):
        def acquire(self):
            raise RuntimeError("connection reset")

    sink = AlertSink("postgresql://x")
    sink._pool = _BoomPool(row=None)
    assert await sink.persist(_fused()) is None
