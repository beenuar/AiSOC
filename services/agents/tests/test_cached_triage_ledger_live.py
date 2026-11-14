"""Cached consumer verdict -> real ledger -> alert readback, with rollback.

Set AISOC_TEST_POSTGRES_DSN explicitly to a migrated test database. The
synthetic tenant, alert and immutable ledger entries share one transaction
that is rolled back, including when an assertion fails. No inference runs.
"""

from __future__ import annotations

import os
import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock

import asyncpg
import pytest
from app.core.cost_governor import CostGovernor
from app.investigator import ledger
from app.replay.shadow import ShadowTriageWriter
from app.workers import fused_alert_consumer as worker_module

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]


class LedgerOnlyWriter(ShadowTriageWriter):
    @property
    def uses_dedup_cache(self):
        return True

    async def persist_auto_triage(self, **values):
        await ledger.persist_auto_triage(**values)


async def test_cached_verdict_reaches_persisted_alert(monkeypatch):
    dsn = os.getenv("AISOC_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("requires an explicit test Postgres DSN with migrations applied")
    conn = await asyncpg.connect(dsn, timeout=5, command_timeout=10)
    try:
        transaction = conn.transaction()
        await transaction.start()
        try:

            class TestPool:
                @asynccontextmanager
                async def acquire(self):
                    yield conn

            tenant, alert = uuid.uuid4(), uuid.uuid4()
            await conn.execute(
                "INSERT INTO tenants(id,name,slug) VALUES($1,'Cached triage regression fixture',$2)",
                tenant,
                "cached-test-" + tenant.hex,
            )
            await conn.execute(
                "INSERT INTO alerts(id,tenant_id,title,severity,status,is_synthetic,raw_event) "
                "VALUES($1,$2,'Cached triage regression fixture','low','new',true,'{}')",
                alert,
                tenant,
            )
            message = {
                "id": str(alert),
                "tenant_id": str(tenant),
                "alert": {"id": str(alert), "title": "Cached triage regression fixture", "severity": "low"},
            }
            state = worker_module.build_state(message)
            assert state is not None
            governor = CostGovernor()
            governor.record_verdict(
                str(tenant),
                governor.evidence_fingerprint(str(tenant), state.raw_alert),
                {"verdict": "needs_review", "confidence": 0.6},
                usd=0,
                tokens=0,
            )
            writer = LedgerOnlyWriter()
            worker = worker_module.FusedAlertTriageWorker(bootstrap_servers="unused", writer=writer)
            monkeypatch.setattr(worker, "_sink_for", AsyncMock(return_value=writer))
            monkeypatch.setattr(worker, "_write_back_to_source", AsyncMock(return_value=None))
            monkeypatch.setattr(worker, "_answer_triage_questions", AsyncMock(return_value=([], [])))
            monkeypatch.setattr(worker, "_resolve_tenant_llm", AsyncMock(side_effect=AssertionError("cached triage must not call a model")))
            monkeypatch.setattr(ledger, "get_pool", AsyncMock(return_value=TestPool()))
            monkeypatch.setattr(worker_module, "get_governor", lambda: governor)
            monkeypatch.setattr(worker_module, "_memory_suppression_enabled", lambda: False)
            monkeypatch.setattr(worker_module, "_memory_writeback_enabled", lambda: False)
            monkeypatch.setattr(worker_module, "_approvals_enabled", lambda: False)
            result = await worker.triage(message)
            row = await conn.fetchrow("SELECT ai_summary,status,disposition FROM alerts WHERE tenant_id=$1 AND id=$2", tenant, alert)
            assert row is not None
            assert row["ai_summary"] and "verdict=None" not in row["ai_summary"]
            assert "cached" in row["ai_summary"].lower()
            assert "confidence=0.60" in row["ai_summary"]
            assert row["status"] != "resolved"
            assert result is not None
            assert row["disposition"] == result["verdict"] == "needs_review"
            assert result["confidence"] == 0.6
        finally:
            await transaction.rollback()
    finally:
        await conn.close()
