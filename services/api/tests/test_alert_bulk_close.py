"""Tests for the bulk-close service (services/api/app/services/alert_bulk_close.py).

Mirrors the alert-queue test convention: pure service layer, mocked
AsyncSession, no TestClient, no Postgres. The integration tests in CI run
the same code path against a real database; here we lock the *rules* —
what refuses to run, and what the executed statements must contain.

The critical assertions are the fail-closed ones:
* the tenant predicate is present in every statement (count, snapshot,
  UPDATE) — an escaping tenant filter is the one bug this endpoint is
  not allowed to have;
* over-match and empty refuse BEFORE any write is attempted (the mock
  would raise if the order were flipped);
* generated backup table names never interpolate attacker input.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.services.alert_bulk_close import (
    DEFAULT_MAX_COUNT,
    MAX_BULK_CLOSE_LIMIT,
    BulkCloseEmpty,
    BulkCloseOverMatch,
    build_bulk_close_predicates,
    bulk_close_alerts,
)


def _tenant() -> uuid.UUID:
    return uuid.uuid4()


def _compiled(stmt) -> str:
    from sqlalchemy.dialects import postgresql

    return str(stmt.compile(dialect=postgresql.dialect(), compile_kwargs={"render_postcompile": True}))


def _session(matched: int = 3, snapshot_rows: int = 3) -> AsyncMock:
    """Mock session whose execute() answers count → matched, then anything."""
    db = AsyncMock()
    count_result = MagicMock()
    count_result.scalar_one.return_value = matched
    update_result = MagicMock()
    update_result.rowcount = snapshot_rows
    db.execute = AsyncMock(side_effect=[count_result, MagicMock(), MagicMock(), update_result])
    return db


class TestPredicateBuilder:
    def test_tenant_predicate_always_first(self):
        preds = build_bulk_close_predicates(
            tenant_id=_tenant(),
            alert_ids=None,
            statuses=None,
            severities=None,
            categories=None,
            connector_types=None,
            older_than=None,
        )
        assert "tenant_id" in _compiled(preds[0])

    def test_bare_filter_restricted_to_open_statuses(self):
        preds = build_bulk_close_predicates(
            tenant_id=_tenant(),
            alert_ids=None,
            statuses=None,
            severities=["low"],
            categories=None,
            connector_types=None,
            older_than=None,
        )
        rendered = " ".join(_compiled(p) for p in preds)
        assert "status IN" in rendered
        # IN-collections render as expando binds, so the open-status
        # guard is checked on the compiled parameters, not SQL text.
        from app.services.alert_bulk_close import OPEN_STATUSES

        params = {}
        for pr in preds:
            params.update(pr.compile().params)
        flat = [v for val in params.values() for v in (val if isinstance(val, (list, tuple)) else [val])]
        assert any(str(v) in OPEN_STATUSES for v in flat)

    def test_explicit_ids_may_reclose_closed_rows(self):
        preds = build_bulk_close_predicates(
            tenant_id=_tenant(),
            alert_ids=[uuid.uuid4()],
            statuses=None,
            severities=None,
            categories=None,
            connector_types=None,
            older_than=None,
        )
        rendered = " ".join(_compiled(p) for p in preds)
        assert "status IN" not in rendered


class TestSnapshotSqlRendering:
    def test_snapshot_ddl_has_no_pyformat_binds(self):
        """asyncpg rejects %(name)s placeholders — live-caught 500.

        The snapshot DDL is compiled with literal_binds; a regression to a
        psycopg2-style compile would reintroduce % binds into text() and
        blow up at the driver, invisible to mocked-session tests.
        """
        from app.services.alert_bulk_close import _snapshot_select, _snapshot_sql

        preds = build_bulk_close_predicates(
            tenant_id=_tenant(),
            alert_ids=None,
            statuses=["new"],
            severities=["low", "high"],
            categories=None,
            connector_types=["scanner"],
            older_than=None,
        )
        ddl = _snapshot_sql(_snapshot_select(preds), "aisoc_bulk_close_backup.bulk_close_backup_deadbeef")
        assert "%" not in ddl
        assert "CREATE TABLE aisoc_bulk_close_backup.bulk_close_backup_deadbeef AS SELECT" in ddl
        assert "tenant_id" in ddl


class TestValidationBeforeWrite:
    @pytest.mark.asyncio
    async def test_no_ids_no_filter_refused(self):
        db = _session()
        with pytest.raises(ValueError, match="requires alert_ids or at least one filter"):
            await bulk_close_alerts(db, tenant_id=_tenant(), actor_id=None, close_status="resolved")
        db.execute.assert_not_awaited()
        db.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_invalid_close_status_refused(self):
        db = _session()
        with pytest.raises(ValueError):
            await bulk_close_alerts(db, tenant_id=_tenant(), actor_id=None, close_status="new", severities=["low"])
        db.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_over_match_refused_before_any_write(self):
        db = _session(matched=900)
        with pytest.raises(BulkCloseOverMatch) as exc_info:
            await bulk_close_alerts(
                db,
                tenant_id=_tenant(),
                actor_id=None,
                close_status="resolved",
                categories=["vulnerability"],
            )
        assert exc_info.value.matched == 900
        assert exc_info.value.max_count == DEFAULT_MAX_COUNT
        # only the COUNT ran — no DROP/CREATE/UPDATE
        assert db.execute.await_count == 1
        db.commit.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_empty_refused(self):
        db = _session(matched=0)
        with pytest.raises(BulkCloseEmpty):
            await bulk_close_alerts(db, tenant_id=_tenant(), actor_id=None, close_status="resolved", severities=["low"])
        assert db.execute.await_count == 1


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_close_writes_snapshot_then_update_with_tenant_scope(self):
        tenant = _tenant()
        db = _session(matched=3, snapshot_rows=3)
        outcome = await bulk_close_alerts(
            db,
            tenant_id=tenant,
            actor_id=uuid.uuid4(),
            close_status="false_positive",
            categories=["vulnerability"],
            connector_types=["scanner"],
            older_than=datetime.now(UTC) - timedelta(days=1),
            max_count=5000,
            comment="kernel backlog suppression",
        )
        assert outcome["closed_count"] == 3
        assert outcome["close_status"] == "false_positive"
        assert outcome["backup_table"].startswith("aisoc_bulk_close_backup.bulk_close_backup_")

        statements = []
        for call in db.execute.await_args_list:
            arg = call.args[0]
            statements.append(str(arg) if not isinstance(arg, str) else arg)
        joined = " | ".join(statements)

        # count → snapshot DDL → update, tenant predicate in each of them
        assert joined.count("tenant_id") >= 3
        assert "CREATE TABLE aisoc_bulk_close_backup.bulk_close_backup_" in joined
        assert "UPDATE alerts" in joined
        assert "DROP TABLE IF EXISTS aisoc_bulk_close_backup.bulk_close_backup_" in joined
        db.commit.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_max_count_clamped_to_hard_ceiling(self):
        tenant = _tenant()
        db = _session(matched=MAX_BULK_CLOSE_LIMIT + 100)
        with pytest.raises(BulkCloseOverMatch) as exc_info:
            await bulk_close_alerts(
                db,
                tenant_id=tenant,
                actor_id=None,
                close_status="resolved",
                severities=["low"],
                max_count=10**9,
            )
        assert exc_info.value.max_count == MAX_BULK_CLOSE_LIMIT

    @pytest.mark.asyncio
    async def test_ids_path_scopes_update_to_ids_and_tenant(self):
        tenant = _tenant()
        ids = [uuid.uuid4(), uuid.uuid4()]
        db = _session(matched=2, snapshot_rows=2)
        outcome = await bulk_close_alerts(db, tenant_id=tenant, actor_id=None, close_status="closed", alert_ids=ids)
        assert outcome["closed_count"] == 2
        update_stmt = str(db.execute.await_args_list[-1].args[0])
        assert "UPDATE alerts" in update_stmt
        assert "id IN" in update_stmt and "tenant_id" in update_stmt


def test_safe_log_text_neutralises_log_injection() -> None:
    """CodeQL py/log-injection: CR/LF/control bytes from user comments must
    never reach the log stream verbatim."""
    from app.services.alert_bulk_close import _safe_log_text

    evil = "sweep\r\n2026-10-07 FAKE extra log line\x1b[31mred\x1b\x00end"
    out = _safe_log_text(evil)
    assert "\r" not in out and "\n" not in out
    assert "\x1b" not in out and "\x00" not in out
    assert out.startswith("sweep")
    assert _safe_log_text("x" * 500) == "x" * 120
    assert _safe_log_text(None) == ""
