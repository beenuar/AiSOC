"""The retention purge must delete, and must delete only what it should.

``test_retention.py`` asserts the purge SQL is well-formed. That is a useful
property and a misleading gate: it passed for several releases while nothing
called the SQL, so "per-tenant retention with tenant-scoped purge" was marked
GATED by a test that could not have failed if the feature were removed.

These tests exercise the worker that now runs it, and concentrate on the two
ways a purge goes wrong in production: deleting another tenant's data, and
appearing to work while deleting nothing.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from app.db.cross_tenant import CrossTenantPreconditionError
from app.services.retention import build_alert_purge_sql, build_lake_purge_sql
from app.workers import retention_purge
from app.workers.retention_purge import (
    build_alert_count_sql,
    build_lake_count_sql,
    run_once,
)

TENANT_A = uuid.UUID("11111111-1111-1111-1111-111111111111")
TENANT_B = uuid.UUID("22222222-2222-2222-2222-222222222222")


class FakeResult:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows


class FakeScalarResult:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one(self) -> Any:
        return self._value

    def mappings(self) -> list[dict[str, Any]]:
        return self._value if isinstance(self._value, list) else []


class FakeSession:
    """Records every statement so tenant scoping can be asserted, not assumed."""

    def __init__(
        self,
        policies: list[dict[str, Any]],
        alert_counts: dict[str, int],
        bound_tenant: str | None = None,
    ) -> None:
        self._policies = policies
        self._alert_counts = alert_counts
        #: What ``current_setting('app.current_tenant_id', true)`` answers.
        #: ``None`` is the cross-tenant case the worker requires.
        self._bound_tenant = bound_tenant
        self.statements: list[tuple[str, dict[str, Any]]] = []
        self.committed = False

    async def scalar(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = str(stmt)
        self.statements.append((sql, dict(params or {})))
        if "app.current_tenant_id" in sql:
            return self._bound_tenant
        return None

    async def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = str(stmt)
        self.statements.append((sql, dict(params or {})))
        if "FROM retention_policies" in sql:
            return FakeScalarResult(self._policies)
        if sql.strip().upper().startswith("SELECT COUNT(*) FROM ALERTS"):
            return FakeScalarResult(self._alert_counts.get(str((params or {}).get("tenant_id")), 0))
        return FakeScalarResult(None)

    async def commit(self) -> None:
        self.committed = True

    async def close(self) -> None:  # pragma: no cover - not used with injected session
        pass

    def deletes(self) -> list[tuple[str, dict[str, Any]]]:
        return [(s, p) for s, p in self.statements if s.strip().upper().startswith("DELETE")]


def _policy(tenant: uuid.UUID, raw: int = 30, alerts: int = 60) -> dict[str, Any]:
    return {
        "tenant_id": tenant,
        "raw_events_days": raw,
        "alerts_days": alerts,
        "audit_days": 730,
    }


@pytest.fixture
def lake_calls(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, dict[str, Any] | None]]:
    """Capture ClickHouse statements and answer counts with a fixed number."""
    calls: list[tuple[str, dict[str, Any] | None]] = []

    async def fake_execute(sql: str, **kwargs: Any) -> FakeResult:
        calls.append((sql, kwargs.get("extra_settings")))
        if sql.lstrip().upper().startswith("SELECT COUNT()"):
            return FakeResult([(7,)])
        return FakeResult([])

    monkeypatch.setattr(retention_purge, "execute_lake_query", fake_execute)
    return calls


class TestItActuallyDeletes:
    async def test_live_run_issues_the_delete(self, lake_calls: list[Any]) -> None:
        db = FakeSession([_policy(TENANT_A)], {str(TENANT_A): 4})
        run = await run_once(db=db, dry_run=False)

        assert run.lake_rows == 7
        assert run.alert_rows == 4
        assert db.committed

        assert any("ALTER TABLE aisoc.raw_events DELETE" in sql for sql, _ in lake_calls)
        assert db.deletes(), "no DELETE was issued against alerts"

    async def test_dry_run_counts_but_deletes_nothing(self, lake_calls: list[Any]) -> None:
        db = FakeSession([_policy(TENANT_A)], {str(TENANT_A): 4})
        run = await run_once(db=db, dry_run=True)

        assert run.dry_run
        assert (run.lake_rows, run.alert_rows) == (7, 4), "a dry run must still report the blast radius"
        assert not any("DELETE" in sql.upper() for sql, _ in lake_calls)
        assert db.deletes() == []
        assert not db.committed

    async def test_nothing_to_delete_skips_the_mutation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def zero(sql: str, **kwargs: Any) -> FakeResult:
            return FakeResult([(0,)]) if "count()" in sql else FakeResult([])

        monkeypatch.setattr(retention_purge, "execute_lake_query", zero)
        db = FakeSession([_policy(TENANT_A)], {str(TENANT_A): 0})
        run = await run_once(db=db, dry_run=False)
        assert (run.lake_rows, run.alert_rows) == (0, 0)
        assert db.deletes() == []


class TestTenantScoping:
    async def test_every_lake_statement_names_one_tenant(self, lake_calls: list[Any]) -> None:
        db = FakeSession([_policy(TENANT_A), _policy(TENANT_B)], {})
        await run_once(db=db, dry_run=False)

        assert lake_calls
        for sql, _ in lake_calls:
            assert "tenant_id = '" in sql, sql
            assert str(TENANT_A) in sql or str(TENANT_B) in sql, sql

    async def test_alert_delete_binds_the_tenant(self, lake_calls: list[Any]) -> None:
        """The bug this guards: build_alert_purge_sql leans on RLS for scoping.

        The worker disables row security so it can enumerate tenants, so an
        unbound predicate would delete every tenant's aged alerts under the
        first tenant's window.
        """
        db = FakeSession([_policy(TENANT_A, alerts=10)], {str(TENANT_A): 3})
        await run_once(db=db, dry_run=False)

        deletes = db.deletes()
        assert len(deletes) == 1
        sql, params = deletes[0]
        assert "tenant_id = :tenant_id" in sql
        assert params["tenant_id"] == str(TENANT_A)
        assert params["days"] == 10

    async def test_per_tenant_windows_are_not_shared(self, lake_calls: list[Any]) -> None:
        db = FakeSession([_policy(TENANT_A, raw=7), _policy(TENANT_B, raw=400)], {})
        await run_once(db=db, dry_run=False)

        for_a = [s for s, _ in lake_calls if str(TENANT_A) in s]
        for_b = [s for s, _ in lake_calls if str(TENANT_B) in s]
        assert all("INTERVAL 7 DAY" in s for s in for_a), for_a
        assert all("INTERVAL 400 DAY" in s for s in for_b), for_b

    async def test_tenants_without_a_policy_are_untouched(self, lake_calls: list[Any]) -> None:
        """Defaults pre-fill a form; they are not an instruction to delete."""
        db = FakeSession([], {})
        run = await run_once(db=db, dry_run=False)
        assert run.tenants == []
        assert lake_calls == []
        assert db.deletes() == []


class TestCountSqlMirrorsDeleteSql:
    """A dry run is only a preview if it selects exactly what the delete removes."""

    def test_lake_predicates_match(self) -> None:
        count = build_lake_count_sql(TENANT_A, 45)
        delete = build_lake_purge_sql(TENANT_A, 45)
        assert count.split("WHERE", 1)[1] == delete.split("WHERE", 1)[1]

    def test_alert_predicates_match(self) -> None:
        count_sql, count_params = build_alert_count_sql(45)
        delete_sql, delete_params = build_alert_purge_sql(45)
        assert count_sql.split("WHERE", 1)[1] == delete_sql.split("WHERE", 1)[1]
        assert count_params == delete_params

    def test_clamping_applies_to_the_count_path_too(self) -> None:
        assert "INTERVAL 1 DAY" in build_lake_count_sql(TENANT_A, 0)
        assert "INTERVAL 3650 DAY" in build_lake_count_sql(TENANT_A, 999_999)
        assert build_alert_count_sql(0)[1]["days"] == 1


class TestResilience:
    async def test_lake_failure_does_not_stop_the_alert_purge(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def boom(sql: str, **kwargs: Any) -> FakeResult:
            raise RuntimeError("clickhouse unreachable")

        monkeypatch.setattr(retention_purge, "execute_lake_query", boom)
        db = FakeSession([_policy(TENANT_A)], {str(TENANT_A): 5})
        run = await run_once(db=db, dry_run=False)

        assert run.alert_rows == 5
        assert db.deletes()
        assert run.errors == ["lake: RuntimeError"]

    async def test_a_failure_is_not_reported_as_nothing_to_delete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An unreachable store must be distinguishable from an empty one."""

        async def boom(sql: str, **kwargs: Any) -> FakeResult:
            raise RuntimeError("clickhouse unreachable")

        monkeypatch.setattr(retention_purge, "execute_lake_query", boom)
        db = FakeSession([_policy(TENANT_A)], {str(TENANT_A): 0})
        run = await run_once(db=db, dry_run=False)
        assert run.lake_rows == 0
        assert run.errors, "a failed purge reported zero rows and no error"

    async def test_one_tenant_failing_does_not_skip_the_next(self, monkeypatch: pytest.MonkeyPatch) -> None:
        async def selective(sql: str, **kwargs: Any) -> FakeResult:
            if str(TENANT_A) in sql:
                raise RuntimeError("shard down")
            return FakeResult([(2,)]) if "count()" in sql else FakeResult([])

        monkeypatch.setattr(retention_purge, "execute_lake_query", selective)
        db = FakeSession([_policy(TENANT_A), _policy(TENANT_B)], {})
        run = await run_once(db=db, dry_run=False)

        assert len(run.tenants) == 2
        assert run.tenants[0].errors and not run.tenants[1].errors
        assert run.tenants[1].lake_rows == 2


async def test_cross_tenant_precondition_is_checked_before_enumerating_tenants(
    lake_calls: list[Any],
) -> None:
    """Without this the worker reads zero policies and purges nothing, quietly.

    The check used to be ``SET LOCAL row_security = off``, which only worked
    because the deployment connected as a superuser — and which *raises* for
    the runtime role introduced in ``migrations/061_runtime_app_role.sql``.
    The cross-tenant read now rests on the ``OR current_tenant_id() IS NULL``
    arm, so what has to be asserted is that no tenant was bound.
    """
    db = FakeSession([_policy(TENANT_A)], {})
    await run_once(db=db, dry_run=True)
    assert "app.current_tenant_id" in db.statements[0][0]
    assert not any("row_security" in sql for sql, _ in db.statements), (
        "SET LOCAL row_security = off raises for a role the policies apply to; " "the worker must not reintroduce it"
    )


async def test_a_sweep_on_a_tenant_bound_session_refuses_rather_than_purging_one_tenant(
    lake_calls: list[Any],
) -> None:
    """The one way this worker can go quiet, made loud.

    A bound session sees a single tenant, so the sweep would purge that
    tenant's rows under whatever policy it happened to load and report
    success. That is worse than not running.
    """
    db = FakeSession([_policy(TENANT_A)], {}, bound_tenant=str(TENANT_A))
    with pytest.raises(CrossTenantPreconditionError):
        await run_once(db=db, dry_run=True)
    assert not db.deletes(), "the sweep must refuse before issuing any delete"


async def test_audit_is_not_purged(lake_calls: list[Any]) -> None:
    """audit_days is storable but unenforceable: the log is a hash chain.

    Deleting rows would break the chain and make every later verification
    fail, so the worker must leave it alone rather than error every tick.
    """
    db = FakeSession([_policy(TENANT_A)], {})
    await run_once(db=db, dry_run=False)
    assert not any("audit" in sql.lower() for sql, _ in db.deletes())
    assert not any("audit" in sql.lower() for sql, _ in lake_calls)
