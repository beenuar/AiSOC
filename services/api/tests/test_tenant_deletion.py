"""Tenant offboarding must erase everywhere, or say plainly that it did not.

There was no deletion path at all. ``DELETE FROM tenants`` leans on foreign-key
cascade, and 14 of the 72 tenant-scoped tables never declared one — so an
offboarded customer's institutional memory, compliance evidence and KB
documents outlived the tenant record. The lake, graph and vector stores had no
deletion path whatsoever.

The tests that matter here are not "does it issue a DELETE". They are:
discovery cannot go stale as tables are added; a partial erase is never
reported as complete; and reference data shared across tenants survives.
"""

from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.services import tenant_deletion
from app.services.tenant_deletion import DeletionReport, StoreResult, delete_tenant

TENANT = uuid.UUID("33333333-3333-3333-3333-333333333333")

DISCOVERED = ["aisoc_institutional_memory", "alerts", "cases", "tenants"]


class FakeScalar:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one(self) -> Any:
        return self._value

    def fetchall(self) -> Any:
        return self._value


class FakeSession:
    def __init__(self, counts: dict[str, int] | None = None, bound_tenant: str | None = None) -> None:
        self.counts = counts if counts is not None else dict.fromkeys(DISCOVERED, 2)
        #: What ``current_setting('app.current_tenant_id', true)`` answers.
        #: ``None`` is the cross-tenant case the purge requires.
        self._bound_tenant = bound_tenant
        self.statements: list[str] = []
        self.committed = False
        self.rolled_back = False

    async def scalar(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = " ".join(str(stmt).split())
        self.statements.append(sql)
        if "app.current_tenant_id" in sql:
            return self._bound_tenant
        return None

    async def execute(self, stmt: Any, params: dict[str, Any] | None = None) -> Any:
        sql = " ".join(str(stmt).split())
        self.statements.append(sql)
        if "information_schema" in sql:
            return FakeScalar([(t,) for t in DISCOVERED])
        if sql.upper().startswith("SELECT COUNT(*) FROM TENANTS WHERE ID"):
            return FakeScalar(self.counts.get("tenants", 0))
        if sql.upper().startswith("SELECT COUNT(*)"):
            table = sql.split(" FROM ")[1].split()[0]
            return FakeScalar(self.counts.get(table, 0))
        return FakeScalar(None)

    async def commit(self) -> None:
        self.committed = True

    async def rollback(self) -> None:
        self.rolled_back = True

    def deletes(self) -> list[str]:
        return [s for s in self.statements if s.upper().startswith("DELETE")]


@pytest.fixture
def stub_stores(monkeypatch: pytest.MonkeyPatch) -> dict[str, AsyncMock]:
    """Satellite stores succeed with a fixed row count unless a test says otherwise."""
    stubs: dict[str, AsyncMock] = {}
    for name, store in [
        ("purge_lake", "clickhouse"),
        ("purge_graph", "neo4j"),
        ("purge_vectors", "qdrant"),
        ("purge_cache", "redis"),
    ]:
        mock = AsyncMock(return_value=StoreResult(store=store, rows=3))
        monkeypatch.setattr(tenant_deletion, name, mock)
        stubs[name] = mock
    return stubs


class TestDiscovery:
    async def test_tables_come_from_information_schema(self) -> None:
        """A hardcoded list is right the day it is written and wrong at the
        next migration, and the failure is silent."""
        db = FakeSession()
        tables = await tenant_deletion.discover_tenant_tables(db)
        assert tables == DISCOVERED
        assert any("information_schema" in s for s in db.statements)

    async def test_a_table_with_no_cascade_is_still_deleted(self, stub_stores: Any) -> None:
        """aisoc_institutional_memory has no FK cascade — the exact orphan case."""
        db = FakeSession()
        await delete_tenant(db, TENANT, dry_run=False)
        assert any("DELETE FROM aisoc_institutional_memory" in s for s in db.deletes())

    async def test_unexpected_identifiers_are_refused(self, monkeypatch: pytest.MonkeyPatch, stub_stores: Any) -> None:
        """Table names are interpolated, so they must come only from the catalogue."""

        async def evil(db: Any) -> list[str]:
            return ["alerts; DROP TABLE tenants--"]

        monkeypatch.setattr(tenant_deletion, "discover_tenant_tables", evil)
        db = FakeSession()
        report = await delete_tenant(db, TENANT, dry_run=False)
        pg = next(s for s in report.stores if s.store == "postgres")
        assert not pg.ok
        assert "refusing to touch" in (pg.error or "")
        assert db.deletes() == []


class TestOrdering:
    async def test_tenants_row_is_deleted_last(self, stub_stores: Any) -> None:
        """Deleting it first would cascade tables out from under the count."""
        db = FakeSession()
        await delete_tenant(db, TENANT, dry_run=False)
        deletes = db.deletes()
        assert deletes[-1].upper().startswith("DELETE FROM TENANTS")

    async def test_postgres_runs_after_the_satellite_stores(self, stub_stores: Any) -> None:
        """Otherwise a later failure orphans data with no record naming its owner."""
        db = FakeSession()
        report = await delete_tenant(db, TENANT, dry_run=False)
        assert [s.store for s in report.stores][-1] == "postgres"


class TestPartialFailure:
    async def test_a_failed_store_makes_the_report_incomplete(self, monkeypatch: pytest.MonkeyPatch, stub_stores: Any) -> None:
        monkeypatch.setattr(
            tenant_deletion,
            "purge_graph",
            AsyncMock(return_value=StoreResult(store="neo4j", error="ServiceUnavailable")),
        )
        db = FakeSession()
        report = await delete_tenant(db, TENANT, dry_run=False)
        assert not report.complete

    async def test_postgres_rolls_back_when_another_store_failed(self, monkeypatch: pytest.MonkeyPatch, stub_stores: Any) -> None:
        """Keep the tenant record that names the data still sitting in Neo4j."""
        monkeypatch.setattr(
            tenant_deletion,
            "purge_graph",
            AsyncMock(return_value=StoreResult(store="neo4j", error="ServiceUnavailable")),
        )
        db = FakeSession()
        await delete_tenant(db, TENANT, dry_run=False)
        assert db.rolled_back and not db.committed

    async def test_a_skipped_store_does_not_block_completion(self, monkeypatch: pytest.MonkeyPatch, stub_stores: Any) -> None:
        """Qdrant absent from a deployment is not a failed erase."""
        monkeypatch.setattr(
            tenant_deletion,
            "purge_vectors",
            AsyncMock(return_value=StoreResult(store="qdrant", skipped="QDRANT_URL is not configured")),
        )
        db = FakeSession()
        report = await delete_tenant(db, TENANT, dry_run=False)
        assert report.complete and db.committed


class TestDryRun:
    async def test_dry_run_counts_without_deleting(self, stub_stores: Any) -> None:
        db = FakeSession()
        report = await delete_tenant(db, TENANT, dry_run=True)
        assert report.dry_run
        assert report.total_rows > 0, "a preview that reports nothing is not a preview"
        assert db.deletes() == []
        assert not db.committed

    async def test_dry_run_is_the_default(self, stub_stores: Any) -> None:
        db = FakeSession()
        report = await delete_tenant(db, TENANT)
        assert report.dry_run and db.deletes() == []

    async def test_dry_run_names_the_tables_it_would_hit(self, stub_stores: Any) -> None:
        db = FakeSession()
        report = await delete_tenant(db, TENANT, dry_run=True)
        pg = next(s for s in report.stores if s.store == "postgres")
        assert "aisoc_institutional_memory" in pg.detail
        assert pg.detail["aisoc_institutional_memory"] == 2

    async def test_empty_tables_are_not_listed(self, stub_stores: Any) -> None:
        db = FakeSession(counts={"alerts": 5})
        report = await delete_tenant(db, TENANT, dry_run=True)
        pg = next(s for s in report.stores if s.store == "postgres")
        assert pg.detail == {"alerts": 5}
        assert pg.rows == 5


class TestGraphScope:
    async def test_global_reference_labels_are_excluded(self) -> None:
        """MITRE technique nodes are shared; offboarding must not remove them."""
        captured: list[str] = []

        class FakeRecord(dict):
            pass

        class FakeResult:
            async def single(self) -> Any:
                return FakeRecord(c=0)

        class FakeNeoSession:
            async def run(self, query: str, **kwargs: Any) -> FakeResult:
                captured.append(query)
                return FakeResult()

            async def __aenter__(self) -> FakeNeoSession:
                return self

            async def __aexit__(self, *args: Any) -> None:
                return None

        def session_factory() -> FakeNeoSession:
            return FakeNeoSession()

        original = tenant_deletion.neo4j_session
        tenant_deletion.neo4j_session = session_factory
        try:
            await tenant_deletion.purge_graph(TENANT, dry_run=True)
        finally:
            tenant_deletion.neo4j_session = original

        assert captured
        assert "NOT n:Technique" in captured[0]
        assert "n.tenant_id = $t" in captured[0]


def test_report_serialises_every_store() -> None:
    report = DeletionReport(tenant_id=TENANT, dry_run=False)
    report.stores = [
        StoreResult(store="postgres", rows=10, detail={"alerts": 10}),
        StoreResult(store="neo4j", error="boom"),
    ]
    payload = report.as_dict()
    assert payload["complete"] is False
    assert payload["total_rows"] == 10
    assert {s["store"] for s in payload["stores"]} == {"postgres", "neo4j"}


async def test_a_purge_on_a_tenant_bound_session_refuses_rather_than_deleting_a_fraction() -> None:
    """The one way this can go quiet, made loud.

    The purge is cross-tenant by construction and used to open with
    ``SET LOCAL row_security = off``, which only worked because the deployment
    connected as a superuser. Under the runtime role
    (``migrations/061_runtime_app_role.sql``) that statement raises, so the
    read now rests on the ``OR current_tenant_id() IS NULL`` arm — and a
    session that *did* bind a tenant would delete some of that tenant's rows
    and report the deletion complete. For an operation whose output is a
    compliance claim, that is the worst available outcome.
    """
    db = FakeSession(bound_tenant=str(TENANT))
    result = await tenant_deletion.purge_postgres(db, TENANT, dry_run=False)
    assert result.error and "CrossTenantPreconditionError" in result.error
    assert not db.deletes(), "the purge must refuse before issuing any delete"
