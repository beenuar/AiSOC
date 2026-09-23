"""Every store that holds schema must have a way to change it.

`clickhouse/001_init.sql` is four `CREATE TABLE IF NOT EXISTS` statements
and zero `ALTER TABLE`; `lake_writer` self-heals with the same idiom. Both
are no-ops once the table exists, so a new column lands on a fresh
deployment and silently does not land on an existing one — and nothing
notices until a query selects a column that is not there, long after the
deploy that was meant to add it.

The tests are mostly about the properties that make a runner trustworthy
rather than about any individual migration: ids never move, a failure stops
the run, and the ledger is read from the store being migrated rather than
somewhere that can drift from it.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from app.db import graph_migrations, lake_migrations, vector_migrations

ALL_RUNNERS = (
    ("neo4j", graph_migrations),
    ("clickhouse", lake_migrations),
    ("qdrant", vector_migrations),
)


class TestEveryStoreHasARunner:
    """The plan called the absence of these a blocker, not a follow-up."""

    @pytest.mark.parametrize(("store", "module"), ALL_RUNNERS, ids=lambda x: str(x))
    def test_runner_exposes_the_same_interface(self, store: str, module: Any) -> None:
        """Three stores, one shape. An operator should not have to learn
        three vocabularies to answer "what has this deployment applied"."""
        for name in ("MIGRATIONS", "run_migrations", "applied_ids", "pending_ids"):
            assert hasattr(module, name), f"{store} runner has no {name}"

    @pytest.mark.parametrize(("store", "module"), ALL_RUNNERS, ids=lambda x: str(x))
    def test_ids_are_unique_and_ordered(self, store: str, module: Any) -> None:
        ids = [m.id for m in module.MIGRATIONS]
        assert len(ids) == len(set(ids)), f"{store} has duplicate migration ids"
        assert ids == sorted(ids), (
            f"{store} migrations are not in id order; the runner applies them "
            f"in tuple order, so a mismatch means they run in an order the "
            f"numbering does not describe"
        )

    @pytest.mark.parametrize(("store", "module"), ALL_RUNNERS, ids=lambda x: str(x))
    def test_every_migration_is_described(self, store: str, module: Any) -> None:
        """A migration whose purpose nobody wrote down cannot be reviewed,
        and cannot be judged safe to re-run."""
        for migration in module.MIGRATIONS:
            assert migration.description.strip(), f"{store}/{migration.id}"

    @pytest.mark.parametrize(("store", "module"), ALL_RUNNERS, ids=lambda x: str(x))
    def test_the_first_migration_is_a_baseline(self, store: str, module: Any) -> None:
        """An existing deployment must converge rather than re-run unknown
        statements against a schema that already has them."""
        first = module.MIGRATIONS[0]
        assert "baseline" in first.id or "core" in first.id, (
            f"{store}'s first migration is {first.id!r}; it should record the " f"pre-existing schema so existing deployments converge"
        )


class TestLakeRunner:
    @pytest.fixture
    def client(self) -> AsyncMock:
        c = AsyncMock()
        c.execute = AsyncMock(return_value=[])
        return c

    async def test_applies_and_records(self, client: AsyncMock) -> None:
        applied = await lake_migrations.run_migrations(client)
        assert applied == ["001_baseline"]
        statements = [call.args[0] for call in client.execute.await_args_list]
        assert any("_migrations" in s for s in statements), "ledger was not created"
        assert any("INSERT INTO" in s for s in statements), "nothing was recorded"

    async def test_an_applied_migration_is_not_reapplied(self, client: AsyncMock) -> None:
        client.execute = AsyncMock(return_value=[("001_baseline",)])
        assert await lake_migrations.run_migrations(client) == []

    async def test_a_failure_stops_the_run(self, client: AsyncMock) -> None:
        """Migration N+1 is written against the schema N produced."""
        calls = {"n": 0}

        async def failing(sql: str, params: Any = None) -> Any:
            calls["n"] += 1
            if "CREATE DATABASE" in sql:
                raise RuntimeError("no such cluster")
            return []

        client.execute = failing
        with pytest.raises(RuntimeError, match="no such cluster"):
            await lake_migrations.run_migrations(client)

    async def test_non_strict_returns_what_succeeded(self, client: AsyncMock) -> None:
        async def failing(sql: str, params: Any = None) -> Any:
            if "CREATE DATABASE" in sql:
                raise RuntimeError("boom")
            return []

        client.execute = failing
        assert await lake_migrations.run_migrations(client, strict=False) == []

    async def test_drives_a_command_style_client(self) -> None:
        """Two ClickHouse client shapes are in use across this repo. A
        runner that speaks one silently does not run in half the
        deployments."""
        c = AsyncMock()
        del c.execute
        c.command = AsyncMock(return_value=[])
        await lake_migrations.run_migrations(c)
        assert c.command.await_count > 0

    async def test_an_undrivable_client_is_a_loud_failure(self) -> None:
        class Opaque:
            pass

        with pytest.raises(TypeError, match="neither execute"):
            await lake_migrations._execute(Opaque(), "SELECT 1")

    async def test_an_unreadable_ledger_is_a_first_run_not_a_crash(self, client: AsyncMock) -> None:
        async def execute(sql: str, params: Any = None) -> Any:
            if "SELECT migration_id" in sql:
                raise RuntimeError("table does not exist")
            return []

        client.execute = execute
        assert await lake_migrations.applied_ids(client) == set()

    @pytest.mark.parametrize("row", [("001_baseline",), {"migration_id": "001_baseline"}, "001_baseline"])
    async def test_reads_every_driver_row_shape(self, client: AsyncMock, row: Any) -> None:
        """Drivers return tuples, dicts or scalars. Reading one shape means
        the runner re-applies everything against the others."""
        client.execute = AsyncMock(return_value=[row])
        assert await lake_migrations.applied_ids(client) == {"001_baseline"}


class TestVectorRunner:
    @pytest.fixture
    def client(self) -> AsyncMock:
        c = AsyncMock()
        c.get_collections = AsyncMock(return_value=type("R", (), {"collections": []})())
        c.scroll = AsyncMock(return_value=([], None))
        return c

    async def test_applies_and_records(self, client: AsyncMock) -> None:
        pytest.importorskip("qdrant_client")
        applied = await vector_migrations.run_migrations(client)
        assert applied == ["001_baseline"]
        client.upsert.assert_awaited_once()

    async def test_point_ids_are_stable_across_processes(self) -> None:
        """Keyed on hash() the ledger would record the same migration under a
        different id every restart, and the runner would re-apply
        everything — the same salted-hash bug the sandbox had."""
        first = vector_migrations._point_id("001_baseline")
        assert first == vector_migrations._point_id("001_baseline")
        assert first != vector_migrations._point_id("002_other")
        assert first > 0, "Qdrant point ids must be unsigned"

    async def test_a_rebuild_is_flagged_before_it_starts(self) -> None:
        """A dimension change re-embeds every point. The difference between
        a one-second migration and a four-hour one should not be discovered
        at deploy time."""
        assert hasattr(vector_migrations, "pending_rebuilds")
        for migration in vector_migrations.MIGRATIONS:
            assert isinstance(migration.rebuilds_collection, bool)

    async def test_an_unreadable_ledger_is_a_first_run(self, client: AsyncMock) -> None:
        pytest.importorskip("qdrant_client")
        client.scroll = AsyncMock(side_effect=RuntimeError("collection missing"))
        assert await vector_migrations.applied_ids(client) == set()
