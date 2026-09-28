"""`ensure_columns` must not ask for a privilege it does not need.

The cost writer applied its provenance columns with

    ALTER TABLE aisoc_run_costs ADD COLUMN IF NOT EXISTS ...

and caught the failure into a warning. `IF NOT EXISTS` reads as "harmless
when they are already there", and it is not: Postgres checks ownership
*before* the existence test, so on a database where all six columns exist the
statement still raises ``must be owner of table aisoc_run_costs`` for the
DML-only runtime role the services connect as.

Measured against a live CORE stack, that fired on **every** triage run:

    cost_telemetry.provenance_columns_unavailable
    error='must be owner of table aisoc_run_costs'

while the six columns were present and the rows carrying them were being
written. A warning that names a working subsystem, and points the operator at
a migration that had already run, costs more than it is worth — it is the
"diagnostic that sends you to debug something that is not broken" shape this
repository keeps finding.

`ensure_table` already had the answer in its own module docstring: look
before leaping. These tests pin that `ensure_columns` does the same, in both
directions — silent when the columns are there, loud when they genuinely are
not.
"""

from __future__ import annotations

import pytest
from app.core.schema_bootstrap import ensure_columns

COLUMNS = ("measured_cost_usd", "resolved_model")
DDL = "ALTER TABLE aisoc_run_costs ADD COLUMN IF NOT EXISTS measured_cost_usd DOUBLE PRECISION;"


class FakeConn:
    """Postgres as the DML-only role sees it: `execute` may be refused."""

    def __init__(self, present: tuple[str, ...], *, execute_error: Exception | None = None) -> None:
        self._present = present
        self._execute_error = execute_error
        self.executed: list[str] = []
        self.probes = 0

    async def fetch(self, _sql: str, _table: str) -> list[dict[str, str]]:
        self.probes += 1
        return [{"column_name": name} for name in self._present]

    async def execute(self, sql: str) -> None:
        self.executed.append(sql)
        if self._execute_error is not None:
            raise self._execute_error


@pytest.mark.asyncio
async def test_present_columns_are_not_altered_at_all() -> None:
    """The case that was firing a warning on every run."""
    conn = FakeConn(present=COLUMNS + ("run_id", "tenant_id"))

    assert await ensure_columns(conn, "aisoc_run_costs", COLUMNS, DDL) is True
    assert conn.executed == [], "asked for ALTER privilege it did not need"
    assert conn.probes == 1


@pytest.mark.asyncio
async def test_a_role_without_ownership_stays_quiet_when_the_columns_exist() -> None:
    """The regression, stated as the deployment that produced it.

    An `execute` that would raise `must be owner` must never be reached, so
    configuring one and finding nothing logged is the assertion.
    """
    conn = FakeConn(
        present=COLUMNS,
        execute_error=RuntimeError("must be owner of table aisoc_run_costs"),
    )

    assert await ensure_columns(conn, "aisoc_run_costs", COLUMNS, DDL) is True
    assert conn.executed == []


@pytest.mark.asyncio
async def test_genuinely_missing_columns_are_still_added() -> None:
    conn = FakeConn(present=("run_id",))

    assert await ensure_columns(conn, "aisoc_run_costs", COLUMNS, DDL) is True
    assert conn.executed == [DDL]


@pytest.mark.asyncio
async def test_one_missing_column_is_enough_to_apply_the_ddl() -> None:
    """A partially-migrated table must converge, not be read as done."""
    conn = FakeConn(present=("measured_cost_usd",))

    assert await ensure_columns(conn, "aisoc_run_costs", COLUMNS, DDL) is True
    assert conn.executed == [DDL]


@pytest.mark.asyncio
async def test_a_refusal_on_genuinely_missing_columns_is_reported_and_not_raised() -> None:
    """Loud, but never fatal: the token counts still land without them."""
    conn = FakeConn(
        present=("run_id",),
        execute_error=RuntimeError("must be owner of table aisoc_run_costs"),
    )

    assert await ensure_columns(conn, "aisoc_run_costs", COLUMNS, DDL) is False
    assert conn.executed == [DDL]


@pytest.mark.asyncio
async def test_a_failed_probe_does_not_take_the_agent_down() -> None:
    class DeadConn(FakeConn):
        async def fetch(self, _sql: str, _table: str):  # type: ignore[override]
            raise RuntimeError("connection is closed")

    assert await ensure_columns(DeadConn(present=()), "aisoc_run_costs", COLUMNS, DDL) is False
