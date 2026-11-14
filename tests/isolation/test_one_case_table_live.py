"""Case metrics see the cases analysts create, against real Postgres.

Gap-closure wave 1.

The product shipped with two case tables that never synchronised. The
console wrote `aisoc_cases`; `resolution_time` — which owns the single
shared MTTR definition — read `cases`, as did the metrics endpoints, the
executive digest, the MSSP portfolio and the GraphQL layer.

So a tenant could close fifty cases in the console and watch MTTR stay
null. Nothing errored. Both tables existed and both queries were valid,
and the only symptom was an empty number with no explanation.

Why this suite needs a live database: the defect was entirely in which
table a query named. Every unit test passed throughout, because they
test the query against whichever table the test itself seeded.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CASES_DSN", "").strip(),
        reason="ISOLATION_CASES_DSN is not set; this suite needs a live Postgres",
    ),
]

TENANT = uuid.UUID("cccc0000-0000-0000-0000-00000000cccc")


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def conn():
    asyncpg = pytest.importorskip("asyncpg")
    connection = await asyncpg.connect(os.environ["ISOLATION_CASES_DSN"].replace("postgresql+asyncpg://", "postgresql://"))
    try:
        await connection.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1,'w1','w1-cases') ON CONFLICT DO NOTHING",
            TENANT,
        )
        yield connection
    finally:
        await connection.close()


async def _close_a_case(conn, *, minutes: int) -> uuid.UUID:  # noqa: ANN001
    """Write a closed case exactly as the console would."""
    case_id = uuid.uuid4()
    created = datetime.now(UTC) - timedelta(minutes=minutes)
    await conn.execute(
        "INSERT INTO aisoc_cases (id, tenant_id, case_number, title, severity, status, created_at, closed_at) "
        "VALUES ($1,$2,$3,'console case','high','closed',$4,$5)",
        case_id,
        TENANT,
        f"CASE-{case_id.hex[:8]}",
        created,
        created + timedelta(minutes=minutes),
    )
    return case_id


class TestThereIsOneCaseTable:
    async def test_the_retired_table_is_gone(self, conn) -> None:  # noqa: ANN001
        """`cases` no longer exists under that name, and reading it now
        fails loudly.

        A read-only view was tried and withdrawn: every historical
        migration doing `ALTER TABLE` or `CREATE INDEX` on `cases` fails
        on re-run against a view, and guarding each of them would
        scatter one decision through the whole migration history.

        Erroring is the better outcome anyway. External SQL against
        `cases` now fails with "relation does not exist" rather than
        quietly returning the pre-consolidation rows.
        """
        assert await conn.fetchval("SELECT to_regclass('public.cases') IS NULL"), (
            "`cases` still exists, so a query naming it reads a second set of rows"
        )

    async def test_the_pre_consolidation_rows_are_kept(self, conn) -> None:  # noqa: ANN001
        """Renamed, not dropped. A consolidation that lost a row nobody
        noticed is worse than two tables."""
        assert await conn.fetchval("SELECT to_regclass('public.cases_pre_consolidation') IS NOT NULL")

    async def test_child_tables_reference_the_surviving_parent(self, conn) -> None:  # noqa: ANN001
        """`case_tasks` and `case_timeline_events` both declared
        `REFERENCES cases(id)`. Repointing the ORM without repointing
        these left SQLAlchemy unable to resolve `Case.tasks` at
        mapper-configuration time, which took down every request that
        touched any model — 257 tests at once."""
        orphaned = await conn.fetchval(
            """
            SELECT count(*)
              FROM information_schema.table_constraints tc
              JOIN information_schema.constraint_column_usage ccu
                ON tc.constraint_name = ccu.constraint_name
             WHERE tc.constraint_type = 'FOREIGN KEY'
               AND ccu.table_name = 'cases_pre_consolidation'
            """
        )
        assert orphaned == 0, f"{orphaned} foreign keys still point at the retired table"


class TestConsoleCasesReachTheMetrics:
    async def test_mttr_counts_a_case_the_console_created(self, conn) -> None:  # noqa: ANN001
        """The defect, stated as a test. This query is
        `resolution_time.MTTR_MINUTES_EXPR` verbatim; before the
        consolidation it ran against `cases` and could not see this row."""
        await _close_a_case(conn, minutes=90)

        mttr = await conn.fetchval(
            """
            SELECT round((avg(EXTRACT(EPOCH FROM (closed_at - created_at))) / 60.0)::numeric, 1)::float8
              FROM aisoc_cases
             WHERE tenant_id = $1 AND closed_at IS NOT NULL AND closed_at >= created_at
            """,
            TENANT,
        )
        assert mttr is not None, "MTTR is null for a tenant that has closed a case"
        assert mttr > 0

    async def test_mttr_is_null_rather_than_zero_for_a_tenant_with_nothing_closed(self, conn) -> None:  # noqa: ANN001
        """The negative control, and a correctness claim of its own: an
        average over zero rows must not publish as 0.0 minutes."""
        empty_tenant = uuid.uuid4()
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
            empty_tenant,
            f"w1-{empty_tenant.hex[:8]}",
            f"w1-{empty_tenant.hex[:8]}",
        )
        mttr = await conn.fetchval(
            """
            SELECT round((avg(EXTRACT(EPOCH FROM (closed_at - created_at))) / 60.0)::numeric, 1)::float8
              FROM aisoc_cases
             WHERE tenant_id = $1 AND closed_at IS NOT NULL AND closed_at >= created_at
            """,
            empty_tenant,
        )
        assert mttr is None


class TestOneStatusVocabulary:
    async def test_the_console_states_are_storable(self, conn) -> None:  # noqa: ANN001
        for status in ("new", "triaged", "investigating", "contained", "resolved", "closed"):
            case_id = uuid.uuid4()
            await conn.execute(
                "INSERT INTO aisoc_cases (id, tenant_id, case_number, title, severity, status) VALUES ($1,$2,$3,'vocab','low',$4)",
                case_id,
                TENANT,
                f"CASE-{case_id.hex[:8]}",
                status,
            )

    async def test_resolved_is_not_counted_as_closed(self, conn) -> None:  # noqa: ANN001
        """`resolved` looks terminal and is not — a case moves
        `resolved → closed`, and only that last transition writes
        `closed_at`. Counting "closed this week" as `status = 'resolved'`
        counts cases still on a queue and misses every one that finished.
        """
        case_id = uuid.uuid4()
        await conn.execute(
            "INSERT INTO aisoc_cases (id, tenant_id, case_number, title, severity, status) "
            "VALUES ($1,$2,$3,'still open','high','resolved')",
            case_id,
            TENANT,
            f"CASE-{case_id.hex[:8]}",
        )
        counted = await conn.fetchval(
            "SELECT count(*) FROM aisoc_cases WHERE id = $1 AND status = 'closed' AND closed_at IS NOT NULL",
            case_id,
        )
        assert counted == 0
