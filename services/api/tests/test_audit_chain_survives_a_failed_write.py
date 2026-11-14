"""A failed best-effort write must not take the audit row with it.

What was observed
-----------------
Against a running CORE stack, `POST /api/v1/alerts/{id}/explain` answered 200
and logged two lines:

    WARNING explain.cost_track_failed … NotNullViolationError: null value in
            column "total_cost_usd" of relation "aisoc_run_costs" violates
            not-null constraint
    WARNING audit: failed to compute hash chain for tenant=… action=alerts.explain

Only the first names a cause. `_impute_public_cost` returns `None` for a model
with no published list price — the normal case for the local model CORE ships
— and that `None` went straight into a `NOT NULL` column. The caller caught
the Python exception, which does not undo PostgreSQL aborting the
transaction, so every later statement on the session failed too.

The audit row was not merely written unchained. Its own `INSERT` ran on the
same aborted transaction and failed as well, so `audit_log` held no
`alerts.explain` row at all — confirmed against the database afterwards:

    action        | unchained | created_at
    alerts:create | f         | 2026-09-28 15:58:59.818406+00
    (1 row)

Why these assertions run rather than read
-----------------------------------------
Every one of these drives a real transaction against SQLite with
`SAVEPOINT` semantics, because the property under test is a database
behaviour and not a shape in the source. A test that asserted
"`_record_llm_cost` is wrapped in try/except" would have passed throughout:
it *was*.
"""

from __future__ import annotations

import os
import socket
import uuid
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from app.db.best_effort import attempt, savepoint
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


@pytest_asyncio.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.execute(text("CREATE TABLE widget (id TEXT PRIMARY KEY, name TEXT NOT NULL)"))
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db:
        yield db
    await engine.dispose()


async def _insert(db: AsyncSession, name: str | None) -> None:
    await db.execute(text("INSERT INTO widget (id, name) VALUES (:i, :n)"), {"i": str(uuid.uuid4()), "n": name})


class TestAFailedOptionalWriteLeavesTheSessionUsable:
    @pytest.mark.asyncio
    async def test_a_savepoint_confines_the_failure(self, session: AsyncSession) -> None:
        _, exc = await attempt(session, lambda: _insert(session, None))
        assert exc is not None, "the failure must still reach the caller — silence is the other defect"

        # The work that used to be collateral damage.
        await _insert(session, "the audit row")
        rows = (await session.execute(text("SELECT name FROM widget"))).scalars().all()
        assert rows == ["the audit row"]

    @pytest.mark.asyncio
    async def test_a_successful_operation_still_commits(self, session: AsyncSession) -> None:
        """The other direction. A savepoint that rolled back unconditionally
        would pass the test above and silently discard every optional write."""
        result, exc = await attempt(session, lambda: _insert(session, "kept"))
        assert exc is None
        assert result is None or result is not None  # `_insert` returns None; the point is it ran
        rows = (await session.execute(text("SELECT name FROM widget"))).scalars().all()
        assert rows == ["kept"]

    @pytest.mark.asyncio
    async def test_the_context_manager_reraises(self, session: AsyncSession) -> None:
        with pytest.raises(Exception):  # noqa: B017, PT011 - driver-specific integrity error
            async with savepoint(session):
                await _insert(session, None)
        await _insert(session, "still works")


class TestTheExplainCostWriterCannotProduceNull:
    """`total_cost_usd` is NOT NULL and the imputer returns None by design.

    `_impute_public_cost` returning `None` is deliberate — "this model has no
    published price" and "this model is free" are different facts. The defect
    was the writer treating that as a number.
    """

    def test_an_unpriced_model_is_counted_not_costed(self) -> None:
        from app.services.alert_explain import _UPSERT_RUN_COST

        sql = str(_UPSERT_RUN_COST)
        assert ":cost_usd" not in sql, "the nullable imputed figure must not reach a NOT NULL column"
        for column in ("estimated_cost_usd", "estimated_call_count", "unpriced_call_count"):
            assert column in sql, f"migration 063 adds {column} and this writer must use it"

    def test_the_imputer_still_returns_none_for_an_unknown_model(self) -> None:
        """Pinned. Making the imputer return 0.0 would 'fix' the crash by
        publishing a price nobody charges — the exact defect migration 063
        exists to prevent."""
        from app.services.cost_dashboard import _impute_public_cost

        assert _impute_public_cost("ollama/llama3.2:3b", 100, 100) is None


# ─── The abort itself, which only PostgreSQL does ────────────────────────────
#
# SQLite does not abort a transaction on a constraint violation — the next
# statement succeeds — so the assertions above exercise the savepoint
# mechanics and cannot reproduce the defect. The defect is PostgreSQL's
# "current transaction is aborted, commands ignored until end of transaction
# block", and reproducing it needs PostgreSQL. Same arrangement as
# `tests/isolation/test_postgres_rls.py`: skipped without a DSN locally, and
# `POSTGRES_ABORT_SEMANTICS_REQUIRED=1` in CI turns the skip into a failure so
# it cannot go quiet.

#: The **owner** DSN, not the runtime one.
#:
#: The fixture below creates a scratch table, and the role the services
#: connect as is DML-only so that row-level security applies to it — it
#: answers `permission denied for schema public` on any DDL, which is the
#: role split working as designed. `tests/isolation/test_postgres_rls.py`
#: resolves the owner the same way, and falls back to the runtime DSN so a
#: single-role deployment still runs.
#:
#: The property under test — PostgreSQL aborting a transaction on a statement
#: error — does not depend on which role holds the connection.
_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("POSTGRES_ABORT_SEMANTICS_REQUIRED", "").strip() not in ("", "0", "false")


def _postgres_is_listening() -> bool:
    """Whether something actually answers on the DSN's host and port.

    Reading the DSN alone is not enough. The unit-test job exports a
    `postgres://…localhost:5432` URL with no server behind it, so a
    string check decided the test should run and it died on
    `Connect call failed`. A DSN is a statement of intent; this asks.
    """
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


#: `POSTGRES_ABORT_SEMANTICS_REQUIRED=1` still overrides, so integration.yml
#: fails loudly rather than skipping if its Postgres is missing.
_HAVE_POSTGRES = "postgres" in _DSN and _postgres_is_listening()


@pytest.mark.skipif(
    not _HAVE_POSTGRES and not _REQUIRED,
    reason="needs a live Postgres — abort-on-error is a PostgreSQL behaviour and SQLite does not have it",
)
class TestPostgresAbortsTheWholeTransaction:
    @pytest_asyncio.fixture
    async def pg(self):
        engine = create_async_engine(_DSN)
        table = f"aisoc_abort_probe_{uuid.uuid4().hex[:8]}"
        async with engine.begin() as conn:
            await conn.execute(text(f"CREATE TABLE {table} (id TEXT PRIMARY KEY, name TEXT NOT NULL)"))
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as db:
            yield db, table
        async with engine.begin() as conn:
            await conn.execute(text(f"DROP TABLE IF EXISTS {table}"))
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_an_unprotected_failure_poisons_everything_after_it(self, pg) -> None:
        """The pre-fix arrangement, written out so the difference is visible.

        A bare try/except around the failing statement. The exception is
        caught, the caller carries on, and the *next* statement fails — which
        is how a cost-tracking bug deleted an audit event.
        """
        db, table = pg
        try:
            await db.execute(text(f"INSERT INTO {table} (id, name) VALUES ('a', NULL)"))
        except Exception:  # noqa: BLE001 - the shape under test
            pass

        with pytest.raises(Exception, match="(?i)current transaction is aborted|InFailedSqlTransaction|PendingRollback"):
            await db.execute(text(f"INSERT INTO {table} (id, name) VALUES ('b', 'the audit row')"))

    @pytest.mark.asyncio
    async def test_a_savepoint_confines_it(self, pg) -> None:
        db, table = pg
        _, exc = await attempt(db, lambda: db.execute(text(f"INSERT INTO {table} (id, name) VALUES ('a', NULL)")))
        assert exc is not None

        await db.execute(text(f"INSERT INTO {table} (id, name) VALUES ('b', 'the audit row')"))
        await db.commit()
        rows = (await db.execute(text(f"SELECT name FROM {table}"))).scalars().all()
        assert rows == ["the audit row"]
