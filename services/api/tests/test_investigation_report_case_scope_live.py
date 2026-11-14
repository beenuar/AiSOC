"""The report.md ledger fallback stays inside the case named in the URL.

When agents can answer, ``case_investigation_report_md`` reads the run's
``case_id`` back and 404s if it names a different case. The cold path has to
match that, or the fallback is the weaker of the two doors: a caller who knows
any run id in their tenant could read its report through whatever case they
happen to be looking at. ``investigation_artifacts`` carries no case id, so the
binding has to go through ``investigation_runs``.

Against real Postgres and the real models, because the thing under test is a
WHERE clause. A session double answers whatever it is asked and would pass with
the predicate deleted, which is exactly how this shipped.

Skips without a database rather than passing without one.
"""

from __future__ import annotations

import hashlib
import os
import uuid

import pytest
import pytest_asyncio
from app.api.v1.endpoints.cases import _ledger_report_md
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e700000-0000-0000-0000-0000000016a1")
CASE_A = uuid.UUID("0e700000-0000-0000-0000-00000000aaaa")
CASE_B = uuid.UUID("0e700000-0000-0000-0000-00000000bbbb")
RUN_B = uuid.UUID("0e700000-0000-0000-0000-00000000cc0b")
BODY_B = "# Case B report — only reachable through case B"


@pytest_asyncio.fixture
async def db():
    if "postgres" not in DSN and not REQUIRED:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(f"MSSP_ISOLATION_REQUIRED is set and no database answered at DATABASE_URL: {type(exc).__name__}: {exc}")
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await session.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, 'scope', :s) ON CONFLICT (id) DO NOTHING"),
            {"i": TENANT, "s": f"scope-{TENANT.hex[:8]}"},
        )
        # One run, belonging to case B, with its report persisted.
        await session.execute(
            text(
                "INSERT INTO investigation_runs (id, tenant_id, case_id, status) "
                "VALUES (:i, :t, :c, 'completed') ON CONFLICT (id) DO NOTHING"
            ),
            {"i": RUN_B, "t": TENANT, "c": str(CASE_B)},
        )
        await session.execute(
            text(
                "INSERT INTO investigation_artifacts "
                "  (id, run_id, tenant_id, kind, content, sha256, size_bytes) "
                "VALUES (:i, :r, :t, 'report_md', :c, :h, :n)"
            ),
            {
                "i": uuid.uuid4(),
                "r": RUN_B,
                "t": TENANT,
                "c": BODY_B,
                "h": hashlib.sha256(BODY_B.encode()).hexdigest(),
                "n": len(BODY_B.encode()),
            },
        )
        await session.commit()
        try:
            yield session
        finally:
            await session.rollback()
            await session.execute(text("DELETE FROM investigation_runs WHERE id = :i"), {"i": RUN_B})
            await session.commit()
    await engine.dispose()


@pytest.mark.asyncio
async def test_another_cases_report_is_not_served_under_this_case(db) -> None:
    """Case A's URL must not yield case B's report body."""
    assert await _ledger_report_md(db, TENANT, CASE_A, str(RUN_B)) is None


@pytest.mark.asyncio
async def test_the_cases_own_report_is_still_served(db) -> None:
    """Positive control: the scoping must not block the legitimate read.

    Without this, deleting the artifact lookup entirely would satisfy the test
    above — a refusal that refuses everything is not a fix.
    """
    assert await _ledger_report_md(db, TENANT, CASE_B, str(RUN_B)) == BODY_B


@pytest.mark.asyncio
async def test_another_tenant_cannot_read_it_either(db) -> None:
    """The tenant predicate still stands alongside the case predicate."""
    assert await _ledger_report_md(db, uuid.uuid4(), CASE_B, str(RUN_B)) is None
