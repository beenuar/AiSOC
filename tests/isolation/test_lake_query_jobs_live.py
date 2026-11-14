"""Cold-tier lake query jobs against real Postgres (depth 4.3).

The three properties worth proving here are all about concurrency and
state, and a mocked session answers whatever the test asked it to:

* **The claim is atomic.** Two API replicas must not both start the same
  cold scan. The claim is one conditional UPDATE, and the only way to
  show that works is to run two of them against one row.
* **A terminal state is never left.** A late progress write or a late
  finish must not resurrect a cancelled job, or rewrite a failure as a
  success.
* **A job id is tenant-scoped.** It is a handle a console holds, so the
  predicate is in the query and row-level security is defence in depth.

Skips when ``ISOLATION_LAKE_JOB_DSN`` is unset; the workflow that owns
this suite sets it unconditionally, because a skip in a job whose whole
purpose is to run live is a pass for the wrong reason.
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_LAKE_JOB_DSN", "").strip(),
        reason="ISOLATION_LAKE_JOB_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_LAKE_JOB_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_LAKE_JOB_DSN is not set")
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


def _admin_dsn() -> str:
    """The owner connection, used only to seed and tear down fixtures.

    The suite runs as the DML-only runtime role, because a suite proving
    a job id is tenant-scoped while connected as a superuser would pass
    with the RLS policy removed. The runtime role cannot insert a
    tenant, so the fixture needs the owner and nothing else does.
    """
    value = os.environ.get("ISOLATION_LAKE_JOB_ADMIN_DSN", "").strip() or _dsn()
    if value.startswith("postgresql://"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def admin_engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    eng = create_async_engine(_admin_dsn())
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory(engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    return async_sessionmaker(engine, expire_on_commit=False)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def tenants(admin_engine):
    from sqlalchemy import text

    a, b = uuid.uuid4(), uuid.uuid4()
    async with admin_engine.begin() as conn:
        for tid, slug in ((a, "lakejob-a"), (b, "lakejob-b")):
            await conn.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :n, :s)"),
                {"id": str(tid), "n": slug, "s": f"{slug}-{uuid.uuid4().hex[:8]}"},
            )
    yield a, b
    async with admin_engine.begin() as conn:
        for tid in (a, b):
            await conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": str(tid)})


async def _make_job(session_factory, tenant_id: uuid.UUID, **overrides):
    from app.models.lake_query_job import LakeQueryJob
    from app.services.lake_query_runner import new_query_id

    job_id = uuid.uuid4()
    values = {
        "id": job_id,
        "tenant_id": tenant_id,
        "submitted_by": uuid.uuid4(),
        "submitted_email": "analyst@example.com",
        "rewritten_sql": "SELECT 1",
        "row_cap": 100,
        "referenced_tables": ["raw_events"],
        "query_id": new_query_id(job_id),
        "estimate": {"cold_bytes": 1234, "estimated_usd": None},
    }
    values.update(overrides)
    async with session_factory() as session:
        job = LakeQueryJob(**values)
        session.add(job)
        await session.commit()
    return job_id


class TestTheClaimIsAtomic:
    async def test_two_interleaved_transactions_produce_one_winner(self, engine, session_factory, tenants):
        """Two API replicas must not both start one cold scan.

        Deterministic rather than a race. The first attempt runs the
        claim and **holds its transaction open**; the second then runs
        the same statement and blocks on the row lock; the first commits;
        the second unblocks and re-evaluates ``status = 'queued'``
        against the committed row.

        The interleaving is forced rather than hoped for because a plain
        ``asyncio.gather`` of five claims passes under a
        SELECT-then-UPDATE implementation as well — measured, by
        subverting the claim and watching that version stay green. A
        concurrency test that cannot fail on the broken implementation
        is not a concurrency test.

        It runs ``claim_statement`` itself, not a re-typed copy: a proof
        against a hand-written statement proves something about the
        test.
        """
        from app.services.lake_query_runner import claim_statement

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a)

        first_claimed: list[bool] = []
        second_claimed: list[bool] = []
        first_has_run = asyncio.Event()

        async def first() -> None:
            async with engine.connect() as conn:
                await conn.begin()
                result = await conn.execute(claim_statement(job_id))
                first_claimed.append(result.scalar_one_or_none() is not None)
                first_has_run.set()
                # Hold the lock long enough for the second attempt to
                # reach the same row and block on it.
                await asyncio.sleep(0.5)
                await conn.commit()

        async def second() -> None:
            await first_has_run.wait()
            await asyncio.sleep(0.1)
            async with engine.connect() as conn:
                await conn.begin()
                result = await conn.execute(claim_statement(job_id))
                second_claimed.append(result.scalar_one_or_none() is not None)
                await conn.commit()

        await asyncio.gather(first(), second())

        assert first_claimed == [True], "the first attempt did not claim the job"
        assert second_claimed == [False], "both transactions claimed the same job, so two replicas would both run the scan"

    async def test_a_job_that_is_not_queued_cannot_be_claimed(self, session_factory, tenants):
        from app.services.lake_query_runner import claim_job

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a, status="succeeded")
        async with session_factory() as session:
            assert await claim_job(session, job_id) is False

    async def test_claiming_records_when_it_started(self, session_factory, tenants):
        from app.models.lake_query_job import LakeQueryJob
        from app.services.lake_query_runner import claim_job

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a)
        async with session_factory() as session:
            assert await claim_job(session, job_id) is True
        async with session_factory() as session:
            job = await session.get(LakeQueryJob, job_id)
            assert job.status == "running"
            assert job.started_at is not None


class TestATerminalStateIsNeverLeft:
    async def test_a_cancelled_job_is_not_overwritten_by_a_late_finish(self, session_factory, tenants):
        """The predicate on ``_finish`` is the whole mechanism: a scan
        that completes after an operator cancelled it must not report
        success."""
        from app.models.lake_query_job import LakeQueryJob
        from app.services.lake_query_runner import _finish, claim_job

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a)
        async with session_factory() as session:
            await claim_job(session, job_id)
        async with session_factory() as session:
            job = await session.get(LakeQueryJob, job_id)
            job.status = "cancelled"
            await session.commit()

        await _finish(session_factory, job_id, status="succeeded", row_count=9)

        async with session_factory() as session:
            job = await session.get(LakeQueryJob, job_id)
            assert job.status == "cancelled"
            assert job.row_count is None

    async def test_cancelling_an_ended_job_is_refused(self, session_factory, tenants):
        from app.models.lake_query_job import LakeQueryJob
        from app.services.lake_query_runner import cancel_job

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a, status="succeeded")
        async with session_factory() as session:
            job = await session.get(LakeQueryJob, job_id)
            assert await cancel_job(session, job) is False

    async def test_progress_is_not_written_onto_a_finished_job(self, session_factory, tenants):
        from app.models.lake_query_job import LakeQueryJob
        from app.services.lake_cold_query import QueryProgress
        from app.services.lake_query_runner import _record_progress

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a, status="succeeded")
        await _record_progress(
            session_factory,
            job_id,
            QueryProgress(rows_read=42, bytes_read=1, total_rows_approx=100, elapsed_seconds=1.0),
        )
        async with session_factory() as session:
            job = await session.get(LakeQueryJob, job_id)
            assert job.rows_read == 0, "a late progress read resurrected a finished job"


class TestProgressIsHonest:
    async def test_an_unknown_denominator_stores_null_not_zero(self, session_factory, tenants):
        from app.models.lake_query_job import LakeQueryJob
        from app.services.lake_cold_query import QueryProgress
        from app.services.lake_query_runner import _record_progress, claim_job

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a)
        async with session_factory() as session:
            await claim_job(session, job_id)

        await _record_progress(
            session_factory,
            job_id,
            QueryProgress(rows_read=500, bytes_read=10, total_rows_approx=0, elapsed_seconds=2.0),
        )
        async with session_factory() as session:
            job = await session.get(LakeQueryJob, job_id)
            assert job.rows_read == 500
            assert job.progress_ratio is None, "unknown progress was stored as a number"

    async def test_a_known_denominator_stores_a_ratio(self, session_factory, tenants):
        from app.models.lake_query_job import LakeQueryJob
        from app.services.lake_cold_query import QueryProgress
        from app.services.lake_query_runner import _record_progress, claim_job

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a)
        async with session_factory() as session:
            await claim_job(session, job_id)
        await _record_progress(
            session_factory,
            job_id,
            QueryProgress(rows_read=250, bytes_read=10, total_rows_approx=1000, elapsed_seconds=2.0),
        )
        async with session_factory() as session:
            job = await session.get(LakeQueryJob, job_id)
            assert job.progress_ratio == pytest.approx(0.25)


class TestTenantScoping:
    async def test_another_tenants_job_is_not_found(self, session_factory, tenants):
        from app.api.v1.endpoints.lake import _load_job
        from fastapi import HTTPException

        tenant_a, tenant_b = tenants
        job_id = await _make_job(session_factory, tenant_b)
        async with session_factory() as session:
            with pytest.raises(HTTPException) as exc:
                await _load_job(session, tenant_a, job_id)
        assert exc.value.status_code == 404

    async def test_the_callers_own_job_is_found(self, session_factory, tenants):
        from app.api.v1.endpoints.lake import _load_job

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a)
        async with session_factory() as session:
            job = await _load_job(session, tenant_a, job_id)
        assert job.id == job_id


class TestStuckJobsAreVisible:
    async def test_a_job_whose_runner_died_is_reported(self, session_factory, tenants):
        """A job stuck at ``running`` with no task behind it reads to an
        analyst as a query that is still working."""
        from app.services.lake_query_runner import list_stuck_jobs

        tenant_a, _ = tenants
        job_id = await _make_job(
            session_factory,
            tenant_a,
            status="running",
            started_at=datetime.now(UTC) - timedelta(hours=2),
        )
        async with session_factory() as session:
            stuck = await list_stuck_jobs(session, older_than_seconds=900)
        assert job_id in {job.id for job in stuck}

    async def test_a_job_that_started_recently_is_not_reported(self, session_factory, tenants):
        from app.services.lake_query_runner import list_stuck_jobs

        tenant_a, _ = tenants
        job_id = await _make_job(session_factory, tenant_a, status="running", started_at=datetime.now(UTC))
        async with session_factory() as session:
            stuck = await list_stuck_jobs(session, older_than_seconds=900)
        assert job_id not in {job.id for job in stuck}
