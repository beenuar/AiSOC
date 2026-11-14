"""Running a cold-tier lake query as a job, and reporting its progress.

Depth plan 4.3. The synchronous path at ``POST /lake/sql`` is bounded by
the published 30-second default and 60-second maximum. A scan that has to
read the cold volume is routed here instead, where it reports what it is
doing rather than disappearing until it either returns or raises a
timeout.

Three things this module is careful about, each because the opposite has
shipped in this repository before.

**A claim is atomic.** The runner claims a job with a conditional UPDATE
rather than a SELECT followed by an UPDATE, so two API replicas cannot
both start the same scan. Two concurrent reads of the cold volume for one
analyst's question is the cost of getting that wrong.

**Progress is the server's.** ``rows_read`` and ``total_rows_approx``
come from ``system.processes``. Nothing here derives a percentage from
elapsed time, because elapsed time over a cold read is not proportional
to anything.

**A terminal state is never left.** A job that failed stays failed. The
alternative — a poller that resets a finished job because a stale
progress read came back — is how a completed query appears to start
again.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.clickhouse import (
    LakeQueryError,
    LakeQueryNotConfiguredError,
    LakeQueryTimeoutError,
    execute_lake_query,
    execute_lake_query_with_id,
)
from app.models.lake_query_job import TERMINAL_STATUSES, LakeQueryJob
from app.services.lake_cold_query import PROGRESS_SQL, QueryProgress, validate_query_id

logger = logging.getLogger(__name__)

#: How long a job may run before the runner gives up on it. Far above the
#: synchronous bound — the whole point is that this path is allowed to
#: take longer — and still bounded, because an unbounded query holds a
#: ClickHouse thread and a cold-volume read budget indefinitely.
#:
#: Fifteen minutes is a policy choice, not a measurement, and is stated as
#: one: nothing here claims a cold scan takes fifteen minutes. It is the
#: ceiling past which a human should be asked whether they still want the
#: answer.
JOB_TIMEOUT_SECONDS = 15 * 60.0

#: How often the poller asks ClickHouse where the query has got to. Two
#: seconds is frequent enough for a console progress bar and rare enough
#: that the poll is not itself a load.
PROGRESS_POLL_SECONDS = 2.0


def new_query_id(job_id: uuid.UUID) -> str:
    """A ClickHouse query id derived from the job id.

    Derived rather than random so the two can always be matched up in a
    ClickHouse query log by someone who only has one of them.
    """
    return validate_query_id(f"aisoc-lake-{job_id}")


async def read_progress(query_id: str) -> QueryProgress | None:
    """Ask ClickHouse how far a running query has got.

    ``None`` means the server does not know about this query id, which is
    true both before it starts and after it finishes. The caller
    distinguishes those by the job's own status rather than by this
    answer, because "not running" is not "not started".
    """
    try:
        result = await execute_lake_query(
            PROGRESS_SQL,
            timeout_seconds=5.0,
            params={"query_id": query_id},
        )
    except (LakeQueryError, LakeQueryNotConfiguredError) as exc:
        # Not fatal to the job: the scan is still running whether or not
        # the progress read succeeded. Logged rather than swallowed, so a
        # permanently unreadable system.processes is visible instead of
        # looking like a query that never progresses.
        logger.warning("lake.job.progress_unreadable query_id=%s error=%s", query_id, exc)
        return None
    if not result.rows:
        return None
    row = result.rows[0]
    return QueryProgress(
        rows_read=int(row[0] or 0),
        bytes_read=int(row[1] or 0),
        total_rows_approx=int(row[2] or 0),
        elapsed_seconds=float(row[3] or 0.0),
    )


def claim_statement(job_id: uuid.UUID):
    """The one statement that claims a job.

    Factored out so a test can run *this* statement on two interleaved
    connections rather than a hand-written copy of it. A concurrency
    proof against a re-typed statement proves something about the test.

    The ``status == 'queued'`` predicate is the whole mechanism. Postgres
    takes a row lock on the UPDATE, so a second connection running the
    same statement blocks until the first commits and then re-evaluates
    the predicate against the committed row — finding `running`, matching
    nothing, and learning that it lost. A SELECT followed by an
    unconditional UPDATE has no such re-evaluation: the second
    connection's SELECT cannot see the first's uncommitted change, reads
    `queued`, and both replicas start the scan.
    """
    now = datetime.now(UTC)
    return (
        update(LakeQueryJob)
        .where(LakeQueryJob.id == job_id, LakeQueryJob.status == "queued")
        .values(status="running", started_at=now, updated_at=now)
        .returning(LakeQueryJob.id)
    )


async def claim_job(session: AsyncSession, job_id: uuid.UUID) -> bool:
    """Move one job from ``queued`` to ``running``, atomically."""
    result = await session.execute(claim_statement(job_id))
    claimed = result.scalar_one_or_none() is not None
    await session.commit()
    return claimed


async def _record_progress(
    session_factory: async_sessionmaker[AsyncSession],
    job_id: uuid.UUID,
    progress: QueryProgress,
) -> None:
    async with session_factory() as session:
        await session.execute(
            update(LakeQueryJob)
            .where(LakeQueryJob.id == job_id, LakeQueryJob.status == "running")
            .values(
                rows_read=progress.rows_read,
                bytes_read=progress.bytes_read,
                total_rows_approx=progress.total_rows_approx,
                progress_ratio=progress.ratio,
                updated_at=datetime.now(UTC),
            )
        )
        await session.commit()


async def _finish(
    session_factory: async_sessionmaker[AsyncSession],
    job_id: uuid.UUID,
    **values: Any,
) -> None:
    """Write a terminal state, and only onto a job that is still running.

    The ``status == 'running'`` predicate stops a late finish from
    overwriting a cancellation an operator has already made.
    """
    async with session_factory() as session:
        await session.execute(
            update(LakeQueryJob)
            .where(LakeQueryJob.id == job_id, LakeQueryJob.status == "running")
            .values(finished_at=datetime.now(UTC), updated_at=datetime.now(UTC), **values)
        )
        await session.commit()


async def run_job(
    session_factory: async_sessionmaker[AsyncSession],
    job_id: uuid.UUID,
    *,
    timeout_seconds: float = JOB_TIMEOUT_SECONDS,
    poll_seconds: float = PROGRESS_POLL_SECONDS,
) -> None:
    """Execute one claimed job, recording progress until it ends.

    Exceptions are turned into a ``failed`` status rather than being
    allowed to escape: this runs as a background task, and an exception
    escaping a background task leaves a job stuck at ``running`` forever
    with nothing in any log explaining why.
    """
    async with session_factory() as session:
        job = await session.get(LakeQueryJob, job_id)
        if job is None:
            logger.warning("lake.job.vanished job_id=%s", job_id)
            return
        if job.status != "running":
            logger.info("lake.job.not_running job_id=%s status=%s", job_id, job.status)
            return
        sql = job.rewritten_sql
        query_id = job.query_id

    poller = asyncio.create_task(_poll(session_factory, job_id, query_id, poll_seconds))
    try:
        result = await execute_lake_query_with_id(
            sql,
            query_id=query_id,
            timeout_seconds=timeout_seconds,
        )
    except LakeQueryTimeoutError as exc:
        await _finish(
            session_factory,
            job_id,
            status="failed",
            error=(
                f"the scan exceeded the job ceiling of {timeout_seconds:.0f}s: {exc}. "
                "Narrow the time range or the columns selected, or raise the ceiling for this deployment."
            ),
        )
        return
    except (LakeQueryError, LakeQueryNotConfiguredError) as exc:
        await _finish(session_factory, job_id, status="failed", error=str(exc))
        return
    except Exception as exc:  # noqa: BLE001 — see the docstring
        logger.exception("lake.job.unexpected job_id=%s", job_id)
        await _finish(session_factory, job_id, status="failed", error=f"unexpected error: {exc}")
        return
    finally:
        poller.cancel()
        # Bound rather than discarded, the shape the fusion ticker test pins:
        # `return_exceptions=True` hands back how the poller ended instead of
        # raising it, and the cancellation is settled either way.
        _ = await asyncio.gather(poller, return_exceptions=True)

    await _finish(
        session_factory,
        job_id,
        status="succeeded",
        result_columns=result.columns,
        result_rows=_jsonable(result.rows),
        row_count=result.row_count,
        rows_read=result.row_count,
        progress_ratio=1.0,
    )
    logger.info("lake.job.succeeded job_id=%s rows=%d elapsed_ms=%d", job_id, result.row_count, result.elapsed_ms)


async def _poll(
    session_factory: async_sessionmaker[AsyncSession],
    job_id: uuid.UUID,
    query_id: str,
    poll_seconds: float,
) -> None:
    while True:
        await asyncio.sleep(poll_seconds)
        progress = await read_progress(query_id)
        if progress is None:
            continue
        await _record_progress(session_factory, job_id, progress)


def _jsonable(rows: list[list[Any]]) -> list[list[Any]]:
    """Make driver values storable in JSONB.

    ClickHouse returns datetimes, UUIDs and Decimals as Python objects,
    and ``json.dumps`` refuses all three. Stringifying them here keeps
    the failure out of the commit, where it would mark a succeeded scan
    as failed after it had already paid for the read.
    """
    out: list[list[Any]] = []
    for row in rows:
        converted: list[Any] = []
        for value in row:
            if isinstance(value, (str, int, float, bool)) or value is None:
                converted.append(value)
            elif isinstance(value, (list, tuple)):
                converted.append([str(v) for v in value])
            else:
                converted.append(str(value))
        out.append(converted)
    return out


async def cancel_job(session: AsyncSession, job: LakeQueryJob) -> bool:
    """Mark a job cancelled and ask ClickHouse to stop the query.

    Returns False for a job that has already ended. Cancelling a finished
    job would rewrite the record of what happened.
    """
    if job.status in TERMINAL_STATUSES:
        return False
    job.status = "cancelled"
    job.finished_at = datetime.now(UTC)
    job.error = "cancelled by an operator"
    await session.commit()

    # Best effort, and after the status is durable: if the KILL fails the
    # job is still correctly recorded as cancelled, and the query will
    # end at the job ceiling anyway. The id is validated at construction,
    # so it cannot carry anything that needs escaping here.
    try:
        await execute_lake_query(
            "KILL QUERY WHERE query_id = %(query_id)s ASYNC",
            timeout_seconds=5.0,
            params={"query_id": job.query_id},
        )
    except (LakeQueryError, LakeQueryNotConfiguredError) as exc:
        logger.warning("lake.job.kill_failed job_id=%s error=%s", job.id, exc)
    return True


async def list_stuck_jobs(session: AsyncSession, older_than_seconds: float) -> list[LakeQueryJob]:
    """Jobs still `running` long past the ceiling.

    A job whose runner died mid-scan — an API replica restarted, say —
    stays `running` forever with no task behind it, which reads to an
    analyst as a query that is still working. Surfacing them is what lets
    readiness and the console say otherwise.
    """
    cutoff = datetime.now(UTC).timestamp() - older_than_seconds
    result = await session.execute(select(LakeQueryJob).where(LakeQueryJob.status == "running"))
    return [job for job in result.scalars().all() if job.started_at is not None and job.started_at.timestamp() < cutoff]
