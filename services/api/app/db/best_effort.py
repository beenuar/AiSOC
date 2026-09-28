"""Run optional database work without taking the caller's transaction with it.

The defect this exists for
--------------------------
``POST /alerts/{id}/explain`` emitted this on every call against a default
install::

    WARNING explain.cost_track_failed … NotNullViolationError: null value in
            column "total_cost_usd" of relation "aisoc_run_costs"
    WARNING audit: failed to compute hash chain for tenant=… action=alerts.explain

Two log lines, and only the first names a cause. The second is a consequence:
PostgreSQL aborts the whole transaction on any statement error, and every
later statement on that connection then raises ``InFailedSqlTransaction``
until a rollback. The cost insert was wrapped in ``try/except`` so it "could
not break the response" — but catching the Python exception does not undo the
abort, so the *next* piece of work on the same session failed too. That next
piece of work was the audit log.

The audit row was then not merely unchained. Its own ``INSERT`` was issued on
the same aborted transaction and failed as well, so the ``alerts.explain``
event was **never written**. An append-only hash-chained audit log that
silently drops events is a compliance claim that is false, and nothing above
the warning line said so.

The rule
--------
Optional database work runs inside a SAVEPOINT. A failure rolls back to the
savepoint, the outer transaction survives, and the caller's later work — the
audit row above all — still commits. Catching the exception without the
savepoint is the shape that looks correct and is not.

This is deliberately not "retry" or "ignore". It is scoped rollback: the
caller still gets the exception, still decides whether to degrade, and still
logs. What changes is that the decision is theirs rather than PostgreSQL's.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import TypeVar

from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar("T")


@asynccontextmanager
async def savepoint(db: AsyncSession) -> AsyncIterator[None]:
    """Scope a block's database errors to a SAVEPOINT.

    The exception still propagates — the caller decides what a failure means.
    What the savepoint guarantees is that the outer transaction is usable
    afterwards either way.

    ``AsyncSession.begin_nested`` emits ``SAVEPOINT`` and, on exit, either
    ``RELEASE SAVEPOINT`` or ``ROLLBACK TO SAVEPOINT``. On a session with no
    transaction open yet SQLAlchemy begins one first, so this is safe to use
    before the caller has issued any statement.
    """
    nested = await db.begin_nested()
    try:
        yield
    except BaseException:
        if nested.is_active:
            await nested.rollback()
        raise
    else:
        if nested.is_active:
            await nested.commit()


async def attempt(db: AsyncSession, operation: Callable[[], Awaitable[T]]) -> tuple[T | None, Exception | None]:
    """Run ``operation`` in a savepoint; return ``(result, error)``.

    For the common shape where a caller wants to degrade rather than raise.
    Returning the exception instead of swallowing it keeps the caller's log
    line specific — ``explain.cost_track_failed … NotNullViolationError`` is
    what identified the defect above, and a bare "cost tracking failed" would
    not have.
    """
    try:
        async with savepoint(db):
            return await operation(), None
    except Exception as exc:  # noqa: BLE001 - the caller decides what it means
        return None, exc
