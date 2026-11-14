"""Only one connector scheduler leads, against real Postgres (depth 4.5).

Without an election, two replicas each add one APScheduler job per
connector instance and every vendor is polled twice on every cycle — and
on a rate-limited API that is worse than duplication, because the second
replica's poll is what gets throttled and a throttled connector looks
identical to one whose credentials expired.

The election is one conditional UPDATE, and the only way to show it works
is to run two of them against one row. The interleaving is **forced**
rather than raced: two coroutines on one loop can serialise by luck, and
a concurrency test that cannot fail on the broken implementation is not a
concurrency test — measured on this repository's own lake-job claim,
where a five-way `asyncio.gather` passed under a SELECT-then-UPDATE.

Skips when ``ISOLATION_LEASE_DSN`` is unset; the workflow that owns this
suite sets it unconditionally.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_LEASE_DSN", "").strip(),
        reason="ISOLATION_LEASE_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_LEASE_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_LEASE_DSN is not set")
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


@pytest_asyncio.fixture(loop_scope="module")
async def scope(engine):
    """A fresh scope per test, removed afterwards."""
    from sqlalchemy import text

    name = f"test-scope-{uuid.uuid4().hex[:12]}"
    yield name
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM scheduler_leases WHERE scope = :s"), {"s": name})


def _lease(engine, scope: str, holder: str, seconds: float = 90.0):
    from app.leader_lease import LeaderLease

    return LeaderLease(engine, scope=scope, holder=holder, lease=seconds)


class TestOnlyOneLeader:
    async def test_two_replicas_racing_for_a_free_lease_produce_one_leader(self, engine, scope):
        a = _lease(engine, scope, "replica-a")
        b = _lease(engine, scope, "replica-b")
        results = await asyncio.gather(a.acquire(), b.acquire())
        assert sum(1 for won in results if won) == 1, f"acquisitions: {results}"

    async def test_two_interleaved_transactions_cannot_both_take_an_expired_lease(self, engine, scope):
        """The deterministic proof, not a race.

        The first challenger runs the acquire and **holds its
        transaction open**; the second runs the same statement and
        blocks on the row lock; the first commits; the second unblocks
        and re-evaluates `expires_at < now()` against the committed row,
        finds a fresh expiry, and matches nothing.
        """
        from sqlalchemy import text

        # Seed an expired lease so both challengers see one going spare.
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "INSERT INTO scheduler_leases (scope, holder, fenced_at, expires_at) "
                    "VALUES (:s, 'dead-replica', 7, now() - interval '1 minute')"
                ),
                {"s": scope},
            )

        from app.leader_lease import _ACQUIRE_SQL  # noqa: PLC0415

        first: list[bool] = []
        second: list[bool] = []
        first_has_run = asyncio.Event()

        async def challenger_a() -> None:
            async with engine.connect() as conn:
                await conn.begin()
                row = (await conn.execute(_ACQUIRE_SQL, {"scope": scope, "holder": "a", "lease": 90.0})).first()
                first.append(row is not None)
                first_has_run.set()
                await asyncio.sleep(0.5)
                await conn.commit()

        async def challenger_b() -> None:
            await first_has_run.wait()
            await asyncio.sleep(0.1)
            async with engine.connect() as conn:
                await conn.begin()
                row = (await conn.execute(_ACQUIRE_SQL, {"scope": scope, "holder": "b", "lease": 90.0})).first()
                second.append(row is not None)
                await conn.commit()

        await asyncio.gather(challenger_a(), challenger_b())

        assert first == [True], "the first challenger did not take the expired lease"
        assert second == [False], "both replicas took the lease; every vendor would be polled twice on every cycle"

    async def test_a_held_lease_cannot_be_stolen(self, engine, scope):
        a = _lease(engine, scope, "replica-a")
        assert await a.acquire() is True
        b = _lease(engine, scope, "replica-b")
        assert await b.acquire() is False, "a live lease was taken from its holder"

    async def test_an_expired_lease_is_taken_over(self, engine, scope):
        dying = _lease(engine, scope, "replica-a", seconds=1.0)
        assert await dying.acquire() is True
        await asyncio.sleep(1.2)
        taking = _lease(engine, scope, "replica-b")
        assert await taking.acquire() is True


class TestRenewal:
    async def test_the_holder_renews(self, engine, scope):
        a = _lease(engine, scope, "replica-a")
        await a.acquire()
        assert await a.renew() is True
        assert a.held is True

    async def test_a_non_holder_cannot_renew(self, engine, scope):
        a = _lease(engine, scope, "replica-a")
        await a.acquire()
        b = _lease(engine, scope, "replica-b")
        assert await b.renew() is False

    async def test_a_process_paused_past_its_expiry_cannot_resume_and_renew(self, engine, scope):
        """The window that matters. A replica stopped for longer than its
        lease must not come back and renew one somebody else now holds."""
        a = _lease(engine, scope, "replica-a", seconds=1.0)
        await a.acquire()
        await asyncio.sleep(1.2)
        assert await a.renew() is False, "a lapsed holder renewed its own expired lease"

    async def test_renewal_does_not_advance_the_term(self, engine, scope):
        # The term counts leadership changes. A heartbeat that incremented
        # it would make the number useless for the one question it answers.
        a = _lease(engine, scope, "replica-a")
        await a.acquire()
        before = a.term
        await a.renew()
        assert (await a.state()).term == before

    async def test_acquisition_after_a_takeover_advances_the_term(self, engine, scope):
        a = _lease(engine, scope, "replica-a", seconds=1.0)
        await a.acquire()
        first_term = a.term
        await asyncio.sleep(1.2)
        b = _lease(engine, scope, "replica-b")
        await b.acquire()
        assert b.term == first_term + 1


class TestRelease:
    async def test_releasing_lets_the_next_replica_in_without_waiting(self, engine, scope):
        # A rolling restart that waited out the whole lease would leave
        # nobody polling for its full duration.
        a = _lease(engine, scope, "replica-a")
        await a.acquire()
        await a.release()
        b = _lease(engine, scope, "replica-b")
        assert await b.acquire() is True

    async def test_release_never_raises(self, engine, scope):
        # A shutdown path that can fail is a pod stuck terminating.
        a = _lease(engine, scope, "replica-a")
        await a.release()
        assert a.held is False


class TestState:
    async def test_state_names_the_holder_so_an_all_follower_deployment_is_visible(self, engine, scope):
        a = _lease(engine, scope, "replica-a")
        await a.acquire()
        b = _lease(engine, scope, "replica-b")
        state = await b.state()
        assert state.held is False
        assert state.holder == "replica-a"
        assert state.expires_at is not None

    async def test_an_unclaimed_scope_reports_no_holder(self, engine, scope):
        state = await _lease(engine, scope, "replica-a").state()
        assert state.held is False
        assert state.holder == ""
