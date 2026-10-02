"""The durable approval pause, against the Postgres it claims to use.

Maturity: the evidence that takes **Alert-triggered playbooks, with a
durable approval pause** to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

Why the offline suite is not enough
------------------------------------
`services/agents/tests/test_playbook_pause_resume.py` is 15 tests against
`_FakeRows` and `_FakePool`. It is a useful test of the module's logic and
it cannot prove the thing the feature is named for, because every property
that matters is a property of the **database**:

* "survives a restart" is a claim about rows on disk, and a fake that
  lives in the test process cannot have any;
* "a double-tap resolves once" is enforced by a *partial unique index* on
  `status = 'waiting'` in migration `081`. The fake re-implements that
  index in Python. A hand-written re-implementation of a constraint is
  the double-more-capable-than-the-real-thing shape that caused four of
  six defects in one live-QA pass;
* "expires with a recorded outcome" depends on `NOW()` and on the partial
  expiry index actually existing.

The README said "live Postgres suspend/resume" before this file existed.
That was wrong, and correcting it was the first commit of this work. This
is the file that makes the stronger claim true.

The negative control
--------------------
The workflow drops the partial unique index and requires the double-tap
test to fail. Without that, "the second resolve returned False" could be
true because the module got lucky rather than because the database
refused.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio

# Skip as a *module*, not only in the fixture.
#
# The offline isolation job collects this directory with no stores
# running. With the skip only in the fixture, any test that does not take
# it ran anyway and failed there — which is a failure about the harness,
# reported against a capability.
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_PLAYBOOK_DSN", "").strip(),
        reason="ISOLATION_PLAYBOOK_DSN is not set; this suite needs live infrastructure",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_PLAYBOOK_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_PLAYBOOK_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture
async def pool():
    """A real asyncpg pool, injected the way production resolves one.

    `app.playbook.pause` reaches its pool through `_pool()`, so patching
    that is how a deployment's wiring is reproduced without importing the
    whole agents service.
    """
    asyncpg = pytest.importorskip("asyncpg")
    from app.playbook import pause as playbook_pause

    created = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4)

    async def _resolve():  # noqa: ANN202
        return created

    original = playbook_pause._pool
    playbook_pause._pool = _resolve
    try:
        yield created
    finally:
        playbook_pause._pool = original
        async with created.acquire() as conn:
            await conn.execute("DELETE FROM aisoc_playbook_pauses WHERE playbook_id LIKE 'pb-live-%'")
        await created.close()


@pytest_asyncio.fixture
async def tenant(pool):  # noqa: ANN001
    """A real tenant row, because the table has a FK to `tenants`.

    Worth stating: the fake had no foreign key, so a pause referencing a
    tenant that does not exist was perfectly acceptable to it.
    """
    tenant_id = uuid.uuid4()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
            tenant_id,
            f"live-{tenant_id.hex[:8]}",
            f"live-{tenant_id.hex[:8]}",
        )
    yield str(tenant_id)
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM tenants WHERE id = $1", tenant_id)


async def _suspend(tenant: str, *, run: str, step_index: int = 2, approval: str | None = None):
    from app.playbook import pause as playbook_pause

    return await playbook_pause.suspend(
        tenant_id=tenant,
        run_id=run,
        playbook_id=f"pb-live-{run}",
        playbook_name="Containment with sign-off",
        step_index=step_index,
        step_id="gate",
        run_context={"host": "WIN-FIN-02", "user": "j.doe"},
        step_results=[{"step_id": "enrich", "status": "success"}],
        approval_id=approval,
    )


class TestItReachesTheRealTable:
    async def test_a_pause_is_a_row(self, pool, tenant) -> None:  # noqa: ANN001
        """The claim the offline suite cannot make: this is on disk."""
        run = f"run-{uuid.uuid4().hex[:8]}"
        result = await _suspend(tenant, run=run)
        assert result is not None, "suspend returned None against a live database"

        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT run_id, step_index, status, run_context, expires_at FROM aisoc_playbook_pauses WHERE run_id = $1",
                run,
            )
        assert row is not None, "no row was written"
        assert row["status"] == "waiting"
        assert row["step_index"] == 2
        assert row["expires_at"] > datetime.now(UTC), "a pause was written already expired"

    async def test_the_context_survives_the_round_trip(self, pool, tenant) -> None:  # noqa: ANN001
        """A resumed run reads `{{prev.*}}` out of this. If jsonb loses
        it, every templated parameter in the second half of the playbook
        resolves to nothing."""
        from app.playbook import pause as playbook_pause

        run = f"run-{uuid.uuid4().hex[:8]}"
        approval = str(uuid.uuid4())
        await _suspend(tenant, run=run, approval=approval)

        found = await playbook_pause.find_waiting(approval_id=approval, tenant_id=tenant)
        assert found is not None, "a pause written to Postgres could not be found again"
        assert found.run_context["host"] == "WIN-FIN-02"
        assert found.step_results[0]["step_id"] == "enrich"


class TestSurvivingARestart:
    async def test_a_cold_process_finds_the_pause(self, pool, tenant) -> None:  # noqa: ANN001
        """Nothing is carried between the write and the read but the
        database, which is what a restart leaves you with.

        The module's caches are cleared in between so the lookup cannot
        be served from anything in this process.
        """
        import importlib

        from app.playbook import pause as playbook_pause

        run = f"run-{uuid.uuid4().hex[:8]}"
        approval = str(uuid.uuid4())
        await _suspend(tenant, run=run, approval=approval)

        # Re-import the module: a fresh process would have no module
        # state at all, and this is the closest a single test can get.
        reloaded = importlib.reload(playbook_pause)

        async def _resolve():  # noqa: ANN202
            return pool

        # `reload` returns `ModuleType`, so the checker cannot see the
        # module-level `_pool` it declares. Patching it is the point of
        # the test — a fresh process is what a restart leaves behind.
        reloaded._pool = _resolve  # type: ignore[attr-defined]
        found = await reloaded.find_waiting(approval_id=approval, tenant_id=tenant)

        assert found is not None, "the pause did not survive a module reload"
        assert found.run_id == run
        assert found.resume_index == found.step_index + 1, (
            "resume must start past the approval step, or a replayed decision pauses forever on the same step"
        )


class TestTheDatabaseEnforcesSingleResolution:
    async def test_a_double_tap_resolves_once(self, pool, tenant) -> None:  # noqa: ANN001
        """A double-tap in the responder app, or a retried webhook.

        This is the test the workflow's negative control breaks: dropping
        the partial unique index must make it fail, which is what proves
        the constraint is doing the work rather than the Python.
        """
        from app.playbook import pause as playbook_pause

        run = f"run-{uuid.uuid4().hex[:8]}"
        result = await _suspend(tenant, run=run)
        assert result is not None

        first = await playbook_pause.resolve(pause_id=result.id, tenant_id=tenant, status="resumed", resolution="approved")
        second = await playbook_pause.resolve(pause_id=result.id, tenant_id=tenant, status="resumed", resolution="approved again")
        assert first is True
        assert second is False, "the same pause was claimed twice, so the run would resume twice"

    async def test_two_waiting_pauses_for_one_run_are_refused(self, pool, tenant) -> None:  # noqa: ANN001
        """The partial unique index, asserted directly.

        A run cannot be waiting at two approval steps, and a duplicate
        would resume it twice. The offline suite re-implements this rule
        in Python; here the database enforces it.
        """
        import asyncpg

        run = f"run-{uuid.uuid4().hex[:8]}"
        first = await _suspend(tenant, run=run)
        assert first is not None

        # Straight at the table, because `suspend` swallows the error and
        # returns None — which is correct behaviour and would hide
        # whether the constraint fired.
        with pytest.raises(asyncpg.UniqueViolationError):
            async with pool.acquire() as conn:
                await conn.execute(
                    "INSERT INTO aisoc_playbook_pauses "
                    "(id, tenant_id, run_id, playbook_id, step_index, step_id, expires_at) "
                    "VALUES ($1::uuid, $2::uuid, $3, $4, 5, 'gate2', NOW() + interval '1 hour')",
                    str(uuid.uuid4()),
                    tenant,
                    run,
                    f"pb-live-{run}",
                )


class TestCrossTenant:
    async def test_another_tenant_cannot_find_or_resolve_it(self, pool, tenant) -> None:  # noqa: ANN001
        """Resuming another tenant's run should take two mistakes.

        The approval id is an unguessable UUID, which is an argument for
        it being hard to reach the wrong row and not an argument for
        being allowed to.
        """
        from app.playbook import pause as playbook_pause

        run = f"run-{uuid.uuid4().hex[:8]}"
        approval = str(uuid.uuid4())
        result = await _suspend(tenant, run=run, approval=approval)
        assert result is not None

        stranger = str(uuid.uuid4())
        assert await playbook_pause.find_waiting(approval_id=approval, tenant_id=stranger) is None
        assert await playbook_pause.resolve(pause_id=result.id, tenant_id=stranger, status="resumed", resolution="not mine") is False
        # And the owner can still do both, so the refusal above is not
        # simply "nothing works".
        assert await playbook_pause.find_waiting(approval_id=approval, tenant_id=tenant) is not None


class TestExpiry:
    async def test_a_pause_past_its_deadline_expires_with_a_reason(self, pool, tenant) -> None:  # noqa: ANN001
        """`expired` is a decision. A pause with no deadline is a run that
        hangs forever and an operator who never learns it did."""
        from app.playbook import pause as playbook_pause

        run = f"run-{uuid.uuid4().hex[:8]}"
        result = await _suspend(tenant, run=run)
        assert result is not None

        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE aisoc_playbook_pauses SET expires_at = NOW() - interval '1 hour' WHERE id = $1::uuid",
                result.id,
            )

        expired = await playbook_pause.expire_due()
        assert run in expired

        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT status, resolution, resolved_at FROM aisoc_playbook_pauses WHERE id = $1::uuid",
                result.id,
            )
        assert row["status"] == "expired"
        assert row["resolved_at"] is not None
        assert "deadline" in (row["resolution"] or ""), (
            "an expired approval must say why, or it is indistinguishable from one still legitimately waiting"
        )

    async def test_a_pause_inside_its_deadline_is_left_alone(self, pool, tenant) -> None:  # noqa: ANN001
        """The negative half of expiry: a sweep that expired everything
        would pass the test above."""
        from app.playbook import pause as playbook_pause

        run = f"run-{uuid.uuid4().hex[:8]}"
        result = await _suspend(tenant, run=run)
        assert result is not None

        await playbook_pause.expire_due(now=datetime.now(UTC) - timedelta(days=1))

        async with pool.acquire() as conn:
            status = await conn.fetchval("SELECT status FROM aisoc_playbook_pauses WHERE id = $1::uuid", result.id)
        assert status == "waiting", "a pause inside its deadline was expired"
