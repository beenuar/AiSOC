"""The platform-wide kill switch can actually be engaged.

What was wrong
--------------
``078_closure_policy_and_kill_switch.sql`` gives ``aisoc_kill_switch`` the
policy::

    USING      (tenant_id IS NULL OR tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
    WITH CHECK (tenant_id = current_tenant_id())

The global row is the one with ``tenant_id IS NULL``. Judged by that
``WITH CHECK`` it is unwritable by **every** session the runtime role can
open, and the two cases fail for different reasons that both land on the
same refusal:

* no tenant bound — ``NULL = NULL`` is ``NULL``, and a ``WITH CHECK`` that
  does not evaluate to true refuses the row;
* a tenant bound — ``NULL = '<uuid>'`` is ``NULL``, same refusal.

So the ``USING`` clause lets every tenant *read* a global stop that no
session could ever have written. The table's own comment says the global row
"is written by the platform operator through a session with no tenant set",
which is the one case the check rejects.

The half that was not reported
------------------------------
The policy is only half of it. Before the fix, **no code in the tree wrote
the global row at all** — every write in ``kill_switch.py`` binds
``t=user.tenant_id``, so the only reachable scope was the caller's own
tenant. There was no endpoint, console control, CLI or script that could set
``tenant_id IS NULL``, while two readers (the endpoint's ``GET`` and
``services/agents`` ``kill_switch_engaged``) consult it on every alert. A
reader over a table nothing writes is the shape ``AGENTS.md`` calls out, and
here it was wearing the label of an emergency stop.

Why this suite connects as ``aisoc_app``
----------------------------------------
Because the defect is invisible from any other role. ``061_runtime_app_role``
makes ``aisoc_app`` ``NOSUPERUSER NOBYPASSRLS``, and both tables are ``FORCE
ROW LEVEL SECURITY``; a superuser ignores policies entirely, so seeding the
global row as the migration role succeeds and proves nothing. That is
precisely the workaround that hid this, so :func:`_refuse_a_vacuous_run`
fails the suite rather than skipping when the DSN resolves to a role that can
walk past a policy.

Against the pre-fix tree every assertion in
:class:`TestTheGlobalSwitchIsEngageable` fails with
``new row violates row-level security policy for table "aisoc_kill_switch"``.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_KILL_SWITCH_DSN", "").strip(),
        reason="ISOLATION_KILL_SWITCH_DSN is not set; this suite needs a live Postgres",
    ),
]

#: The sentinel an unbound session carries. ``current_tenant_id()`` maps both
#: an unset and an empty setting to NULL, so clearing is how a connection
#: becomes the platform operator rather than a tenant.
_UNBOUND = ""


def _dsn() -> str:
    value = os.environ.get("ISOLATION_KILL_SWITCH_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_KILL_SWITCH_DSN is not set")
    return value.replace("postgresql+asyncpg://", "postgresql://")


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pool():
    asyncpg = pytest.importorskip("asyncpg")
    created = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4)
    yield created
    await created.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module", autouse=True)
async def _refuse_a_vacuous_run(pool) -> None:
    """A role that bypasses RLS would pass every assertion below.

    This suite's whole subject is what a policy does to the runtime role. Run
    as the owner or a superuser it is not a weaker test, it is a test of
    nothing, and it would have reported the pre-fix tree healthy.
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT current_user AS who, rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        )
        forced = await conn.fetchval(
            "SELECT bool_and(relforcerowsecurity) FROM pg_class WHERE relname IN ('aisoc_kill_switch', 'aisoc_kill_switch_audit')"
        )

    assert not row["rolsuper"], (
        f"connected as {row['who']}, which is a SUPERUSER and ignores every row-level security "
        "policy. Point ISOLATION_KILL_SWITCH_DSN at the aisoc_app runtime role."
    )
    assert not row["rolbypassrls"], f"connected as {row['who']}, which holds BYPASSRLS, so no policy below is in force"
    assert forced is True, (
        "aisoc_kill_switch / aisoc_kill_switch_audit are not FORCE ROW LEVEL SECURITY, so the table owner "
        "walks past the policy and this suite cannot see what a tenant session sees"
    )


async def _tenant(pool) -> str:
    """A tenant row, created on an unbound connection.

    ``tenants`` is not the table under test and creating one needs no tenant
    context, so this deliberately does not go through the bound path.
    """
    tenant_id = str(uuid.uuid4())
    async with pool.acquire() as conn:
        await _bind(conn, _UNBOUND)
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, $2, $3)",
            tenant_id,
            "kill-switch",
            f"ks-{tenant_id[:8]}",
        )
    return tenant_id


async def _bind(conn, tenant_id: str) -> None:
    """Bind, or clear with ``_UNBOUND``. Session scope, not ``SET LOCAL``:
    these connections run statements outside an explicit transaction."""
    await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_id)


async def _engage(conn, tenant_id: str | None, *, reason: str, actor: str = "operator") -> None:
    """Engage, upserting on whichever of the two unique indexes applies.

    The global index is ``ON aisoc_kill_switch ((TRUE)) WHERE tenant_id IS
    NULL``, so its conflict target is the expression rather than the column.
    """
    if tenant_id is None:
        await conn.execute(
            """
            INSERT INTO aisoc_kill_switch (tenant_id, engaged, reason, engaged_by)
            VALUES (NULL, TRUE, $1, $2)
            ON CONFLICT ((TRUE)) WHERE tenant_id IS NULL
            DO UPDATE SET engaged = TRUE, reason = EXCLUDED.reason, engaged_by = EXCLUDED.engaged_by,
                          released_by = NULL, released_at = NULL
            """,
            reason,
            actor,
        )
        return
    await conn.execute(
        """
        INSERT INTO aisoc_kill_switch (tenant_id, engaged, reason, engaged_by)
        VALUES ($1::uuid, TRUE, $2, $3)
        ON CONFLICT (tenant_id) WHERE tenant_id IS NOT NULL
        DO UPDATE SET engaged = TRUE, reason = EXCLUDED.reason, engaged_by = EXCLUDED.engaged_by,
                      released_by = NULL, released_at = NULL
        """,
        tenant_id,
        reason,
        actor,
    )


async def _audit(conn, tenant_id: str | None, *, scope: str, action: str = "engage") -> None:
    await conn.execute(
        """
        INSERT INTO aisoc_kill_switch_audit (tenant_id, action, reason, actor, scope)
        VALUES ($1::uuid, $2, 'because the agent was doing something unexpected', 'operator', $3)
        """,
        tenant_id,
        action,
        scope,
    )


@pytest_asyncio.fixture(loop_scope="module", autouse=True)
async def _clean(pool):
    """The global row is a singleton, so one test's switch is the next
    test's starting state unless it is cleared."""
    yield
    async with pool.acquire() as conn:
        await _bind(conn, _UNBOUND)
        await conn.execute("DELETE FROM aisoc_kill_switch WHERE tenant_id IS NULL")


class TestTheGlobalSwitchIsEngageable:
    """The reported defect. Every assertion here fails on the pre-fix tree."""

    async def test_an_unbound_session_can_engage_the_global_switch(self, pool) -> None:
        async with pool.acquire() as conn:
            await _bind(conn, _UNBOUND)

            await _engage(conn, None, reason="platform-wide stop at 3am")

            state = await conn.fetchrow("SELECT engaged, reason FROM aisoc_kill_switch WHERE tenant_id IS NULL")

        assert state is not None, "the global kill switch row does not exist after engaging it"
        assert state["engaged"] is True
        assert state["reason"] == "platform-wide stop at 3am"

    async def test_the_global_switch_can_be_released_again(self, pool) -> None:
        """A stop that cannot be released is its own outage."""
        async with pool.acquire() as conn:
            await _bind(conn, _UNBOUND)
            await _engage(conn, None, reason="platform-wide stop at 3am")

            released = await conn.fetchval(
                """
                UPDATE aisoc_kill_switch
                   SET engaged = FALSE, released_by = 'operator', released_at = NOW()
                 WHERE tenant_id IS NULL AND engaged = TRUE
             RETURNING id
                """
            )

        assert released is not None, "the global kill switch could not be released by the runtime role"

    async def test_the_global_audit_row_can_be_written(self, pool) -> None:
        """``aisoc_kill_switch_audit`` carries the same strict check, so a
        switch that could be thrown would still have 500'd on its audit row —
        and an unaudited emergency stop is one nobody can account for."""
        async with pool.acquire() as conn:
            await _bind(conn, _UNBOUND)

            await _audit(conn, None, scope="global")

            written = await conn.fetchval("SELECT count(*) FROM aisoc_kill_switch_audit WHERE tenant_id IS NULL AND scope = 'global'")

        assert written >= 1, "the global kill switch cannot write its audit row"


class TestTheTenantSwitchStillWorks:
    """The working half. A fix for the global row that regressed this would
    have traded one unreachable stop for another."""

    async def test_a_tenant_bound_session_engages_its_own_row(self, pool) -> None:
        tenant_id = await _tenant(pool)
        async with pool.acquire() as conn:
            await _bind(conn, tenant_id)

            await _engage(conn, tenant_id, reason="this tenant only", actor="analyst")

            state = await conn.fetchrow("SELECT engaged FROM aisoc_kill_switch WHERE tenant_id = $1::uuid", tenant_id)

        assert state is not None and state["engaged"] is True

    async def test_a_tenant_bound_session_writes_its_own_audit_row(self, pool) -> None:
        tenant_id = await _tenant(pool)
        async with pool.acquire() as conn:
            await _bind(conn, tenant_id)

            await _audit(conn, tenant_id, scope="tenant")

            written = await conn.fetchval("SELECT count(*) FROM aisoc_kill_switch_audit WHERE tenant_id = $1::uuid", tenant_id)

        assert written == 1


class TestEngagingGloballyWidensNothing:
    """The negative property. Making the global row writable must not make
    any session able to write a row that is not its own."""

    async def test_a_tenant_cannot_write_the_global_row(self, pool) -> None:
        """Otherwise any tenant administrator could freeze every other
        tenant on the deployment."""
        asyncpg = pytest.importorskip("asyncpg")
        tenant_id = await _tenant(pool)

        async with pool.acquire() as conn:
            await _bind(conn, tenant_id)

            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await _engage(conn, None, reason="freezing the whole platform from one tenant")

    async def test_a_tenant_cannot_write_another_tenants_row(self, pool) -> None:
        asyncpg = pytest.importorskip("asyncpg")
        mine = await _tenant(pool)
        theirs = await _tenant(pool)

        async with pool.acquire() as conn:
            await _bind(conn, mine)

            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await _engage(conn, theirs, reason="stopping somebody else's tenant")

    async def test_a_tenant_cannot_write_another_tenants_audit_row(self, pool) -> None:
        """A forged audit row is how a real action gets attributed to the
        wrong operator."""
        asyncpg = pytest.importorskip("asyncpg")
        mine = await _tenant(pool)
        theirs = await _tenant(pool)

        async with pool.acquire() as conn:
            await _bind(conn, mine)

            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await _audit(conn, theirs, scope="tenant")

    async def test_an_unbound_session_cannot_write_a_tenants_row(self, pool) -> None:
        """The platform operator's session owns the global row and nothing
        else. Without this the fix would be 'drop the check', which would let
        any unbound worker write into any tenant."""
        asyncpg = pytest.importorskip("asyncpg")
        tenant_id = await _tenant(pool)

        async with pool.acquire() as conn:
            await _bind(conn, _UNBOUND)

            with pytest.raises(asyncpg.exceptions.InsufficientPrivilegeError):
                await _engage(conn, tenant_id, reason="writing into a tenant from an unbound session")


class TestBothScopesAreVisibleToTheTenant:
    """A platform-wide stop a tenant cannot see reads to them as an
    unexplained outage, which is why ``USING`` admits the global row."""

    async def test_a_tenant_reads_the_global_switch(self, pool) -> None:
        tenant_id = await _tenant(pool)

        async with pool.acquire() as conn:
            await _bind(conn, _UNBOUND)
            await _engage(conn, None, reason="platform maintenance")

        async with pool.acquire() as conn:
            await _bind(conn, tenant_id)
            seen = await conn.fetch(
                "SELECT tenant_id, reason FROM aisoc_kill_switch WHERE engaged = TRUE AND (tenant_id IS NULL OR tenant_id = $1::uuid)",
                tenant_id,
            )

        assert [r["reason"] for r in seen] == ["platform maintenance"]

    async def test_a_tenant_does_not_read_another_tenants_switch(self, pool) -> None:
        mine = await _tenant(pool)
        theirs = await _tenant(pool)

        async with pool.acquire() as conn:
            await _bind(conn, theirs)
            await _engage(conn, theirs, reason="their own stop", actor="their-analyst")

        async with pool.acquire() as conn:
            await _bind(conn, mine)
            seen = await conn.fetch("SELECT tenant_id FROM aisoc_kill_switch WHERE engaged = TRUE")

        assert [r["tenant_id"] for r in seen] == [], "one tenant can see another tenant's kill switch"
