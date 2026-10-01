"""Live-Postgres proof that the `mssp_*` policies isolate two MSSP portfolios.

Why this is a separate file from ``test_postgres_rls.py``
---------------------------------------------------------
That suite discovers tables by looking for a column literally named
``tenant_id``. Every ``mssp_*`` table names its tenants differently —
``parent_tenant_id`` and ``child_tenant_id``, or ``parent_id`` and
``child_id`` — so **all seven were invisible to it**, and its coverage
figure was a statement about the tables it could see. That blind spot is
the reason six of them carried no policy for as long as they did.

They also cannot be asserted the same way. A normal row belongs to one
tenant and the test is ``scoped read returns A's row, never B's``. An MSSP
row joins two tenants and *both* must read it: a policy naming only the
parent would hide from a customer the overrides applied to their own
detections, which is the transparency the adoption flow was rebuilt around.
So the assertion is "exactly one of the two seeded rows, from four different
directions, and zero from a fifth tenant that is party to neither".

The defect this would have caught
---------------------------------
Writing the pack and assignment policies as mutual subqueries is the
obvious way to express "a pack is visible to anyone it is assigned to" and
"an assignment is visible to the owning pack's parent". Both are true
statements; together they are unusable, and Postgres answers ``infinite
recursion detected in policy for relation "mssp_rule_packs"`` on the first
SELECT. ``check_rls_policy_shape.py`` passed throughout, because the shape
was right. Only running them found it.

Skips when no database answers, so a local ``pytest tests/isolation`` stays
green — but cannot skip where it is meant to run: ``integration.yml`` sets
``POSTGRES_RLS_ISOLATION_REQUIRED=1`` and an unreachable database is then a
failure, because a gate that quietly declines to run looks exactly like one
that ran and found nothing.
"""

from __future__ import annotations

import os
import uuid

import pytest

DSN = os.environ.get("DATABASE_URL", "")
ADMIN_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or DSN
REQUIRED = os.environ.get("POSTGRES_RLS_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

pytestmark = pytest.mark.skipif(
    "postgres" not in DSN and not REQUIRED,
    reason="no Postgres DSN; set DATABASE_URL, or POSTGRES_RLS_ISOLATION_REQUIRED=1 to demand one",
)

#: Two unrelated MSSPs, each managing one customer, plus an outsider who is
#: party to neither. Fixed UUIDs so a failure names the tenant.
MSSP_A = uuid.UUID("0c000000-0000-0000-0000-0000000aaaa1")
CHILD_A = uuid.UUID("0c000000-0000-0000-0000-0000000aaaa2")
MSSP_B = uuid.UUID("0c000000-0000-0000-0000-0000000bbbb1")
CHILD_B = uuid.UUID("0c000000-0000-0000-0000-0000000bbbb2")
OUTSIDER = uuid.UUID("0c000000-0000-0000-0000-0000000ccccc")

#: table → the four parties who must each see exactly their own row.
TABLES = (
    "mssp_delegations",
    "mssp_rule_overrides",
    "mssp_tenant_notes",
    "mssp_rule_packs",
    "mssp_rule_pack_assignments",
    "mssp_rule_pack_rules",
)


def _asyncpg_dsn(url: str) -> str:
    return url.replace("postgresql+asyncpg://", "postgresql://").replace("postgres+asyncpg://", "postgresql://")


async def _connect(dsn: str):
    asyncpg = pytest.importorskip("asyncpg")
    if not dsn:
        pytest.skip("neither DATABASE_MIGRATION_URL nor DATABASE_URL is set")
    try:
        return await asyncpg.connect(_asyncpg_dsn(dsn))
    except Exception as exc:  # noqa: BLE001
        if REQUIRED:
            pytest.fail(f"POSTGRES_RLS_ISOLATION_REQUIRED is set but no Postgres answered: {exc}")
        pytest.skip(f"no Postgres: {exc}")


async def _count_as(conn, tenant: uuid.UUID, table: str) -> int:
    async with conn.transaction():
        await conn.execute("SELECT set_config('app.current_tenant_id', $1, true)", str(tenant))
        return await conn.fetchval(f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed list


@pytest.fixture(scope="module")
def seeded():
    """Two portfolios, torn down afterwards. Skips if the schema is absent.

    A *synchronous* fixture driving `asyncio.run`, matching the convention
    in `test_postgres_rls.py`, which has no async fixtures at all. An
    `async def` under a plain `@pytest.fixture` yields the generator object
    rather than the value — nothing is seeded, and every assertion then
    reads an empty table. That happened here, and the only reason it did
    not pass silently is the unscoped-read guard below, which exists for
    exactly this.
    """
    import asyncio

    state: dict = {}
    # Torn down *before* seeding as well as after. A run whose seed raised
    # part-way leaves rows behind, and the next run then dies on a unique
    # constraint rather than on the thing it was testing — which is how a
    # one-off failure becomes a permanently red job.
    asyncio.run(_teardown())
    asyncio.run(_seed(state))
    try:
        yield state
    finally:
        asyncio.run(_teardown())


async def _teardown() -> None:
    admin = await _connect(ADMIN_DSN)
    try:
        for tenant in (MSSP_A, CHILD_A, MSSP_B, CHILD_B, OUTSIDER):
            await admin.execute("DELETE FROM tenants WHERE id = $1", tenant)
    finally:
        await admin.close()


async def _seed(state: dict) -> None:
    admin = await _connect(ADMIN_DSN)
    exists = await admin.fetchval("SELECT to_regclass('public.mssp_rule_packs')")
    if exists is None:
        await admin.close()
        pytest.skip("the mssp_* schema is not present in this database")

    rule_id = uuid.uuid4()
    pack_a, pack_b = uuid.uuid4(), uuid.uuid4()
    try:
        for tenant, slug in (
            (MSSP_A, "rls-mssp-a"),
            (CHILD_A, "rls-child-a"),
            (MSSP_B, "rls-mssp-b"),
            (CHILD_B, "rls-child-b"),
            (OUTSIDER, "rls-outsider"),
        ):
            await admin.execute(
                "INSERT INTO tenants (id, slug, name) VALUES ($1, $2, $2) ON CONFLICT (id) DO NOTHING",
                tenant,
                slug,
            )
        await admin.execute(
            "INSERT INTO detection_rules (id, tenant_id, name) VALUES ($1, $2, 'rls-probe') ON CONFLICT (id) DO NOTHING",
            rule_id,
            MSSP_A,
        )
        for parent, child, pack in ((MSSP_A, CHILD_A, pack_a), (MSSP_B, CHILD_B, pack_b)):
            await admin.execute(
                "INSERT INTO mssp_delegations (parent_tenant_id, child_tenant_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
                parent,
                child,
            )
            await admin.execute(
                # `action` is NOT NULL with a CHECK of ('exclude','customize')
                # and no default. A hand-written probe schema that omitted it
                # passed locally and failed in CI against the real migration
                # chain — which is the argument for running this against the
                # chain rather than an approximation of it.
                "INSERT INTO mssp_rule_overrides "
                "(parent_tenant_id, child_tenant_id, rule_id, action) "
                "VALUES ($1,$2,$3,'exclude') ON CONFLICT DO NOTHING",
                parent,
                child,
                rule_id,
            )
            await admin.execute(
                "INSERT INTO mssp_tenant_notes (parent_id, child_id, body) VALUES ($1,$2,'probe')",
                parent,
                child,
            )
            await admin.execute(
                "INSERT INTO mssp_rule_packs (id, parent_tenant_id, name) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
                pack,
                parent,
                f"rls-pack-{parent}",
            )
            await admin.execute(
                "INSERT INTO mssp_rule_pack_assignments (pack_id, parent_tenant_id, child_tenant_id) VALUES ($1,$2,$3)",
                pack,
                parent,
                child,
            )
            await admin.execute("INSERT INTO mssp_rule_pack_rules (pack_id, rule_id) VALUES ($1,$2)", pack, rule_id)
        state.update({"rule_id": rule_id, "pack_a": pack_a, "pack_b": pack_b})
    finally:
        await admin.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("table", TABLES)
async def test_an_unscoped_read_sees_both_portfolios(seeded, table: str) -> None:
    """The step that stops every assertion below passing for the wrong reason.

    A scoped read returning one row on a table holding one row proves
    nothing. This establishes that two exist before anything is filtered.
    """
    admin = await _connect(ADMIN_DSN)
    try:
        total = await admin.fetchval(f"SELECT count(*) FROM {table}")  # noqa: S608 - fixed list
    finally:
        await admin.close()
    assert total >= 2, f"{table} holds {total} rows; the isolation assertions would be vacuous"


@pytest.mark.asyncio
@pytest.mark.parametrize("table", TABLES)
@pytest.mark.parametrize("tenant", [MSSP_A, CHILD_A, MSSP_B, CHILD_B], ids=["mssp-a", "child-a", "mssp-b", "child-b"])
async def test_each_party_sees_exactly_its_own_row(seeded, table: str, tenant: uuid.UUID) -> None:
    """Both sides of the relationship read, and neither reads the other's.

    Four directions rather than two: a policy that names the parent and
    forgets the child passes a parent-only test while a customer's page
    renders empty, and the one table where that is missed is invisible
    until somebody asks why.
    """
    conn = await _connect(DSN)
    try:
        seen = await _count_as(conn, tenant, table)
    finally:
        await conn.close()
    assert seen == 1, f"{table} showed {seen} rows to {tenant}; exactly its own one was expected"


@pytest.mark.asyncio
@pytest.mark.parametrize("table", TABLES)
async def test_an_unrelated_tenant_sees_nothing(seeded, table: str) -> None:
    conn = await _connect(DSN)
    try:
        seen = await _count_as(conn, OUTSIDER, table)
    finally:
        await conn.close()
    assert seen == 0, f"{table} leaked {seen} row(s) to a tenant party to neither portfolio"


@pytest.mark.asyncio
async def test_no_policy_recurses(seeded) -> None:
    """A cycle raises rather than leaking, so it is a liveness bug, not a leak.

    Asserted anyway because it is how the pack policies were written first,
    and because a `SELECT` that raises in production reads to an operator
    as a database fault rather than as a policy they can fix.
    """
    conn = await _connect(DSN)
    try:
        for table in TABLES:
            try:
                await _count_as(conn, MSSP_A, table)
            except Exception as exc:  # noqa: BLE001
                pytest.fail(f"reading {table} raised, which a recursive policy does: {exc}")
    finally:
        await conn.close()


@pytest.mark.asyncio
async def test_the_composite_key_refuses_a_forged_parent(seeded) -> None:
    """The denormalised `parent_tenant_id` cannot be made to lie.

    It exists only to keep the assignment policy free of a subquery; a
    column that could drift from the pack it mirrors would be worse than
    the recursion it replaced.
    """
    admin = await _connect(ADMIN_DSN)
    try:
        with pytest.raises(Exception) as exc:  # noqa: PT011 - asyncpg's own type
            await admin.execute(
                "INSERT INTO mssp_rule_pack_assignments (pack_id, parent_tenant_id, child_tenant_id) VALUES ($1,$2,$3)",
                seeded["pack_a"],
                MSSP_B,  # not pack_a's owner
                OUTSIDER,
            )
        assert "foreign key" in str(exc.value).lower()
    finally:
        await admin.close()
