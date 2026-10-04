"""A tenant can opt itself into retro-hunts, against real Postgres.

Fix pass item 5.1. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
`retro_hunt_settings.enabled` defaults to FALSE under a comment reading "Off
until a tenant asks", and there was nowhere to ask: no route, no console
surface, nothing in `services/` touching the table beyond the ORM declaration.
Opting a tenant in meant an UPDATE issued by hand.

Why an offline test is not enough here
--------------------------------------
The write is an `INSERT ... ON CONFLICT (tenant_id) DO UPDATE`, and the thing
that matters is the branch a plain UPDATE would have got wrong: a tenant that
has never opted in has **no row at all**, so an UPDATE affects nothing and
reports success. That is the exact shape of defect this fix pass exists for,
and only a real table with a real primary key can tell the two apart.

What this file asserts
----------------------
Real Postgres with every migration applied, driving the handlers rather than
the SQL: a first opt-in creates the row, a second edits it rather than
duplicating, one tenant's settings are invisible to another, the budget
columns are not writable through this surface, and the lookback bound is
enforced.
"""

from __future__ import annotations

import os
import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_RETRO_HUNT_DSN", "").strip(),
        reason="ISOLATION_RETRO_HUNT_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_RETRO_HUNT_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_RETRO_HUNT_DSN is not set")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def engine():
    from sqlalchemy.ext.asyncio import create_async_engine

    dsn = _dsn()
    if dsn.startswith("postgresql://"):
        dsn = dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    eng = create_async_engine(dsn, poolclass=None)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest_asyncio.fixture(loop_scope="module")
async def two_tenants(engine):
    """Two real tenant rows. Cleaned up by the FK cascade on delete."""
    from sqlalchemy import text

    a, b = uuid.uuid4(), uuid.uuid4()
    async with engine.begin() as conn:
        for tid, slug in ((a, f"retro-a-{a.hex[:8]}"), (b, f"retro-b-{b.hex[:8]}")):
            await conn.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug)"),
                {"id": tid, "name": slug, "slug": slug},
            )
    try:
        yield a, b
    finally:
        async with engine.begin() as conn:
            await conn.execute(text("DELETE FROM tenants WHERE id = ANY(:ids)"), {"ids": [a, b]})


async def _get(engine, tenant_id: uuid.UUID):
    from app.api.v1.endpoints.retro_hunts import get_retro_hunt_settings
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as session:
        return await get_retro_hunt_settings(db=session, user=SimpleNamespace(tenant_id=tenant_id))


async def _put(engine, tenant_id: uuid.UUID, **fields):
    from app.api.v1.endpoints.retro_hunts import RetroHuntSettingsIn, put_retro_hunt_settings
    from sqlalchemy.ext.asyncio import AsyncSession

    async with AsyncSession(engine) as session:
        return await put_retro_hunt_settings(
            body=RetroHuntSettingsIn(**fields),
            db=session,
            user=SimpleNamespace(tenant_id=tenant_id),
        )


class TestOptingIn:
    async def test_a_tenant_with_no_row_reads_as_not_opted_in(self, engine, two_tenants) -> None:
        """Not a 404. "You have not opted in" is a state with a correct answer,
        and a 404 would read as "retro-hunts do not exist here"."""
        a, _ = two_tenants

        settings = await _get(engine, a)

        assert settings.enabled is False
        assert settings.lookback_days == 30

    async def test_the_first_opt_in_creates_the_row(self, engine, two_tenants) -> None:
        """The branch a plain UPDATE gets wrong: there is no row to update, so
        an UPDATE would affect nothing and report success."""
        a, _ = two_tenants

        written = await _put(engine, a, enabled=True, lookback_days=14, include_federated=False)

        assert written.enabled is True
        assert written.lookback_days == 14
        assert written.include_federated is False

        # And it is durable, read back through a fresh session.
        assert (await _get(engine, a)).enabled is True

    async def test_a_second_write_edits_rather_than_duplicating(self, engine, two_tenants) -> None:
        from sqlalchemy import text

        a, _ = two_tenants
        await _put(engine, a, enabled=True, lookback_days=14)
        await _put(engine, a, enabled=False, lookback_days=90)

        async with engine.connect() as conn:
            rows = (
                await conn.execute(
                    text("SELECT count(*) FROM retro_hunt_settings WHERE tenant_id = :t"),
                    {"t": a},
                )
            ).scalar_one()

        assert rows == 1, f"{rows} settings rows for one tenant; the upsert duplicated instead of updating"
        assert (await _get(engine, a)).lookback_days == 90


class TestIsolationAndBounds:
    async def test_one_tenants_opt_in_is_invisible_to_another(self, engine, two_tenants) -> None:
        a, b = two_tenants
        await _put(engine, a, enabled=True, lookback_days=7)

        assert (await _get(engine, b)).enabled is False, "tenant B can see tenant A's opt-in"

    async def test_the_budget_is_not_writable_through_this_surface(self, engine, two_tenants) -> None:
        """The negative control that matters. The budget is the operator's
        ceiling on what one tenant can cost the deployment, and a tenant that
        could raise its own ceiling would not have one."""
        from app.api.v1.endpoints.retro_hunts import RetroHuntSettingsIn

        a, _ = two_tenants
        await _put(engine, a, enabled=True)

        assert "max_sweeps_per_hour" not in RetroHuntSettingsIn.model_fields
        assert "max_sweeps_per_day" not in RetroHuntSettingsIn.model_fields
        assert (await _get(engine, a)).max_sweeps_per_hour == 120

    @pytest.mark.parametrize("days", [0, -1, 366, 10_000])
    async def test_an_out_of_range_lookback_is_refused_before_postgres_sees_it(self, engine, two_tenants, days: int) -> None:
        """The column CHECK would also catch this, as a 500. Refusing in the
        model gives the caller a 422 naming the bound."""
        from pydantic import ValidationError

        a, _ = two_tenants
        with pytest.raises(ValidationError):
            await _put(engine, a, enabled=True, lookback_days=days)
