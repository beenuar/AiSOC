"""An earned auto-close grant is actually readable by the closure policy.

Fix pass item 1.4. See `plans/aisoc_fix_pass_plan.plan.md`.

What was wrong
--------------
`_has_auto_close_grant` in `services/agents/app/closure/policy.py` queried a
table called `autonomy_grants`. There is no such table. Migration 067 creates
`aisoc_autonomy_grants`, and the query additionally filtered on `revoked_at`
and `expires_at`, neither of which that table has; its lifecycle is a `state`
column with `shadow`, `granted` and `demoted`, plus `demoted_at`.

Three names wrong in one statement, wrapped in `except Exception` that logged
at warning and returned `False`.

`require_grant` defaults to **true** in migration 078, so the effect was that a
tenant which enabled a closure policy could never auto-close anything. The
feature was off for exactly the tenants who turned it on.

Why the offline suite did not catch it
--------------------------------------
Its fake connection answers any query. A double that returns a row for
`SELECT 1 FROM a_table_that_does_not_exist` cannot distinguish a working query
from a broken one, and this is the second time that shape has shipped here.

What this file asserts
----------------------
Real Postgres with every migration applied. A tenant holding a `granted` row
auto-closes; a tenant holding none does not; and the three states are told
apart. Against the pre-fix tree every one of these fails with
`relation "autonomy_grants" does not exist`, swallowed into `False`.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CLOSURE_DSN", "").strip(),
        reason="ISOLATION_CLOSURE_DSN is not set; this suite needs a live Postgres",
    ),
]


def _dsn() -> str:
    value = os.environ.get("ISOLATION_CLOSURE_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_CLOSURE_DSN is not set")
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pool():
    """A real asyncpg pool, which is what the production code is handed."""
    asyncpg = pytest.importorskip("asyncpg")
    dsn = _dsn().replace("postgresql+asyncpg://", "postgresql://")
    created = await asyncpg.create_pool(dsn, min_size=1, max_size=4)
    yield created
    await created.close()


async def _tenant(pool) -> str:
    tenant_id = str(uuid.uuid4())
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, $2, $3)",
            tenant_id,
            "closure-grant",
            f"closure-{tenant_id[:8]}",
        )
    return tenant_id


async def _grant(pool, tenant_id: str, *, alert_class: str, state: str) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO aisoc_autonomy_grants
                (tenant_id, scope_kind, scope_key, capability, state, source, evidence)
            VALUES ($1::uuid, 'alert_class', $2, 'auto_close', $3, 'earned', '{}'::jsonb)
            """,
            tenant_id,
            alert_class,
            state,
        )


class TestAnEarnedGrantIsHonoured:
    async def test_a_granted_row_lets_the_class_auto_close(self, pool) -> None:
        """The whole point of the capability, and it had never worked."""
        from app.closure.policy import _has_auto_close_grant

        tenant_id = await _tenant(pool)
        await _grant(pool, tenant_id, alert_class="benign_scanner", state="granted")

        held = await _has_auto_close_grant(pool, tenant_id=tenant_id, alert_class="benign_scanner")

        assert held is True, (
            "an earned auto_close grant was not visible to the closure policy, so a tenant that enabled a policy could never auto-close"
        )

    async def test_a_tenant_with_no_grant_does_not_auto_close(self, pool) -> None:
        """The negative control. Without it a reader that returned True for
        everything would satisfy the assertion above."""
        from app.closure.policy import _has_auto_close_grant

        tenant_id = await _tenant(pool)

        assert await _has_auto_close_grant(pool, tenant_id=tenant_id, alert_class="benign_scanner") is False

    @pytest.mark.parametrize("state", ["shadow", "demoted"])
    async def test_a_grant_that_is_not_granted_does_not_count(self, pool, state: str) -> None:
        """`shadow` is still being evaluated and `demoted` was taken away.

        The pre-fix query filtered on `revoked_at IS NULL`, a column this
        table does not have, so it had no way to tell these apart even if the
        table name had been right.
        """
        from app.closure.policy import _has_auto_close_grant

        tenant_id = await _tenant(pool)
        await _grant(pool, tenant_id, alert_class="benign_scanner", state=state)

        assert await _has_auto_close_grant(pool, tenant_id=tenant_id, alert_class="benign_scanner") is False

    async def test_a_grant_for_another_class_does_not_leak(self, pool) -> None:
        """A grant is per alert class, not per tenant."""
        from app.closure.policy import _has_auto_close_grant

        tenant_id = await _tenant(pool)
        await _grant(pool, tenant_id, alert_class="benign_scanner", state="granted")

        assert await _has_auto_close_grant(pool, tenant_id=tenant_id, alert_class="credential_access") is False

    async def test_a_grant_does_not_leak_across_tenants(self, pool) -> None:
        from app.closure.policy import _has_auto_close_grant

        holder = await _tenant(pool)
        other = await _tenant(pool)
        await _grant(pool, holder, alert_class="benign_scanner", state="granted")

        assert await _has_auto_close_grant(pool, tenant_id=other, alert_class="benign_scanner") is False
