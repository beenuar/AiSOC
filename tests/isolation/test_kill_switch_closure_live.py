"""An engaged platform switch actually stops automatic closure.

Why this exists separately
--------------------------
``test_kill_switch_global_live.py`` proves the row can be written and
``test_kill_switch_endpoint_live.py`` proves a product surface writes it.
Neither proves the thing the switch is *for*. This repository treats a
control nothing consults as not existing, and the global row spent its whole
life in exactly that state — readable, documented, and written by nothing —
so asserting that the reader honours it is the half that makes the other two
worth having.

This runs against ``services/agents``, whose ``app`` package owns
``closure.policy``. ``services/api`` ships a different package by the same
name, so importing one shadows the other; the live workflow runs this leg
from ``services/agents`` for that reason, exactly as
``test_closure_grant_live.py`` does.

No ``importorskip`` on ``app.closure.policy``. A skip in a job whose purpose
is to run this live is indistinguishable from a pass, and that shape has
shipped here before.
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

#: Well above any configured threshold, so a verdict that is refused here was
#: refused by the switch rather than by confidence.
CERTAIN = 0.99


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


@pytest_asyncio.fixture(loop_scope="module", autouse=True)
async def _clean(pool):
    """Clear the singleton global row, and drop the resolver's cache.

    The cache is a 10-second TTL keyed per tenant, so without this a test
    that engages the switch would still be answered from the state the
    previous test left behind.
    """
    from app.closure.policy import reset_cache

    reset_cache()
    yield
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM aisoc_kill_switch WHERE tenant_id IS NULL")
    reset_cache()


async def _tenant(pool) -> str:
    tenant_id = str(uuid.uuid4())
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, $2, $3)",
            tenant_id,
            "ks-closure",
            f"ksc-{tenant_id[:8]}",
        )
    return tenant_id


async def _authorize_closure(pool, tenant_id: str, *, threshold: float = 0.50) -> None:
    """Give the tenant an explicit closure policy.

    Automatic closure is default-deny: a tenant with no row in
    `aisoc_closure_policies` does not auto-close, whatever the kill switch
    says. A test about the *switch* therefore has to authorize closure
    first, or releasing the switch leaves the alert refused for an unrelated
    reason and the test proves nothing about the switch at all.
    """
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO aisoc_closure_policies
                (tenant_id, alert_class, enabled, threshold, require_grant)
            VALUES ($1::uuid, NULL, TRUE, $2, FALSE)
            """,
            tenant_id,
            threshold,
        )


async def _engage_globally(pool, reason: str) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO aisoc_kill_switch (tenant_id, engaged, reason, engaged_by)
            VALUES (NULL, TRUE, $1, 'operator')
            ON CONFLICT ((TRUE)) WHERE tenant_id IS NULL
            DO UPDATE SET engaged = TRUE, reason = EXCLUDED.reason, released_by = NULL, released_at = NULL
            """,
            reason,
        )


class TestTheClosurePathObservesTheGlobalSwitch:
    async def test_an_engaged_global_switch_refuses_closure(self, pool) -> None:
        """The reader is `services/agents` `kill_switch_engaged`, which the
        closure resolver calls first and separately from the policy."""
        from app.closure.policy import kill_switch_engaged, reset_cache

        tenant_id = await _tenant(pool)
        await _engage_globally(pool, "platform-wide stop")
        reset_cache()

        engaged, why = await kill_switch_engaged(pool, tenant_id)

        assert engaged is True, "the closure path did not observe an engaged platform kill switch"
        assert "global" in why, f"the reason does not name the scope an operator has to go and release: {why!r}"

    async def test_it_refuses_a_verdict_the_threshold_would_have_closed(self, pool) -> None:
        """Through `resolve_closure_policy`, which is what the triage path
        calls. A confidence of 0.99 against a 0.50 bar closes on any other
        day, so the refusal is attributable to the switch alone."""
        from app.closure.policy import reset_cache, resolve_closure_policy

        tenant_id = await _tenant(pool)
        await _engage_globally(pool, "platform-wide stop")
        reset_cache()

        decision = await resolve_closure_policy(pool, tenant_id=tenant_id, alert_class=None, confidence=CERTAIN, default_threshold=0.50)

        assert decision.allowed is False
        assert decision.source == "kill_switch", f"refused for the wrong reason: {decision.source} / {decision.reason}"

    async def test_a_tenant_that_engaged_nothing_is_still_stopped(self, pool) -> None:
        """The global switch is the platform operator's and does not need any
        tenant's agreement. A stop that only covered tenants who had opted in
        would not be a platform-wide stop."""
        from app.closure.policy import kill_switch_engaged, reset_cache

        first = await _tenant(pool)
        second = await _tenant(pool)
        await _engage_globally(pool, "platform-wide stop")
        reset_cache()

        assert (await kill_switch_engaged(pool, first))[0] is True
        assert (await kill_switch_engaged(pool, second))[0] is True

    async def test_releasing_it_resumes_closure(self, pool) -> None:
        """The negative control for this file. Without it, a reader that
        returned True unconditionally would satisfy every assertion above."""
        from app.closure.policy import kill_switch_engaged, reset_cache, resolve_closure_policy

        tenant_id = await _tenant(pool)
        # Closure is default-deny, so without an explicit policy the release
        # below would be masked by the missing policy and this control could
        # not tell "switch released" from "tenant never authorized closure".
        await _authorize_closure(pool, tenant_id)
        await _engage_globally(pool, "platform-wide stop")
        reset_cache()
        assert (await kill_switch_engaged(pool, tenant_id))[0] is True

        async with pool.acquire() as conn:
            await conn.execute("UPDATE aisoc_kill_switch SET engaged = FALSE WHERE tenant_id IS NULL")
        reset_cache()

        engaged, _why = await kill_switch_engaged(pool, tenant_id)
        decision = await resolve_closure_policy(pool, tenant_id=tenant_id, alert_class=None, confidence=CERTAIN, default_threshold=0.50)

        assert engaged is False, "closure stayed frozen after the switch was released"
        assert decision.allowed is True, f"closure did not resume after release: {decision.reason}"
