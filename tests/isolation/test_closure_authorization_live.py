"""Every automatic closure of a production alert passes one authorization check.

Phase 1 of the closure remediation. See
`docs/remediation/phase-1-closure-authorization.md`.

What was wrong
--------------
`alerts.status` reaches `'resolved'` from exactly one statement — the `UPDATE
alerts` at the end of `app.investigator.ledger.persist_auto_triage`, whose
`CASE WHEN $7 AND NOT $10 THEN 'resolved'` turns on the caller-supplied
`auto_closed` flag. Two callers set that flag and only one of them asked
permission:

* `run_auto_triage` consulted `closure_policy.decide(...)` — the kill switch,
  the tenant's policy row, the earned `auto_close` grant;
* `FusedAlertTriageWorker._maybe_suppress_from_memory` set
  `state.status = COMPLETED` straight from a stored outcome prior, and
  `_record` forwarded `auto_closed=state.status is AgentStatus.COMPLETED`.
  The strings `closure_policy` and `kill_switch` appear in that module only
  inside comments.

So a tenant with `enabled = false` still got automatic closures, the kill
switch did not stop them, `require_grant` was not consulted, and the
confidence written against the decision was read off the prior rather than
measured. A remembered verdict was being treated as remembered permission.

Why this file is a live suite
-----------------------------
The defect is a disagreement between two modules about who asked permission,
resolved by SQL. A fake connection answers both sides happily: the offline
suite had a `_Pool` whose `fetchrow` returns whatever it was constructed with,
which cannot tell a policy that refused from a policy that was never read, and
cannot run the `CASE` expression that is the actual closure. Everything here
drives the real `persist_auto_triage`, the real `app.closure` modules and real
Postgres with every migration applied, and asserts on the row afterwards.

Against the pre-fix tree the first, third, fourth, fifth, sixth, seventh,
eighth and eleventh tests fail with the alert sitting at `status='resolved'`.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CLOSURE_AUTHZ_DSN", "").strip(),
        reason="ISOLATION_CLOSURE_AUTHZ_DSN is not set; this suite needs a live Postgres",
    ),
]

#: The verdict every test here uses. Auto-closeable, so nothing in these
#: results turns on verdict eligibility — the question under test is
#: authorization, and a non-closeable verdict would pass for the wrong reason.
BENIGN = "benign"


def _dsn() -> str:
    value = os.environ.get("ISOLATION_CLOSURE_AUTHZ_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_CLOSURE_AUTHZ_DSN is not set")
    return value


def _admin_dsn() -> str:
    """The schema owner, used only for fixtures and assertions.

    The code under test runs as the *runtime* role, where RLS is forced and
    a superuser's exemption cannot make a cross-tenant assertion pass for the
    wrong reason. Test setup is a different job: it writes rows for several
    tenants at once and reads them back, which under those same policies
    needs the owner. Keeping the two roles apart is what lets the production
    path be judged under the policies it really runs under.
    """
    return os.environ.get("ISOLATION_CLOSURE_AUTHZ_ADMIN_DSN", "").strip() or _dsn()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pool():
    """A real asyncpg pool, plus the `DATABASE_URL` production reads.

    Both the ledger and the closure policy resolve their own pool from the
    environment. Setting it here rather than handing each a pool is the
    point: a test that injected pools would not notice a module that
    resolves the wrong one.
    """
    asyncpg = pytest.importorskip("asyncpg")
    os.environ["DATABASE_URL"] = _dsn()

    from app.closure import policy as closure_policy
    from app.investigator import ledger as ledger_module

    created = await asyncpg.create_pool(
        _admin_dsn().replace("postgresql+asyncpg://", "postgresql://"),
        min_size=1,
        max_size=6,
    )
    yield created
    await created.close()

    await ledger_module.close_pool()
    # The closure package resolves the institutional pool. Closed through the
    # accessor it exports rather than by reaching into a private global, so
    # this teardown does not depend on the shape of a module it is testing.
    shared = await closure_policy.shared_pool()
    if shared is not None:
        await shared.close()
    closure_policy.reset_cache()


@pytest.fixture(autouse=True)
def _clear_policy_cache():
    """The policy caches its answer for ten seconds.

    Every test here changes a policy row and then asks again, which is
    exactly the window the cache covers, so leaving it would make tests pass
    or fail on their ordering.
    """
    from app.closure import policy as closure_policy

    closure_policy.reset_cache()
    yield
    closure_policy.reset_cache()


async def _tenant(pool) -> str:
    tenant_id = str(uuid.uuid4())
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1::uuid, $2, $3)",
            tenant_id,
            "closure-authz",
            f"closure-authz-{tenant_id[:8]}",
        )
    return tenant_id


async def _alert(pool, tenant_id: str, *, category: str = "identity") -> str:
    alert_id = str(uuid.uuid4())
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO alerts (id, tenant_id, title, severity, status, category)
            VALUES ($1::uuid, $2::uuid, 'closure authorization probe', 'medium', 'new', $3)
            """,
            alert_id,
            tenant_id,
            category,
        )
    return alert_id


async def _policy(
    pool,
    tenant_id: str,
    *,
    enabled: bool,
    threshold: float | None = None,
    require_grant: bool = False,
    alert_class: str | None = None,
) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO aisoc_closure_policies
                (tenant_id, alert_class, enabled, threshold, require_grant)
            VALUES ($1::uuid, $2, $3, $4, $5)
            """,
            tenant_id,
            alert_class,
            enabled,
            threshold,
            require_grant,
        )


async def _grant(pool, tenant_id: str, *, alert_class: str, state: str = "granted") -> None:
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


async def _engage_kill_switch(pool, tenant_id: str | None, *, reason: str) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO aisoc_kill_switch (tenant_id, engaged, reason, engaged_by)
            VALUES ($1::uuid, TRUE, $2, 'isolation-suite')
            """,
            tenant_id,
            reason,
        )


async def _release_kill_switches(pool) -> None:
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM aisoc_kill_switch")


async def _row(pool, alert_id: str) -> dict[str, Any]:
    async with pool.acquire() as conn:
        found = await conn.fetchrow(
            "SELECT status, disposition, resolved_at, ai_score FROM alerts WHERE id = $1::uuid",
            alert_id,
        )
    return dict(found)


async def _persist(
    *,
    tenant_id: str,
    alert_id: str,
    auto_closed: bool = True,
    confidence: float = 0.99,
    tier: str = "llm",
    verdict: str = BENIGN,
    shadow: bool = False,
    category: str = "identity",
) -> bool:
    """The real durable write, called exactly as the worker calls it."""
    from app.investigator import ledger as ledger_module

    return await ledger_module.persist_auto_triage(
        run_id=uuid.uuid4(),
        alert_id=alert_id,
        tenant_ref=tenant_id,
        alert_summary="closure authorization probe",
        raw_alert={"id": alert_id, "category": category},
        tier=tier,
        verdict=verdict,
        confidence=confidence,
        rationale="probe",
        findings=[],
        proposed_actions=[],
        auto_closed=auto_closed,
        shadow=shadow,
    )


class TestClosureNeedsExplicitAuthorization:
    """A tenant that has authorized nothing gets no automatic closures."""

    async def test_an_eligible_verdict_does_not_close_without_an_explicit_policy(self, pool) -> None:
        """Finding 14. The absence of a policy row was read as permission.

        `resolve_closure_policy` returned `confidence >= default_threshold`
        for a tenant with no row, so every tenant auto-closed from the moment
        the agent produced a confident benign verdict — including one that had
        never opened the screen.
        """
        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)

        await _persist(tenant_id=tenant_id, alert_id=alert_id)

        row = await _row(pool, alert_id)
        assert row["status"] != "resolved", (
            "an alert auto-resolved for a tenant that has authorized no automatic closure at all"
        )
        assert row["resolved_at"] is None

    async def test_an_explicitly_authorized_tenant_still_closes(self, pool) -> None:
        """The positive control, and the reason it is not optional.

        A gate that refuses everything satisfies every other assertion in
        this file. Without this test, wiring the chokepoint to `return False`
        would look like a complete fix.
        """
        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)
        await _policy(pool, tenant_id, enabled=True, threshold=0.80, require_grant=False)

        await _persist(tenant_id=tenant_id, alert_id=alert_id)

        row = await _row(pool, alert_id)
        assert row["status"] == "resolved", "an explicitly authorized tenant stopped auto-closing"
        assert row["resolved_at"] is not None
        assert row["disposition"] == BENIGN

    async def test_a_disabled_policy_blocks_closure(self, pool) -> None:
        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)
        await _policy(pool, tenant_id, enabled=False)

        await _persist(tenant_id=tenant_id, alert_id=alert_id)

        assert (await _row(pool, alert_id))["status"] != "resolved"

    async def test_an_unearned_grant_blocks_closure(self, pool) -> None:
        """`require_grant` is the tenant saying "only once shadow mode earns it"."""
        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)
        await _policy(pool, tenant_id, enabled=True, threshold=0.5, require_grant=True)

        await _persist(tenant_id=tenant_id, alert_id=alert_id)

        assert (await _row(pool, alert_id))["status"] != "resolved"

        from app.closure import policy as closure_policy

        earned = await _alert(pool, tenant_id)
        await _grant(pool, tenant_id, alert_class="identity")
        closure_policy.reset_cache()

        await _persist(tenant_id=tenant_id, alert_id=earned)

        assert (await _row(pool, earned))["status"] == "resolved", "an earned grant did not unblock closure"


class TestEveryClosurePathIsGoverned:
    """The LLM path asked permission. The other two did not."""

    async def test_the_memory_suppression_path_is_governed(self, pool) -> None:
        """Finding 1, at the durable boundary.

        `_maybe_suppress_from_memory` reaches `persist_auto_triage` with
        `auto_closed=True` and `tier='memory'` having consulted no policy at
        all. A trusted prior is evidence about the alert; it is not a grant.
        """
        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)
        await _policy(pool, tenant_id, enabled=False)

        await _persist(tenant_id=tenant_id, alert_id=alert_id, tier="memory", confidence=0.9)

        assert (await _row(pool, alert_id))["status"] != "resolved", (
            "outcome-memory suppression closed an alert for a tenant whose policy disables closure"
        )

    async def test_the_cached_verdict_path_is_governed(self, pool) -> None:
        """A cached verdict is a remembered answer, not remembered permission.

        The cost governor returns `Decision.DEDUPLICATED` with a verdict
        produced for an earlier alert, possibly under a policy that has since
        changed.
        """
        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)
        await _policy(pool, tenant_id, enabled=False)

        await _persist(tenant_id=tenant_id, alert_id=alert_id, tier="cached")

        assert (await _row(pool, alert_id))["status"] != "resolved"

    async def test_the_real_suppression_path_does_not_close_an_unauthorized_alert(self, pool) -> None:
        """The whole of Finding 1, driven through the worker rather than the ledger.

        Everything here is production: the real `FusedAlertTriageWorker`
        method, the real `LiveTriageWriter`, the real ledger and the real
        policy. Only the outcome prior is supplied, because that is the
        worker's *input* — a reader is the seam replay already uses, and
        faking it fakes the alert's history, not the authorization.
        """
        from app.agents.dispositions import BENIGN as BENIGN_DISPOSITION
        from app.memory.outcomes import HUMAN
        from app.models.state import InvestigationState
        from app.workers.fused_alert_consumer import FusedAlertTriageWorker
        from app.workers.triage_persistence import LiveTriageWriter

        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)
        await _policy(pool, tenant_id, enabled=False)

        class _PriorReader:
            """Returns one trusted prior. Every other read is empty."""

            async def lookup_prior(self, tenant: str, signature: str) -> dict[str, Any]:  # noqa: ARG002
                return {
                    "disposition": BENIGN_DISPOSITION,
                    "confidence": 0.97,
                    "count": 5,
                    "author": HUMAN,
                    "last_seen": datetime.now(UTC).isoformat(),
                }

        worker = FusedAlertTriageWorker.__new__(FusedAlertTriageWorker)
        worker._reader = _PriorReader()  # type: ignore[assignment]
        worker._writer = LiveTriageWriter()

        state = InvestigationState(
            incident_id=uuid.uuid4(),
            tenant_id=uuid.UUID(tenant_id),
            alert_summary="repeat alert",
            raw_alert={"id": alert_id, "category": "identity"},
        )

        suppressed = await worker._maybe_suppress_from_memory(
            state,
            "sig-authz-probe",
            [],
            writer=LiveTriageWriter(),
        )

        assert suppressed is not None, "the prior should still suppress re-triage; only the closure is withheld"
        assert (await _row(pool, alert_id))["status"] != "resolved", (
            "the production memory-suppression path closed an alert the tenant's policy forbids"
        )


class TestAuthorizationIsEvaluatedAtTheWrite:
    async def test_a_changed_policy_invalidates_an_earlier_authorization(self, pool) -> None:
        """Recovery must re-evaluate, never replay a stale permissive answer.

        A retried or resumed alert is persisted long after the decision that
        produced its verdict. If the authorization travelled with the verdict,
        a tenant disabling closure would not stop work already in flight.
        """
        from app.closure import policy as closure_policy

        tenant_id = await _tenant(pool)
        await _policy(pool, tenant_id, enabled=True, threshold=0.5, require_grant=False)

        first = await _alert(pool, tenant_id)
        await _persist(tenant_id=tenant_id, alert_id=first)
        assert (await _row(pool, first))["status"] == "resolved"

        async with pool.acquire() as conn:
            await conn.execute("UPDATE aisoc_closure_policies SET enabled = FALSE WHERE tenant_id = $1::uuid", tenant_id)
        closure_policy.reset_cache()

        second = await _alert(pool, tenant_id)
        await _persist(tenant_id=tenant_id, alert_id=second)

        assert (await _row(pool, second))["status"] != "resolved", (
            "closure continued after the tenant disabled it, so the authorization was retained rather than re-evaluated"
        )

    async def test_one_tenants_policy_cannot_authorize_anothers_closure(self, pool) -> None:
        authorized = await _tenant(pool)
        await _policy(pool, authorized, enabled=True, threshold=0.5, require_grant=False)

        other = await _tenant(pool)
        alert_id = await _alert(pool, other)

        await _persist(tenant_id=other, alert_id=alert_id)

        assert (await _row(pool, alert_id))["status"] != "resolved"


class TestStopControls:
    async def test_a_global_kill_switch_stops_closure(self, pool) -> None:
        from app.closure import policy as closure_policy

        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)
        await _policy(pool, tenant_id, enabled=True, threshold=0.5, require_grant=False)
        await _engage_kill_switch(pool, None, reason="incident 4471")
        closure_policy.reset_cache()

        try:
            await _persist(tenant_id=tenant_id, alert_id=alert_id)
            assert (await _row(pool, alert_id))["status"] != "resolved"
        finally:
            await _release_kill_switches(pool)
            closure_policy.reset_cache()

    async def test_a_tenant_kill_switch_stops_only_that_tenant(self, pool) -> None:
        from app.closure import policy as closure_policy

        stopped = await _tenant(pool)
        running = await _tenant(pool)
        for tenant_id in (stopped, running):
            await _policy(pool, tenant_id, enabled=True, threshold=0.5, require_grant=False)
        await _engage_kill_switch(pool, stopped, reason="tuning")
        closure_policy.reset_cache()

        try:
            stopped_alert = await _alert(pool, stopped)
            await _persist(tenant_id=stopped, alert_id=stopped_alert)
            assert (await _row(pool, stopped_alert))["status"] != "resolved"

            closure_policy.reset_cache()
            running_alert = await _alert(pool, running)
            await _persist(tenant_id=running, alert_id=running_alert)
            assert (await _row(pool, running_alert))["status"] == "resolved", (
                "one tenant's stop control froze another tenant's closures"
            )
        finally:
            await _release_kill_switches(pool)
            closure_policy.reset_cache()

    async def test_the_memory_path_obeys_the_kill_switch(self, pool) -> None:
        """The switch somebody reaches for at 3am did not reach this path at all."""
        from app.closure import policy as closure_policy

        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)
        await _policy(pool, tenant_id, enabled=True, threshold=0.5, require_grant=False)
        await _engage_kill_switch(pool, None, reason="incident 4471")
        closure_policy.reset_cache()

        try:
            await _persist(tenant_id=tenant_id, alert_id=alert_id, tier="memory", confidence=0.9)
            assert (await _row(pool, alert_id))["status"] != "resolved", (
                "the kill switch did not stop an outcome-memory closure"
            )
        finally:
            await _release_kill_switches(pool)
            closure_policy.reset_cache()


class TestShadowAndReplay:
    async def test_a_shadow_run_leaves_production_status_untouched(self, pool) -> None:
        """Already fixed before this phase; pinned here so the chokepoint cannot regress it."""
        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)
        await _policy(pool, tenant_id, enabled=True, threshold=0.5, require_grant=False)

        await _persist(tenant_id=tenant_id, alert_id=alert_id, shadow=True)

        row = await _row(pool, alert_id)
        assert row["status"] != "resolved"
        assert row["disposition"] is None, "a shadow verdict landed in the column the analyst fills in"


class TestManualClosureIsUnaffected:
    async def test_an_analyst_can_still_close_an_alert(self, pool) -> None:
        """The gate governs *automatic* closure only.

        A human resolving an alert through the API writes this row directly
        and must keep working for a tenant that has authorized no automation.
        """
        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)

        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE alerts SET status = 'closed', disposition = $2, resolved_at = now() WHERE id = $1::uuid",
                alert_id,
                "false_positive",
            )

        row = await _row(pool, alert_id)
        assert row["status"] == "closed"
        assert row["disposition"] == "false_positive"

    async def test_an_unauthorized_verdict_is_still_recorded(self, pool) -> None:
        """Withholding the closure must not withhold the triage.

        The alert stays open with the agent's verdict visible on it, which is
        the difference between "held for a human" and "lost".
        """
        tenant_id = await _tenant(pool)
        alert_id = await _alert(pool, tenant_id)

        written = await _persist(tenant_id=tenant_id, alert_id=alert_id)

        assert written is True
        row = await _row(pool, alert_id)
        assert row["status"] == "triaged", "an alert held back from closure should still show as triaged"
        assert row["ai_score"] == pytest.approx(0.99)
