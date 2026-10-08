"""Dispatch re-checks a standing grant's evidence, against a real database.

Fix pass item 3.7. See ``plans/aisoc_fix_pass_plan.plan.md``.

``services/actions`` resolved unattended execution from ``state = 'granted'``
alone. That column is a cached verdict: the only thing that ever moved a grant
out of it was ``reconcile_grants``, whose single production caller was the
handler behind ``GET /api/v1/autonomy-policy/grants``. So on a deployment
nobody opens that page on, a tenant whose agreement had collapsed kept
auto-executing containment at a customer's vendor indefinitely.

Why this file is separate from ``test_autonomy_promotion_live.py``
------------------------------------------------------------------

``services/api`` and ``services/actions`` both package their code as top-level
``app``, so one process holds one of them. That suite runs with the API on the
path; this one runs with the actions service on it, and
``integration.yml`` gives it its own step with ``working-directory:
services/actions`` for exactly that reason.

Why it needs a real database rather than a fake connection
-----------------------------------------------------------

The thing being proven is that two independently-written halves agree: a
Postgres aggregate written in the shared rules module, and a pure evaluator
written beside it. A fake connection would answer whatever shape the test
handed it, which is the assertion agreeing with itself. The arity defect this
code shipped with makes the point — passing seven parameters to a statement
that binds six failed closed, so every grant on every deployment was withheld
while the log called it unreadable evidence, and no offline double would have
noticed because no offline double refuses a parameter count.

Skipping
--------

Skips when no Postgres answers, and refuses to skip when
``AUTONOMY_DRIFT_LIVE_REQUIRED`` is set, following its sibling suite. A suite
that can silently skip where it is supposed to run reports green for a gate
nobody executed.
"""

from __future__ import annotations

import os
import re
import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("AUTONOMY_DRIFT_LIVE_REQUIRED", "").strip().lower() in {"1", "true", "yes", "on"}

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        "postgres" not in DSN and not REQUIRED,
        reason="no Postgres DATABASE_URL; set AUTONOMY_DRIFT_LIVE_REQUIRED=1 to make this a failure",
    ),
]

CLASS = "identity"
RULE = "det-identity-004"
SOURCE = "okta"
MODEL = "ollama_chat/llama3.2:3b"

#: A HIGH blast-radius verb, deliberately. The cost of reading a stale
#: ``granted`` is whatever the verb does, and this is the one that takes a
#: production host off the network.
VERB = "isolate_host"

MALICIOUS = "true_positive"
FALSE_POSITIVE = "false_positive"

#: L3. High enough that the tier is not what withholds the verb, so a failure
#: here is about the evidence and not about the ladder.
TIER = 3


def _asyncpg_dsn(url: str) -> str:
    """Whatever spelling the environment holds, as a plain asyncpg DSN."""
    return re.sub(r"^postgres(ql)?\+asyncpg://", "postgresql://", url)


@asynccontextmanager
async def probe():
    """A tenant at L3 measuring one class, and a connection. Cleans up after itself."""
    asyncpg = pytest.importorskip("asyncpg")

    conn = await asyncpg.connect(_asyncpg_dsn(DSN), timeout=10.0)
    try:
        try:
            await conn.execute("SELECT 1 FROM aisoc_autonomy_grants LIMIT 0")
        except Exception as exc:  # noqa: BLE001
            if REQUIRED:
                pytest.fail(f"migration 067 has not been applied: {exc}")
            pytest.skip(f"aisoc_autonomy_grants is absent: {exc}")

        tenant_id = uuid.uuid4()
        slug = f"drift-{tenant_id.hex[:10]}"
        await conn.execute("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)", tenant_id, "Drift probe", slug)
        await conn.execute(
            "INSERT INTO aisoc_shadow_mode (tenant_id, alert_class, enabled, enabled_at) VALUES ($1, $2, TRUE, now())",
            tenant_id,
            CLASS,
        )
        await conn.execute("INSERT INTO remediation_maturity (tenant_id, maturity_tier) VALUES ($1, $2)", tenant_id, TIER)
        try:
            yield conn, tenant_id
        finally:
            for table in ("aisoc_autonomy_grants", "aisoc_shadow_decisions", "aisoc_shadow_mode", "remediation_maturity"):
                await conn.execute(f"DELETE FROM {table} WHERE tenant_id = $1", tenant_id)  # noqa: S608 - fixed table list
    finally:
        await conn.close()


async def _record(conn, tenant_id, *, count: int, verdict: str, disposition: str, resolved_at: datetime) -> None:
    """``count`` decisions that said ``verdict`` and were closed ``disposition``."""
    for index in range(count):
        await conn.execute(
            """
            INSERT INTO aisoc_shadow_decisions
                (tenant_id, alert_id, alert_class, rule_id, source, model, verdict,
                 confidence, decided_at, analyst_disposition, resolution_source, resolved_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 0.91, $8, $9, 'aisoc', $8)
            """,
            tenant_id,
            uuid.uuid4(),
            CLASS,
            RULE,
            SOURCE,
            MODEL,
            verdict,
            resolved_at + timedelta(seconds=index * 60),
            disposition,
        )


async def _grant(conn, tenant_id) -> None:
    """A standing ``action_verb`` grant, written directly.

    Not earned through ``request_promotion``: that lives in ``services/api``
    and cannot be imported here. Writing the row states the precondition this
    suite is about — a grant whose *state* says granted — without making the
    dispatch assertion depend on the promotion gate agreeing first.
    """
    await conn.execute(
        """
        INSERT INTO aisoc_autonomy_grants
            (tenant_id, scope_kind, scope_key, capability, state, source, evidence, granted_at)
        VALUES ($1, 'action_verb', $2, 'auto_execute', 'granted', 'earned', '{}'::jsonb, now())
        """,
        tenant_id,
        VERB,
    )


async def _strong_record(conn, tenant_id) -> None:
    base = datetime.now(UTC) - timedelta(days=20)
    await _record(conn, tenant_id, count=200, verdict=FALSE_POSITIVE, disposition=FALSE_POSITIVE, resolved_at=base)
    await _record(conn, tenant_id, count=40, verdict=MALICIOUS, disposition=MALICIOUS, resolved_at=base + timedelta(days=1))


async def _resolve(tenant_id):
    from app.services.tenant_policy import clear_cache, resolve_tenant_policy

    # The resolver caches for 30s and these tests change the evidence under
    # one tenant several times, which is not something production does.
    clear_cache()
    return await resolve_tenant_policy(str(tenant_id))


class TestDispatchReadsTheEvidenceAndNotJustTheState:
    async def test_a_grant_whose_evidence_has_drifted_is_withheld(self):
        """The reproduction. The row still says ``granted``; the verb is refused.

        Deliberately without running the API's sweep first, because the point
        is the window between its ticks: in that window the stored state is
        stale and this is the only thing standing between it and a vendor.
        """
        async with probe() as (conn, tenant_id):
            await _strong_record(conn, tenant_id)
            await _grant(conn, tenant_id)
            await _record(
                conn,
                tenant_id,
                count=30,
                verdict=FALSE_POSITIVE,
                disposition=MALICIOUS,
                resolved_at=datetime.now(UTC) - timedelta(minutes=30),
            )

            state = await conn.fetchval("SELECT state FROM aisoc_autonomy_grants WHERE tenant_id = $1", tenant_id)
            assert state == "granted", "the stored state must still be stale, or this proves nothing"

            policy = await _resolve(tenant_id)

            assert policy.from_store is True, f"the tenant's stored policy was not read: source={policy.source}"
            assert policy.earned_autonomy_for(VERB) is None
            assert policy.earned_verbs == {}

    async def test_a_grant_whose_record_still_holds_is_honoured(self):
        """The control. A re-check that always refuses is not a re-check.

        It would pass the test above, and it would silently disable earned
        autonomy on every deployment — a product that has stopped acting,
        wearing the appearance of caution.
        """
        async with probe() as (conn, tenant_id):
            await _strong_record(conn, tenant_id)
            await _grant(conn, tenant_id)
            await _record(
                conn,
                tenant_id,
                count=30,
                verdict=FALSE_POSITIVE,
                disposition=FALSE_POSITIVE,
                resolved_at=datetime.now(UTC) - timedelta(minutes=30),
            )

            policy = await _resolve(tenant_id)

            assert policy.earned_autonomy_for(VERB) == "earned"

    async def test_a_demoted_row_is_refused_without_reaching_the_aggregate(self):
        """The pre-existing state check still stands in front of the new one."""
        async with probe() as (conn, tenant_id):
            await _strong_record(conn, tenant_id)
            await _grant(conn, tenant_id)
            await conn.execute(
                "UPDATE aisoc_autonomy_grants SET state = 'demoted', demoted_at = now() WHERE tenant_id = $1",
                tenant_id,
            )

            policy = await _resolve(tenant_id)

            assert policy.earned_autonomy_for(VERB) is None

    async def test_an_empty_window_keeps_the_grant_as_the_shared_evaluator_says(self):
        """Dispatch must not be stricter than the evaluator, only no laxer.

        ``evaluate_demotion`` deliberately ignores an unmeasured rate: a week
        in which no malicious alert arrived is not evidence the agent got
        worse, and revoking over an empty denominator would make quiet weeks
        dangerous. The grant was earned on evidence at promotion time and an
        empty window since does not retract it.

        This is asserted rather than assumed because the obvious instinct
        writing a dispatch-side re-check is to refuse what it cannot measure,
        and a re-check that invented that rule would be a *second* definition
        of the floors — the divergence the shared module exists to prevent,
        reintroduced by the fix for it.
        """
        async with probe() as (conn, tenant_id):
            await _grant(conn, tenant_id)

            policy = await _resolve(tenant_id)

            assert policy.earned_autonomy_for(VERB) == "earned"
