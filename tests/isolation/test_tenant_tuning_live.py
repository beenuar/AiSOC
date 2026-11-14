"""A tenant's tuning read out of Postgres and applied by the real engine.

Maturity: the evidence that takes **Per-tenant detection tuning in the
live engine** to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

Why a live read matters more here than almost anywhere
-------------------------------------------------------
`OverlayCache._fetch` returns `None` when it cannot read, and the caller
turns that into the empty overlay. That fail-soft is deliberate — losing
a tenant's suppressions because the database blinked would turn their
queue back on — but it means **a permanently broken overlay is
indistinguishable from a tenant who has configured no tuning**. Both show
an engine that suppresses nothing.

That is not a hypothetical failure mode. The query selected `rule_id` and
`updated_by` from `detection_rules`, which has neither; every execution
raised, the handler logged a warning, and the overlay loaded nothing on
every deployment. Thirty unit tests passed throughout, because they ran
against a fake that answered for whatever columns it was asked about.

The offline suite now has a schema check, but it regex-parses the
migration and compares it to a regex over the module's own source: text
against text, never a connection. This file opens one.

The negative control
--------------------
`test_an_untuned_tenant_still_fires` is the half that makes the rest
mean something. Every suppression assertion here would also pass against
an engine that fires nothing at all.
"""

from __future__ import annotations

import json
import os
import uuid

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
        not os.environ.get("ISOLATION_TUNING_DSN", "").strip(),
        reason="ISOLATION_TUNING_DSN is not set; this suite needs live infrastructure",
    ),
]

#: One rule, defined here rather than loaded from the 2,603-rule corpus,
#: so the test states exactly what it expects to fire. The engine under
#: test is the real one either way.
NOISY_RULE = {
    "id": "det-live-tuning-001",
    "name": "Build agent runs a shell",
    "severity": "high",
    "category": "endpoint",
    "match_when": {"host": "JENKINS-01"},
}

EVENT = {"ocsf_event": {"raw_data": json.dumps({"host": "JENKINS-01", "src_country": "RU"})}}


def _dsn() -> str:
    value = os.environ.get("ISOLATION_TUNING_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_TUNING_DSN is not set; this suite needs a live Postgres")
    return value


@pytest_asyncio.fixture
async def pool():
    asyncpg = pytest.importorskip("asyncpg")
    created = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4)
    yield created
    async with created.acquire() as conn:
        await conn.execute("DELETE FROM detection_rules WHERE name LIKE 'live-tuning-%'")
    await created.close()


@pytest_asyncio.fixture
async def tenant(pool):  # noqa: ANN001
    tenant_id = uuid.uuid4()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            tenant_id,
            f"tuning-{tenant_id.hex[:8]}",
            f"tuning-{tenant_id.hex[:8]}",
        )
    yield str(tenant_id)
    async with pool.acquire() as conn:
        await conn.execute("DELETE FROM detection_rules WHERE tenant_id = $1", tenant_id)
        await conn.execute("DELETE FROM tenants WHERE id = $1", tenant_id)


async def _write_tuning(
    pool,
    tenant: str,
    *,
    status: str = "active",
    suppression: dict | None = None,
    threshold: dict | None = None,
    author: str = "alice@example.com",
) -> None:
    """Write tuning the way the console does: into `detection_rules`.

    The `det-*` identifier goes in `provenance->>'source_id'`, which is
    where migration 036 puts a rule's stable external id. Getting that
    wrong is precisely the defect this suite exists for.
    """
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO detection_rules
                (id, tenant_id, name, rule_language, rule_body, category,
                 status, severity, suppression_config, threshold_config,
                 provenance, author)
            VALUES (gen_random_uuid(), $1::uuid, $2, 'sigma', 'x', 'endpoint',
                    $3, 'high', $4::jsonb, $5::jsonb, $6::jsonb, $7)
            """,
            tenant,
            f"live-tuning-{uuid.uuid4().hex[:8]}",
            status,
            json.dumps(suppression or {}),
            json.dumps(threshold or {}),
            json.dumps({"source_id": NOISY_RULE["id"]}),
            author,
        )


def _engine():  # noqa: ANN202
    from app.services.detection_engine import DetectionEngine

    return DetectionEngine(rules=[NOISY_RULE])


async def _overlay(pool, tenant: str):  # noqa: ANN001, ANN202
    """The production cache, reading the production query."""
    from app.services.tenant_overlay import OverlayCache

    return await OverlayCache(pool, reload_seconds=0).get(tenant)


class TestTheQueryRunsAtAll:
    async def test_the_overlay_query_executes_against_the_real_schema(self, pool, tenant) -> None:  # noqa: ANN001
        """The defect, stated as a test.

        `_fetch` selected two columns `detection_rules` does not have.
        Every execution raised, the handler turned it into a warning, and
        the overlay loaded nothing on every deployment while thirty unit
        tests passed.
        """
        from app.services.tenant_overlay import OverlayCache

        await _write_tuning(pool, tenant, status="disabled")
        fetched = await OverlayCache(pool, reload_seconds=0)._fetch(tenant)

        assert fetched is not None, (
            "_fetch returned None, which means a query raised and the fail-soft path "
            "swallowed it. A tenant with tuning configured would see none applied, and "
            "nothing would say so."
        )
        # Two result sets since depth plan 3.3: the tuning rows, and this
        # tenant's privileged identities from `identity_nodes`. Both run
        # against the real schema here, which is the point — the second
        # query is as able to name a column that does not exist as the
        # first was, and that defect looked exactly like "no tuning".
        rows, identities = fetched
        assert len(rows) == 1, f"expected the one tuned rule, got {rows!r}"
        assert identities == [], f"this tenant imported no directory, so the privilege query must return nothing, got {identities!r}"


class TestSuppression:
    async def test_an_untuned_tenant_still_fires(self, pool, tenant) -> None:  # noqa: ANN001
        """The negative control.

        Every assertion below would also pass against an engine that
        fires nothing, which is exactly what a silently-broken overlay
        looks like.
        """
        overlay = await _overlay(pool, tenant)
        hits = _engine().evaluate(EVENT, overlay)
        assert len(hits) == 1, (
            "a rule that should fire did not, with no tuning configured. Every suppression assertion in this file is vacuous if this fails."
        )

    async def test_a_disabled_rule_stops_firing(self, pool, tenant) -> None:  # noqa: ANN001
        """The product claim: a rule you turn off in the console actually
        stops producing alerts."""
        await _write_tuning(pool, tenant, status="disabled")
        overlay = await _overlay(pool, tenant)

        assert _engine().evaluate(EVENT, overlay) == [], (
            "a rule disabled in detection_rules still fired. That is the shape where the "
            "console shows it disabled and the alerts keep arriving."
        )

    async def test_a_field_suppression_stops_firing(self, pool, tenant) -> None:  # noqa: ANN001
        await _write_tuning(
            pool,
            tenant,
            suppression={"suppress_when": {"host": ["JENKINS-01"]}, "reason": "build agent"},
        )
        overlay = await _overlay(pool, tenant)
        assert _engine().evaluate(EVENT, overlay) == []

    async def test_a_suppression_for_a_different_value_does_not(self, pool, tenant) -> None:  # noqa: ANN001
        """Suppression has to be specific, or it is just an off switch."""
        await _write_tuning(pool, tenant, suppression={"suppress_when": {"host": ["SOME-OTHER-HOST"]}})
        overlay = await _overlay(pool, tenant)
        assert len(_engine().evaluate(EVENT, overlay)) == 1

    async def test_the_author_and_reason_travel_with_the_suppression(self, pool, tenant) -> None:  # noqa: ANN001
        """A dropped alert with no explanation is indistinguishable from a
        rule that did not match, and an analyst asking why they stopped
        seeing something deserves an answer."""
        await _write_tuning(
            pool,
            tenant,
            status="disabled",
            suppression={"reason": "known noisy on build agents"},
            author="alice@example.com",
        )
        overlay = await _overlay(pool, tenant)
        why = overlay.suppresses(NOISY_RULE["id"], {"host": "JENKINS-01"})

        assert why, "the overlay suppressed without recording why"
        assert "alice@example.com" in why
        assert "build agents" in why


class TestTheSeverityFloor:
    async def test_a_match_below_the_floor_is_held(self, pool, tenant) -> None:  # noqa: ANN001
        await _write_tuning(pool, tenant, threshold={"min_severity": "critical"})
        overlay = await _overlay(pool, tenant)
        assert _engine().evaluate(EVENT, overlay) == [], "a high-severity match fired against a critical floor"

    async def test_a_match_at_the_floor_still_fires(self, pool, tenant) -> None:  # noqa: ANN001
        await _write_tuning(pool, tenant, threshold={"min_severity": "high"})
        overlay = await _overlay(pool, tenant)
        assert len(_engine().evaluate(EVENT, overlay)) == 1


class TestTenantIsolation:
    async def test_one_tenants_tuning_does_not_silence_another(self, pool, tenant) -> None:  # noqa: ANN001
        """The plan's own done-when, against two real tenant rows."""
        other = uuid.uuid4()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                other,
                f"tuning-b-{other.hex[:8]}",
                f"tuning-b-{other.hex[:8]}",
            )
        try:
            await _write_tuning(pool, tenant, status="disabled")

            theirs = await _overlay(pool, str(other))
            assert len(_engine().evaluate(EVENT, theirs)) == 1, "tenant A's disable silenced the rule for tenant B"

            mine = await _overlay(pool, tenant)
            assert _engine().evaluate(EVENT, mine) == []
        finally:
            async with pool.acquire() as conn:
                await conn.execute("DELETE FROM detection_rules WHERE tenant_id = $1", other)
                await conn.execute("DELETE FROM tenants WHERE id = $1", other)


class TestTheFailSoftIsVisible:
    async def test_an_unreachable_database_yields_the_empty_overlay(self, pool, tenant) -> None:  # noqa: ANN001
        """Documenting the behaviour that makes this whole file necessary.

        A broken read produces an overlay that suppresses nothing, which
        on its own is indistinguishable from a tenant with no tuning. The
        fail-soft is the right choice; the live test above is what stops
        it hiding a permanent break.
        """
        from app.services.tenant_overlay import EMPTY, OverlayCache

        class _Unreachable:
            def acquire(self):  # noqa: ANN202
                raise RuntimeError("database is gone")

        assert await OverlayCache(_Unreachable(), reload_seconds=0).get(tenant) is EMPTY
