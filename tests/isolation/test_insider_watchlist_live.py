"""The insider watchlist's Postgres truths, against real Postgres.

Why this has to be live
-----------------------
* Expiry exclusion lives **inside the SQL** — `rebuild_managed_rules`'s
  SELECT refuses expired and ref-less rows in its WHERE clause, which a
  stubbed session always gets right by construction.
* The two-document contract is upsert behaviour: the console save updates
  `yaml_text` and must leave `managed_yaml` alone; the watchlist upsert
  updates `managed_yaml` and must leave `yaml_text` alone. Both are
  `ON CONFLICT` arms only a real unique constraint exercises.
* The `watchlist_source` vocabulary is a CHECK constraint.
* RLS on `insider_watchlist_policies` is judged under the DML-only
  `aisoc_app` role, which a superuser silently bypasses — including the
  unbound arm the sweep worker depends on.

Against the pre-change tree every test fails at setup: `managed_yaml`,
`watchlist_expires_at` and `insider_watchlist_policies` do not exist.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_INSIDER_WATCHLIST_DSN", "").strip(),
        reason="ISOLATION_INSIDER_WATCHLIST_DSN is not set; this suite needs a live Postgres",
    ),
]

_API = Path(__file__).resolve().parents[2] / "services" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()


def _dsn(name: str) -> str:
    return os.environ[name].strip()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pools():
    import asyncpg

    admin = await asyncpg.connect(_dsn("ISOLATION_INSIDER_WATCHLIST_ADMIN_DSN"))
    app = await asyncpg.connect(_dsn("ISOLATION_INSIDER_WATCHLIST_DSN"))

    suffix = uuid.uuid4().hex[:8]
    for tenant, label in ((TENANT_A, f"iw-live-a-{suffix}"), (TENANT_B, f"iw-live-b-{suffix}")):
        await admin.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2) ON CONFLICT (id) DO NOTHING",
            tenant,
            label,
        )
    yield admin, app

    for tenant in (TENANT_A, TENANT_B):
        await admin.execute("DELETE FROM insider_watchlist_policies WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM workforce_members WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM aisoc_business_context_rule_sets WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM insider_indicators WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM user_risk_profiles WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM aisoc_cases WHERE tenant_id = $1 AND case_type = 'insider_review'", tenant)
        await admin.execute("DELETE FROM tenants WHERE id = $1", tenant)
    await admin.close()
    await app.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    """A real AsyncSession over the app DSN, so the suite drives the service's
    own functions (and therefore its own SQL) rather than re-typing it."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    dsn = _dsn("ISOLATION_INSIDER_WATCHLIST_DSN").replace("postgresql://", "postgresql+asyncpg://")
    engine = create_async_engine(dsn, poolclass=None)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def _bind(conn, tenant: uuid.UUID) -> None:
    await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(tenant))


async def _add_profile(
    admin,
    tenant: uuid.UUID,
    ref: str | None,
    *,
    watchlisted: bool = True,
    expires_in_days: int = 30,
) -> uuid.UUID:
    pid = uuid.uuid4()
    await admin.execute(
        """
        INSERT INTO user_risk_profiles
            (id, tenant_id, external_user_ref, is_watchlisted, watchlist_reason,
             watchlist_expires_at, watchlist_source)
        VALUES ($1, $2, $3, $4, 'live fixture', $5, 'manual')
        """,
        pid,
        tenant,
        ref,
        watchlisted,
        datetime.now(UTC) + timedelta(days=expires_in_days),
    )
    return pid


async def test_rebuild_excludes_expired_and_refless_rows(pools, session_factory):
    """The exclusion is the SQL's WHERE clause — the live half of expiry."""

    from app.services.insider_watchlist import rebuild_managed_rules

    admin, _ = pools
    await _add_profile(admin, TENANT_A, "active@example.com", expires_in_days=30)
    await _add_profile(admin, TENANT_A, "expired@example.com", expires_in_days=-1)
    await _add_profile(admin, TENANT_A, None)  # ref-less: nothing to match
    await _add_profile(admin, TENANT_A, "cleared@example.com", watchlisted=False)

    async with session_factory() as db:
        covered = await rebuild_managed_rules(db, TENANT_A)
        await db.commit()
    assert covered == 1

    doc = await admin.fetchval("SELECT managed_yaml FROM aisoc_business_context_rule_sets WHERE tenant_id = $1", TENANT_A)
    assert "active@example.com" in doc
    assert "expired@example.com" not in doc
    assert "cleared@example.com" not in doc


async def test_the_two_documents_never_clobber_each_other(pools, session_factory):
    """Console saves own yaml_text; the watchlist owns managed_yaml."""
    from app.services.insider_watchlist import rebuild_managed_rules

    admin, _ = pools
    # Console-style save first (the endpoint's own upsert shape).
    await admin.execute(
        """
        INSERT INTO aisoc_business_context_rule_sets (tenant_id, yaml_text, enabled, updated_at)
        VALUES ($1, 'rules: []  # analyst draft', TRUE, now())
        ON CONFLICT (tenant_id) DO UPDATE SET
            yaml_text = EXCLUDED.yaml_text, enabled = EXCLUDED.enabled, updated_at = EXCLUDED.updated_at
        """,
        TENANT_A,
    )
    async with session_factory() as db:
        await rebuild_managed_rules(db, TENANT_A)
        await db.commit()
    row = await admin.fetchrow(
        "SELECT yaml_text, managed_yaml FROM aisoc_business_context_rule_sets WHERE tenant_id = $1",
        TENANT_A,
    )
    assert row["yaml_text"] == "rules: []  # analyst draft", "the watchlist upsert must not touch yaml_text"
    managed_before = row["managed_yaml"]
    assert "active@example.com" in managed_before

    # A second console save must leave the managed document alone.
    await admin.execute(
        """
        INSERT INTO aisoc_business_context_rule_sets (tenant_id, yaml_text, enabled, updated_at)
        VALUES ($1, 'rules: []  # edited draft', TRUE, now())
        ON CONFLICT (tenant_id) DO UPDATE SET
            yaml_text = EXCLUDED.yaml_text, enabled = EXCLUDED.enabled, updated_at = EXCLUDED.updated_at
        """,
        TENANT_A,
    )
    after = await admin.fetchval("SELECT managed_yaml FROM aisoc_business_context_rule_sets WHERE tenant_id = $1", TENANT_A)
    assert after == managed_before, "the console save must not touch managed_yaml"


async def test_sweep_flips_expired_rows_and_rebuilds(pools, session_factory):
    from app.services.insider_watchlist import sweep_expired

    admin, _ = pools
    pid = await _add_profile(admin, TENANT_B, "leaver@example.com", expires_in_days=-2)
    async with session_factory() as db:
        summary = await sweep_expired(db)
        await db.commit()
    assert summary.expired >= 1
    flag = await admin.fetchval("SELECT is_watchlisted FROM user_risk_profiles WHERE id = $1", pid)
    assert flag is False
    doc = await admin.fetchval("SELECT managed_yaml FROM aisoc_business_context_rule_sets WHERE tenant_id = $1", TENANT_B)
    assert doc == "" or "leaver@example.com" not in doc


async def test_watchlist_source_vocabulary_is_a_check_constraint(pools):
    import asyncpg

    admin, _ = pools
    with pytest.raises(asyncpg.exceptions.CheckViolationError):
        await admin.execute(
            """
            INSERT INTO user_risk_profiles (id, tenant_id, watchlist_source)
            VALUES ($1, $2, 'carrier-pigeon')
            """,
            uuid.uuid4(),
            TENANT_A,
        )


async def test_policy_rls_under_the_app_role(pools):
    """A bound session sees its own tenant only; the unbound arm (the sweep
    worker's shape) sees every row — both judged under aisoc_app."""
    admin, app = pools
    for tenant in (TENANT_A, TENANT_B):
        await admin.execute(
            """
            INSERT INTO insider_watchlist_policies (tenant_id, hr_sync_enabled)
            VALUES ($1, TRUE)
            ON CONFLICT (tenant_id) DO UPDATE SET hr_sync_enabled = TRUE
            """,
            tenant,
        )
    role = await app.fetchval("SELECT current_user")
    bypass = await app.fetchval("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
    assert bypass is False, f"role {role!r} bypasses RLS; this test would prove nothing"

    await _bind(app, TENANT_A)
    rows = await app.fetch("SELECT tenant_id FROM insider_watchlist_policies")
    assert {r["tenant_id"] for r in rows} == {TENANT_A}

    await app.execute("SELECT set_config('app.current_tenant_id', '', false)")
    rows = await app.fetch("SELECT tenant_id FROM insider_watchlist_policies")
    assert {TENANT_A, TENANT_B} <= {r["tenant_id"] for r in rows}


async def test_hr_door_lists_a_departing_member_end_to_end(pools, session_factory):
    """workforce_members row + opted-in policy -> watchlist row + managed rule
    + review case, driven through the service's own sweep."""
    from app.services.insider_watchlist import sweep_hr

    admin, _ = pools
    await admin.execute(
        """
        INSERT INTO workforce_members (tenant_id, connector_type, external_id, email, display_name, status, end_date)
        VALUES ($1, 'workday', 'hr-1', 'departing@example.com', 'Dep Arting', 'terminated', CURRENT_DATE)
        ON CONFLICT DO NOTHING
        """,
        TENANT_B,
    )
    async with session_factory() as db:
        summary = await sweep_hr(db)
        await db.commit()
    assert summary.hr_watchlisted >= 1, f"sweep summary: {summary}"

    row = await admin.fetchrow(
        """
        SELECT is_watchlisted, watchlist_source, watchlist_expires_at
        FROM user_risk_profiles
        WHERE tenant_id = $1 AND lower(external_user_ref) = 'departing@example.com'
        """,
        TENANT_B,
    )
    assert row is not None and row["is_watchlisted"] is True
    assert row["watchlist_source"] == "hr_sync"
    assert row["watchlist_expires_at"] > datetime.now(UTC)

    doc = await admin.fetchval("SELECT managed_yaml FROM aisoc_business_context_rule_sets WHERE tenant_id = $1", TENANT_B)
    assert "departing@example.com" in doc

    case = await admin.fetchrow(
        """
        SELECT title, description FROM aisoc_cases
        WHERE tenant_id = $1 AND case_type = 'insider_review'
        ORDER BY created_at DESC LIMIT 1
        """,
        TENANT_B,
    )
    assert case is not None
    assert "departing@example.com" in case["title"]
    # The lake is absent in this harness: the case must say so, never zero.
    assert "unknown, not zero" in case["description"] or "Could not check" in case["description"]

    # Idempotence: a second sweep lists nobody twice.
    async with session_factory() as db:
        second = await sweep_hr(db)
        await db.commit()
    assert second.hr_watchlisted == 0
