"""Live-Postgres proof that a portfolio aggregate cannot see outside itself.

The MSSP surface deliberately reads more than one tenant's rows, which makes
it the one place in the product where "filter by the caller's tenant" is not
the rule. That is worth a gate that runs against a real database rather than
a mocked session, for the reason the cross-store suite exists at all: an
isolation contract that is only unit-tested against a mock is a claim, not a
gate.

Shape of every test here, borrowed from `tests/isolation/test_live_stores.py`
because it is what makes such a test meaningful:

1. Seed a managed portfolio *and* data belonging to tenants outside it.
2. Assert the outside data really exists, so a scoped read returning
   nothing cannot pass vacuously on an empty database.
3. Assert the scoped read returns the portfolio and never the outsiders.

Two of these also stand as regression tests against what this surface used
to do. `/mssp/tenants` returned five hardcoded companies — Acme Corp, Globex
Industries, Wayne Enterprises — with invented alert counts and health
scores. `test_every_returned_tenant_exists_in_the_database` fails against
that code, because none of those names is a row.

Skips when no database answers, so a local `pytest` run stays green — but
**cannot** skip where it is supposed to run. `integration.yml` sets
`MSSP_ISOLATION_REQUIRED=1`, and an unreachable database is then a failure
rather than a skip. A gate that quietly declines to run is the shape that
left the public scoreboard ten weeks stale while its page promised weekly
rows; checking the DSN *string* is not the same as checking that a database
is there, and `ci.yml` sets a placeholder DSN with no server behind it.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from app.services.entitlements import limit_for
from app.services.mssp_portfolio import portfolio_alerts, summarise, tenant_rollups
from app.services.org_scope import (
    PortfolioScope,
    PortfolioScopeError,
    narrow,
    resolve_portfolio_scope,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
# Set in `integration.yml`, where a real Postgres with the full migration
# chain is guaranteed. When it is set, an unreachable database fails the
# build instead of skipping past the isolation proof.
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

pytestmark = [
    pytest.mark.skipif(
        "postgres" not in DSN and not REQUIRED,
        reason="needs a live Postgres with the migration chain applied (integration.yml)",
    ),
    pytest.mark.asyncio,
]

# Fixed ids so a failure names something greppable.
ORG_P = uuid.UUID("0a000000-0000-0000-0000-000000000001")
ORG_Q = uuid.UUID("0a000000-0000-0000-0000-000000000002")
TENANT_A = uuid.UUID("0b000000-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("0b000000-0000-0000-0000-00000000000b")
# Managed by a *different* organisation — the interesting outsider, because
# it is in the organisation tables and must still be invisible to P.
TENANT_C = uuid.UUID("0c000000-0000-0000-0000-00000000000c")
# Managed by nobody.
TENANT_D = uuid.UUID("0d000000-0000-0000-0000-00000000000d")

OWNER_P = uuid.UUID("0e000000-0000-0000-0000-000000000001")
OPERATOR_P = uuid.UUID("0e000000-0000-0000-0000-000000000002")
NEWCOMER_P = uuid.UUID("0e000000-0000-0000-0000-000000000003")
STRANGER = uuid.UUID("0e000000-0000-0000-0000-000000000009")

_ALL_TENANTS = (TENANT_A, TENANT_B, TENANT_C, TENANT_D)
_ALL_USERS = (OWNER_P, OPERATOR_P, NEWCOMER_P, STRANGER)


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(
                "MSSP_ISOLATION_REQUIRED is set but no database answered at DATABASE_URL — "
                f"the cross-tenant isolation proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _seed(session)
        try:
            yield session
        finally:
            await _teardown(session)
    await engine.dispose()


async def _teardown(session) -> None:
    await session.rollback()
    for table in ("alerts", "cases", "connectors"):
        await session.execute(
            text(f"DELETE FROM {table} WHERE tenant_id = ANY(:ids)"),
            {"ids": [str(t) for t in _ALL_TENANTS]},
        )
    await session.execute(
        text("DELETE FROM organizations WHERE id = ANY(:ids)"),
        {"ids": [str(ORG_P), str(ORG_Q)]},
    )
    await session.execute(text("DELETE FROM users WHERE id = ANY(:ids)"), {"ids": [str(u) for u in _ALL_USERS]})
    await session.execute(
        text("DELETE FROM tenants WHERE id = ANY(:ids)"),
        {"ids": [str(t) for t in _ALL_TENANTS]},
    )
    await session.commit()


async def _seed(session) -> None:
    await _teardown(session)

    await session.execute(
        text(
            "INSERT INTO tenants (id, name, slug, limits) VALUES "
            "(:a, 'Portfolio A', 'iso-portfolio-a', '{\"connectors\": 1}'::jsonb), "
            "(:b, 'Portfolio B', 'iso-portfolio-b', '{}'::jsonb), "
            "(:c, 'Rival Customer', 'iso-rival-customer', '{}'::jsonb), "
            "(:d, 'Unmanaged', 'iso-unmanaged', '{}'::jsonb)"
        ),
        {"a": str(TENANT_A), "b": str(TENANT_B), "c": str(TENANT_C), "d": str(TENANT_D)},
    )
    await session.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, username, hashed_password, role) VALUES "
            "(:owner, :a, 'owner@iso.test', 'owner', 'x', 'admin'), "
            "(:operator, :a, 'operator@iso.test', 'operator', 'x', 'soc_analyst'), "
            "(:newcomer, :a, 'newcomer@iso.test', 'newcomer', 'x', 'soc_analyst'), "
            "(:stranger, :d, 'stranger@iso.test', 'stranger', 'x', 'soc_analyst')"
        ),
        {
            "owner": str(OWNER_P),
            "operator": str(OPERATOR_P),
            "newcomer": str(NEWCOMER_P),
            "stranger": str(STRANGER),
            "a": str(TENANT_A),
            "d": str(TENANT_D),
        },
    )
    await session.execute(
        text(
            # Provider P's own staff sign in to tenant A, so A is both its
            # home tenant and part of its portfolio — the shape a provider
            # that also runs its own estate actually has.
            "INSERT INTO organizations (id, slug, name, home_tenant_id) VALUES "
            "(:p, 'iso-provider-p', 'Provider P', :a), (:q, 'iso-provider-q', 'Provider Q', NULL)"
        ),
        {"p": str(ORG_P), "q": str(ORG_Q), "a": str(TENANT_A)},
    )
    await session.execute(
        text("INSERT INTO organization_tenants (org_id, tenant_id) VALUES " "(:p, :a), (:p, :b), (:q, :c)"),
        {"p": str(ORG_P), "q": str(ORG_Q), "a": str(TENANT_A), "b": str(TENANT_B), "c": str(TENANT_C)},
    )
    await session.execute(
        text(
            "INSERT INTO organization_members (org_id, user_id, org_role) VALUES "
            "(:p, :owner, 'owner'), (:p, :operator, 'operator'), (:p, :newcomer, 'operator')"
        ),
        {"p": str(ORG_P), "owner": str(OWNER_P), "operator": str(OPERATOR_P), "newcomer": str(NEWCOMER_P)},
    )
    # The operator is granted one of the two managed tenants. The newcomer is
    # granted nothing.
    await session.execute(
        text("INSERT INTO organization_member_tenants (org_id, user_id, tenant_id) VALUES (:p, :operator, :a)"),
        {"p": str(ORG_P), "operator": str(OPERATOR_P), "a": str(TENANT_A)},
    )

    await session.execute(
        text(
            "INSERT INTO alerts (tenant_id, title, severity, status, is_synthetic) VALUES "
            "(:a, 'A real critical', 'critical', 'new', false), "
            "(:b, 'B real medium', 'medium', 'new', false), "
            "(:b, 'B SEEDED DEMO ROW', 'critical', 'new', true), "
            "(:c, 'RIVAL CUSTOMER SECRET', 'critical', 'new', false), "
            "(:d, 'UNMANAGED SECRET', 'critical', 'new', false)"
        ),
        {"a": str(TENANT_A), "b": str(TENANT_B), "c": str(TENANT_C), "d": str(TENANT_D)},
    )
    await session.execute(
        text(
            "INSERT INTO connectors (tenant_id, name, connector_type, is_enabled, last_sync, health_status) VALUES "
            "(:a, 'a-okta', 'okta', true, now(), 'healthy'), "
            "(:c, 'c-okta', 'okta', true, now(), 'healthy'), "
            "(:d, 'd-okta', 'okta', true, now(), 'healthy')"
        ),
        {"a": str(TENANT_A), "c": str(TENANT_C), "d": str(TENANT_D)},
    )
    await session.commit()


def _owner_scope() -> PortfolioScope:
    return PortfolioScope(
        org_id=ORG_P,
        org_slug="iso-provider-p",
        org_role="owner",
        tenant_ids=frozenset({TENANT_A, TENANT_B}),
        portfolio_wide=True,
    )


async def _user(session, user_id: uuid.UUID):
    from app.models.tenant import User

    return await session.get(User, user_id)


# ---------------------------------------------------------------------------
# Step 2 of the shape: the outsiders really exist
# ---------------------------------------------------------------------------


async def test_outsider_data_is_really_present(db) -> None:
    """Without this, every assertion below could pass on an empty database."""
    total = (
        await db.execute(
            text("SELECT count(*) FROM alerts WHERE tenant_id = ANY(:ids)"),
            {"ids": [str(t) for t in _ALL_TENANTS]},
        )
    ).scalar_one()
    assert total == 5, total

    outsiders = (
        await db.execute(
            text("SELECT count(*) FROM alerts WHERE tenant_id = ANY(:ids)"),
            {"ids": [str(TENANT_C), str(TENANT_D)]},
        )
    ).scalar_one()
    assert outsiders == 2, outsiders


# ---------------------------------------------------------------------------
# The isolation property
# ---------------------------------------------------------------------------


async def test_rollups_never_include_a_tenant_outside_the_portfolio(db) -> None:
    rollups = await tenant_rollups(db, _owner_scope())

    assert {r.name for r in rollups} == {"Portfolio A", "Portfolio B"}
    assert all(r.tenant_id in {TENANT_A, TENANT_B} for r in rollups)
    assert "Rival Customer" not in {r.name for r in rollups}, "another organisation's tenant leaked into the rollup"
    assert "Unmanaged" not in {r.name for r in rollups}


async def test_portfolio_alerts_never_include_an_outsider(db) -> None:
    titles = [a["title"] for a in await portfolio_alerts(db, _owner_scope())]

    assert "A real critical" in titles
    assert "B real medium" in titles
    assert not any("SECRET" in t for t in titles), f"outsider alert leaked: {titles}"


async def test_connector_health_counts_only_portfolio_connectors(db) -> None:
    """C and D each own an enabled connector; the portfolio owns one."""
    summary = summarise(await tenant_rollups(db, _owner_scope()))
    assert summary["connectors_total"] == 1, summary


async def test_an_operator_sees_only_the_tenants_granted_to_them(db) -> None:
    scope = await resolve_portfolio_scope(db, await _user(db, OPERATOR_P))

    assert scope.is_member
    assert scope.portfolio_wide is False
    assert scope.tenant_ids == frozenset({TENANT_A})

    rollups = await tenant_rollups(db, scope)
    assert {r.name for r in rollups} == {"Portfolio A"}


async def test_a_member_with_no_grants_resolves_to_empty_not_everything(db) -> None:
    """The failure mode this whole design is shaped around.

    An operator who has been added to the organisation but assigned no
    accounts must see nothing. If "no grants" ever degraded into "no
    filter", every new hire would get the entire book of business.
    """
    scope = await resolve_portfolio_scope(db, await _user(db, NEWCOMER_P))

    assert scope.is_member, "should still be recognised as a member"
    assert scope.tenant_ids == frozenset()

    with pytest.raises(PortfolioScopeError):
        await tenant_rollups(db, scope)


async def test_a_non_member_resolves_to_no_organisation_at_all(db) -> None:
    scope = await resolve_portfolio_scope(db, await _user(db, STRANGER))

    assert scope.is_member is False
    assert scope.tenant_ids == frozenset()


async def test_an_owner_of_one_organisation_cannot_reach_another(db) -> None:
    owner = await resolve_portfolio_scope(db, await _user(db, OWNER_P))

    assert owner.org_id == ORG_P
    assert TENANT_C not in owner.tenant_ids, "Provider Q's customer is in Provider P's scope"


async def test_a_tenant_filter_cannot_select_a_tenant_outside_the_portfolio(db) -> None:
    """`?tenant_id=` narrows; it must never widen."""
    narrowed = narrow(_owner_scope(), [TENANT_C, TENANT_D])
    assert narrowed.tenant_ids == frozenset()

    with pytest.raises(PortfolioScopeError):
        await tenant_rollups(db, narrowed)


# ---------------------------------------------------------------------------
# Regressions against the invented-tenant surface these routes used to serve
# ---------------------------------------------------------------------------


async def test_every_returned_tenant_exists_in_the_database(db) -> None:
    """Fails against the pre-fix `/mssp/tenants`.

    That route returned Acme Corp, Globex Industries, Initech LLC, Wayne
    Enterprises and Stark Solutions with invented alert counts and health
    scores. None of them was a row in `tenants`, which is precisely what
    this asserts.
    """
    rollups = await tenant_rollups(db, _owner_scope())
    assert rollups, "fixture should produce rows"

    known = {uuid.UUID(str(r[0])) for r in (await db.execute(text("SELECT id FROM tenants"))).all()}
    for rollup in rollups:
        assert rollup.tenant_id in known, f"{rollup.name} is not a tenant in this database"


async def test_figures_are_counted_not_asserted(db) -> None:
    """Every headline number must move when the underlying rows move."""
    before = summarise(await tenant_rollups(db, _owner_scope()))

    await db.execute(
        text(
            "INSERT INTO alerts (tenant_id, title, severity, status, is_synthetic) "
            "VALUES (:a, 'A second critical', 'critical', 'new', false)"
        ),
        {"a": str(TENANT_A)},
    )
    await db.commit()

    after = summarise(await tenant_rollups(db, _owner_scope()))
    assert after["critical_alerts"] == before["critical_alerts"] + 1
    assert after["open_alerts"] == before["open_alerts"] + 1


async def test_seeded_rows_are_counted_apart_from_real_ones(db) -> None:
    """A demo install must not report its fixtures as the customer's posture."""
    rollups = {r.name: r for r in await tenant_rollups(db, _owner_scope())}
    tenant_b = rollups["Portfolio B"]

    assert tenant_b.synthetic_alerts == 1
    assert tenant_b.critical_alerts == 0, "a seeded critical was counted as real"

    default_titles = [a["title"] for a in await portfolio_alerts(db, _owner_scope())]
    assert "B SEEDED DEMO ROW" not in default_titles

    opted_in = await portfolio_alerts(db, _owner_scope(), include_synthetic=True)
    seeded = [a for a in opted_in if a["title"] == "B SEEDED DEMO ROW"]
    assert seeded and seeded[0]["is_synthetic"] is True, "opting in must label what it returns"


async def test_headroom_is_measured_and_uncapped_stays_uncapped(db) -> None:
    rollups = {r.name: r for r in await tenant_rollups(db, _owner_scope())}
    limits = {h.key: h for h in rollups["Portfolio A"].limits}

    # Tenant A has one enabled connector and a configured ceiling of one.
    assert limits["connectors"].used == 1
    assert limits["connectors"].limit == 1
    assert limits["connectors"].state == "exhausted"

    # Tenant A configured nothing else, and this build ships no plan caps.
    assert limits["seats"].limit is None
    assert limits["seats"].state == "unlimited"
    assert limits["seats"].used == 3, "seats must be counted, not guessed"

    # Tenant B configured nothing at all.
    b_limits = {h.key: h for h in rollups["Portfolio B"].limits}
    assert all(h.limit is None for h in b_limits.values())
    assert limit_for({}, "connectors") is None


async def test_mttr_is_null_rather_than_zero_when_nothing_closed(db) -> None:
    """A tenant that has closed no cases has no resolution time.

    Reporting 0.0 would put the account that has done nothing at the top of
    the league table.
    """
    rollups = {r.name: r for r in await tenant_rollups(db, _owner_scope())}
    assert rollups["Portfolio A"].mttr_minutes is None

    await db.execute(
        text(
            "INSERT INTO cases (tenant_id, case_number, title, status, created_at, closed_at) "
            "VALUES (:a, :num, 'closed case', 'closed', now() - interval '30 minutes', now())"
        ),
        {"a": str(TENANT_A), "num": f"ISO-{uuid.uuid4().hex[:8]}"},
    )
    await db.commit()

    rollups = {r.name: r for r in await tenant_rollups(db, _owner_scope())}
    assert rollups["Portfolio A"].mttr_minutes == pytest.approx(30.0, abs=1.0)


# ---------------------------------------------------------------------------
# The database refuses what the application would also refuse
# ---------------------------------------------------------------------------


async def test_a_grant_cannot_name_a_tenant_outside_the_portfolio(db) -> None:
    """Enforced by the composite foreign key, not by the writing code path.

    If the API check were deleted tomorrow, this would still fail.
    """
    with pytest.raises(Exception) as excinfo:
        await db.execute(
            text("INSERT INTO organization_member_tenants (org_id, user_id, tenant_id) VALUES (:p, :u, :c)"),
            {"p": str(ORG_P), "u": str(OPERATOR_P), "c": str(TENANT_C)},
        )
        await db.commit()
    assert "foreign key" in str(excinfo.value).lower()
    await db.rollback()


async def test_two_organisations_cannot_both_claim_one_tenant(db) -> None:
    with pytest.raises(Exception) as excinfo:
        await db.execute(
            text("INSERT INTO organization_tenants (org_id, tenant_id) VALUES (:q, :a)"),
            {"q": str(ORG_Q), "a": str(TENANT_A)},
        )
        await db.commit()
    assert "unique" in str(excinfo.value).lower() or "duplicate" in str(excinfo.value).lower()
    await db.rollback()


async def test_releasing_a_tenant_revokes_every_grant_over_it(db) -> None:
    """Offboarding a customer must not leave a live grant behind."""
    before = (
        await db.execute(
            text("SELECT count(*) FROM organization_member_tenants WHERE tenant_id = :a"),
            {"a": str(TENANT_A)},
        )
    ).scalar_one()
    assert before == 1

    await db.execute(
        text("DELETE FROM organization_tenants WHERE org_id = :p AND tenant_id = :a"),
        {"p": str(ORG_P), "a": str(TENANT_A)},
    )
    await db.commit()

    after = (
        await db.execute(
            text("SELECT count(*) FROM organization_member_tenants WHERE tenant_id = :a"),
            {"a": str(TENANT_A)},
        )
    ).scalar_one()
    assert after == 0

    # And the operator's resolved scope collapses to empty rather than
    # silently keeping the account they no longer manage.
    scope = await resolve_portfolio_scope(db, await _user(db, OPERATOR_P))
    assert scope.tenant_ids == frozenset()


async def test_releasing_a_tenant_does_not_delete_the_tenant(db) -> None:
    """Offboarding from a provider is not a deletion request."""
    await db.execute(
        text("DELETE FROM organization_tenants WHERE org_id = :p AND tenant_id = :b"),
        {"p": str(ORG_P), "b": str(TENANT_B)},
    )
    await db.commit()

    still_there = (await db.execute(text("SELECT count(*) FROM tenants WHERE id = :b"), {"b": str(TENANT_B)})).scalar_one()
    assert still_there == 1

    alerts_kept = (await db.execute(text("SELECT count(*) FROM alerts WHERE tenant_id = :b"), {"b": str(TENANT_B)})).scalar_one()
    assert alerts_kept == 2


# ---------------------------------------------------------------------------
# Offboarding: the organisation participates, and the report says so
# ---------------------------------------------------------------------------


async def test_deleting_the_home_tenant_reports_and_removes_the_organisation(db) -> None:
    """`discover_tenant_tables` looks for a column named `tenant_id`.

    `organizations.home_tenant_id` is not one, so the row would be removed
    by the foreign-key cascade and never appear in the report. An erasure
    sign-off that undercounts is the same class of problem as one that
    overstates completeness.
    """
    from app.services.tenant_deletion import purge_postgres

    # The Postgres store directly: the satellite stores are not running in
    # this job, and `delete_tenant` correctly rolls the whole erasure back
    # when any of them fails, which would hide what we are asserting.
    preview = await purge_postgres(db, TENANT_A, dry_run=True)
    assert preview.ok, preview.error
    assert preview.detail.get("organizations") == 1, preview.detail

    applied = await purge_postgres(db, TENANT_A, dry_run=False)
    assert applied.ok, applied.error
    await db.commit()

    orgs_left = (await db.execute(text("SELECT count(*) FROM organizations WHERE id = :p"), {"p": str(ORG_P)})).scalar_one()
    assert orgs_left == 0

    # The customers the provider managed are not the provider's to erase.
    survivors = (
        await db.execute(
            text("SELECT count(*) FROM tenants WHERE id = ANY(:ids)"),
            {"ids": [str(TENANT_B), str(TENANT_C)]},
        )
    ).scalar_one()
    assert survivors == 2
