"""The dashboard and the portfolio must report the same MTTR for the same rows.

A live acceptance pass found the dashboard publishing **CASES CLOSED (7D) 0**
and **MTTR 0.0 hrs** for a tenant that had closed two cases at a 90-minute
mean, which `/mssp/portfolio` reported correctly as 1.5h. Two surfaces
disagreeing about one number is the symptom; two separately written queries
over the same table is the cause.

So the assertions here come in two shapes, and the second is the one that
matters over time:

* the figures are right against rows whose values are known by construction —
  one case closed after 60 minutes, one after 120, mean 90.0; and
* the two surfaces produce the **same** figure from the same rows, which is
  what a shared definition is for. Checking each against a hardcoded 90.0
  independently would let both drift together and still pass.

Every test below fails against the pre-change tree:
`cases_closed` counted `status = 'resolved' AND updated_at >= …` (the
lifecycle's terminal state is `closed`, and `updated_at` moves whenever
anyone edits the case), and MTTR averaged `alerts.resolved_at`, a column no
part of ordinary case work writes — so it averaged nothing and `float(None
or 0.0)` published that as a confident zero.

Skips when no database answers so a local `pytest` run stays green, but
cannot skip where it is supposed to run: `integration.yml` sets
`MSSP_ISOLATION_REQUIRED=1`, and an unreachable database is then a failure.
A gate that quietly declines to run is the shape this whole file exists to
catch.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.services.mssp_portfolio import tenant_rollups
from app.services.org_scope import PortfolioScope
from app.services.resolution_time import (
    CLOSED_CASE_PREDICATE,
    MTTR_MINUTES_EXPR,
    MTTR_WINDOW,
    tenant_case_mttr_minutes,
    tenant_cases_closed,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

# The skip lives on the `db` fixture rather than on the module, because not
# every test here needs a database. A module-level `pytestmark` also skipped
# the one test that does not, so the check on whether the two surfaces share a
# definition ran only where Postgres did — which is the narrower half of the
# places it is meant to hold.

# Fixed ids so a failure names something greppable.
ORG = uuid.UUID("0a100000-0000-0000-0000-000000000001")
TENANT = uuid.UUID("0b100000-0000-0000-0000-00000000000a")
# A tenant in the same portfolio that has closed nothing.
TENANT_IDLE = uuid.UUID("0b100000-0000-0000-0000-00000000000b")

_ALL_TENANTS = (TENANT, TENANT_IDLE)


@pytest_asyncio.fixture
async def db():
    if "postgres" not in DSN and not REQUIRED:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(
                "MSSP_ISOLATION_REQUIRED is set but no database answered at DATABASE_URL — "
                f"the MTTR parity proof did not run: {type(exc).__name__}: {exc}"
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
    await session.execute(
        text("DELETE FROM aisoc_cases WHERE tenant_id = ANY(:ids)"),
        {"ids": list(_ALL_TENANTS)},
    )
    await session.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": str(ORG)})
    await session.execute(
        text("DELETE FROM tenants WHERE id = ANY(:ids)"),
        {"ids": list(_ALL_TENANTS)},
    )
    await session.commit()


async def _case(session, *, tenant, number, opened_minutes_ago, duration_minutes, status="closed", closed=True):
    now = datetime.now(UTC)
    created = now - timedelta(minutes=opened_minutes_ago)
    closed_at = created + timedelta(minutes=duration_minutes) if closed else None
    await session.execute(
        text(
            """
            INSERT INTO aisoc_cases (id, tenant_id, case_number, title, status, created_at, closed_at, updated_at)
            VALUES (:id, :tenant, :number, :title, :status, :created, :closed_at, :updated)
            """
        ),
        {
            "id": uuid.uuid4(),
            "tenant": tenant,
            "number": number,
            "title": f"parity fixture {number}",
            "status": status,
            "created": created,
            "closed_at": closed_at,
            # Deliberately *old*, so anything windowing on `updated_at`
            # instead of `closed_at` misses these rows.
            "updated": created,
        },
    )


async def _seed(session) -> None:
    await _teardown(session)
    for tenant, name in ((TENANT, "Parity Tenant"), (TENANT_IDLE, "Idle Tenant")):
        await session.execute(
            text("INSERT INTO tenants (id, name, slug, plan) VALUES (:id, :name, :slug, 'enterprise')"),
            {"id": str(tenant), "name": name, "slug": f"parity-{tenant.hex}"},
        )
    await session.execute(
        text("INSERT INTO organizations (id, slug, name, kind) VALUES (:id, :slug, :name, 'mssp')"),
        {"id": str(ORG), "slug": f"parity-org-{ORG.hex[:8]}", "name": "Parity Org"},
    )

    # Mean of 60 and 120 is 90.0 minutes = 1.5 hours.
    await _case(session, tenant=TENANT, number=f"PAR-{TENANT.hex[:6]}-1", opened_minutes_ago=4320, duration_minutes=60)
    await _case(session, tenant=TENANT, number=f"PAR-{TENANT.hex[:6]}-2", opened_minutes_ago=2880, duration_minutes=120)
    await session.commit()


@pytest.mark.asyncio
async def test_cases_closed_counts_the_terminal_state_not_the_intermediate_one(db) -> None:
    """Both fixtures are `closed`; the old query looked for `resolved`."""
    week_ago = datetime.now(UTC) - timedelta(days=7)
    assert await tenant_cases_closed(db, TENANT, week_ago) == 2


@pytest.mark.asyncio
async def test_cases_closed_windows_on_closed_at_not_updated_at(db) -> None:
    """The fixtures' `updated_at` is set to their creation time, days before
    the close. Anything windowing on `updated_at` still finds them here, so
    the sharper assertion is a row closed *inside* the window whose
    `updated_at` sits *outside* it."""
    await _case(
        db,
        tenant=TENANT,
        number=f"PAR-{TENANT.hex[:6]}-3",
        opened_minutes_ago=30,
        duration_minutes=10,
    )
    await db.execute(
        text("UPDATE aisoc_cases SET updated_at = now() - interval '400 days' WHERE case_number = :n"),
        {"n": f"PAR-{TENANT.hex[:6]}-3"},
    )
    await db.commit()

    week_ago = datetime.now(UTC) - timedelta(days=7)
    assert await tenant_cases_closed(db, TENANT, week_ago) == 3


@pytest.mark.asyncio
async def test_a_case_marked_closed_without_a_closed_at_is_not_counted(db) -> None:
    """`closed_at` is the fact; `status` is a label that has had several
    spellings. A row with the label and no timestamp has no duration, so
    counting it would put a case with no measurable resolution time into the
    denominator of the mean."""
    await _case(
        db,
        tenant=TENANT,
        number=f"PAR-{TENANT.hex[:6]}-4",
        opened_minutes_ago=100,
        duration_minutes=0,
        closed=False,
    )
    await db.commit()

    week_ago = datetime.now(UTC) - timedelta(days=7)
    assert await tenant_cases_closed(db, TENANT, week_ago) == 2


@pytest.mark.asyncio
async def test_mttr_is_the_mean_of_the_known_durations(db) -> None:
    assert await tenant_case_mttr_minutes(db, TENANT) == 90.0


@pytest.mark.asyncio
async def test_mttr_is_none_when_the_tenant_closed_nothing(db) -> None:
    """Null and 0.0 are opposite claims — "no data" and "instant resolution".
    The console renders the first as "not measured"; publishing the second put
    a tenant that had done nothing at the top of the league table."""
    assert await tenant_case_mttr_minutes(db, TENANT_IDLE) is None


@pytest.mark.asyncio
async def test_a_case_closed_before_it_was_created_is_excluded(db) -> None:
    """Back-filled timestamps out of order would otherwise pull the mean
    below zero and make the tile read as a negative duration."""
    await _case(
        db,
        tenant=TENANT,
        number=f"PAR-{TENANT.hex[:6]}-5",
        opened_minutes_ago=200,
        duration_minutes=-500,
    )
    await db.commit()

    assert await tenant_case_mttr_minutes(db, TENANT) == 90.0


@pytest.mark.asyncio
async def test_the_dashboard_and_the_portfolio_agree_on_the_same_rows(db) -> None:
    """The assertion the defect was actually about.

    Not "each equals 90.0" — that would let both drift together — but that the
    figure the SOC dashboard computes and the figure the portfolio computes
    are the same number for one tenant's rows.
    """
    dashboard_minutes = await tenant_case_mttr_minutes(db, TENANT)

    scope = PortfolioScope(org_id=ORG, tenant_ids=frozenset(_ALL_TENANTS), portfolio_wide=True)
    rollups = await tenant_rollups(db, scope)
    by_tenant = {r.tenant_id: r for r in rollups}

    assert by_tenant[TENANT].mttr_minutes == dashboard_minutes
    # And the idle tenant is absent from both, rather than zero in either.
    assert by_tenant[TENANT_IDLE].mttr_minutes is None
    assert await tenant_case_mttr_minutes(db, TENANT_IDLE) is None


@pytest.mark.asyncio
async def test_a_case_that_never_reached_the_closed_label_still_counts(db) -> None:
    """`closed_at` is the fact and `status` is a label, so a row carrying the
    timestamp counts whatever the label says.

    The pre-change dashboard filtered `status = 'resolved'` and missed every
    completed case; filtering `status = 'closed'` instead would miss this one.
    Neither query may read the label at all, and the way to assert that is a
    row whose label is wrong and whose timestamp is right.
    """
    await _case(
        db,
        tenant=TENANT,
        number=f"PAR-{TENANT.hex[:6]}-6",
        opened_minutes_ago=300,
        duration_minutes=90,
        status="resolved",
    )
    await db.commit()

    week_ago = datetime.now(UTC) - timedelta(days=7)
    assert await tenant_cases_closed(db, TENANT, week_ago) == 3
    # 60, 120 and 90 — the mean is unchanged, so the row was counted rather
    # than skipped into a coincidentally equal figure.
    assert await tenant_case_mttr_minutes(db, TENANT) == 90.0


class _EmptyResult:
    """What `db.execute` hands back when the statement is never run."""

    def mappings(self):
        return []


class _RecordingSession:
    """Records the statement and the bound parameters instead of executing.

    Enough of the `AsyncSession` surface for both MTTR queries to be *built*,
    which is the part under test. No database is involved, so this runs
    wherever the suite does rather than only where Postgres does.
    """

    def __init__(self) -> None:
        self.statements: list[str] = []
        self.parameters: list[dict] = []

    def _record(self, statement, params):
        self.statements.append(str(statement))
        self.parameters.append(dict(params or {}))

    async def scalar(self, statement, params=None):
        self._record(statement, params)
        return None

    async def execute(self, statement, params=None):
        self._record(statement, params)
        return _EmptyResult()


async def _sql_and_parameters(build) -> tuple[str, dict]:
    session = _RecordingSession()
    await build(session)
    assert session.statements, "the surface under test issued no statement at all"
    mttr = [(sql, params) for sql, params in zip(session.statements, session.parameters, strict=True) if "closed_at" in sql]
    assert mttr, "no statement this surface sent mentions the column MTTR is computed from"
    return mttr[0]


async def _dashboard_mttr_query() -> tuple[str, dict]:
    return await _sql_and_parameters(lambda session: tenant_case_mttr_minutes(session, TENANT))


async def _portfolio_mttr_query() -> tuple[str, dict]:
    scope = PortfolioScope(org_id=ORG, tenant_ids=frozenset(_ALL_TENANTS), portfolio_wide=True)
    return await _sql_and_parameters(lambda session: tenant_rollups(session, scope))


@pytest.mark.asyncio
async def test_both_surfaces_send_the_shared_expression_and_predicate() -> None:
    """The two queries must be built from one definition, asserted on the SQL
    they send rather than on the text of the function that builds it.

    This replaces an assertion that the literal string ``"{MTTR_MINUTES_EXPR}"``
    appeared in ``inspect.getsource(tenant_rollups)`` — the un-interpolated
    f-string placeholder. That was backwards in both directions: renaming the
    local, switching to ``.format()`` or lifting the query into a constant
    would all have failed it without changing a single byte of SQL, while an
    expression that had become wrong would still have contained the
    placeholder and passed.

    The portfolio computes MTTR inside one bound cross-tenant statement on
    purpose — one round trip for the whole portfolio — so it interpolates the
    shared fragments rather than calling the shared function. What has to
    remain true is that the fragments reaching the database are the shared
    ones, and that is what the rendered statement says.
    """
    dashboard_sql, _ = await _dashboard_mttr_query()
    portfolio_sql, _ = await _portfolio_mttr_query()

    for surface, sql in (("dashboard", dashboard_sql), ("portfolio", portfolio_sql)):
        assert MTTR_MINUTES_EXPR in sql, f"the {surface} MTTR query no longer contains the shared expression"
        assert CLOSED_CASE_PREDICATE in sql, f"the {surface} MTTR query no longer contains the shared predicate"

    # And the shared fragments are still about the column that carries the
    # fact rather than the label that has had several spellings. Asserted
    # here rather than against the constants alone because what matters is
    # what the database is asked, and `test_a_case_that_never_reached_the_
    # closed_label_still_counts` above proves the same property against rows.
    assert "closed_at" in CLOSED_CASE_PREDICATE and "status" not in CLOSED_CASE_PREDICATE
    assert "closed_at" in MTTR_MINUTES_EXPR


@pytest.mark.asyncio
async def test_both_surfaces_bind_the_same_window() -> None:
    """One definition of the expression is not enough if the two ask about
    different spans of time.

    Nothing asserted this before. The dashboard binds ``since`` and the
    portfolio binds ``mttr_since``, computed in two different modules, and a
    window that drifted in one of them would leave both figures individually
    defensible and the pair inconsistent — which is the exact symptom that
    started this file.
    """
    before = datetime.now(UTC)
    _, dashboard_parameters = await _dashboard_mttr_query()
    _, portfolio_parameters = await _portfolio_mttr_query()
    after = datetime.now(UTC)

    dashboard_since = dashboard_parameters["since"]
    portfolio_since = portfolio_parameters["mttr_since"]

    # Both are `now - MTTR_WINDOW`, evaluated microseconds apart, so they are
    # compared against the interval this test itself spans rather than for
    # exact equality.
    assert abs(dashboard_since - portfolio_since) <= (after - before)
    for name, since in (("dashboard", dashboard_since), ("portfolio", portfolio_since)):
        assert before - MTTR_WINDOW <= since <= after - MTTR_WINDOW, f"{name} does not window on MTTR_WINDOW"
