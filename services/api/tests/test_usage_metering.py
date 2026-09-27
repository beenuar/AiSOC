"""Metering has to equal the rows it claims to summarise.

Gap-closure Phase 13.3 gate, and the acceptance is literal: insert a known
number of rows, ask the meter, compare.

Why the comparison is against rows and not against a fixture
-------------------------------------------------------------
Two console figures in this repository's history were wrong on real data
while passing their tests, because each test compared a producer against a
copy of itself. `cases_closed_7d` filtered an intermediate status;
`mttr_hours` averaged a column ordinary case work never writes and published
emptiness as a confident `0.0`. Both would have survived any test that
asserted the function returned what the function computed.

So every assertion below counts rows independently of the meter, in the test,
and compares. The meter and the check are different queries over the same
table, which is the only arrangement where a disagreement can show up.

The second property, and the one a naive implementation gets wrong: a daily
series summed over a range must equal one query over the whole range. Day
boundaries are where a row gets dropped or counted twice, and neither shows
up in a single-day test.
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
import pytest_asyncio
from app.api.v1.endpoints.usage import get_usage
from app.db.database import Base
from app.models.alert import Alert
from app.models.connector import Connector
from app.models.investigation import InvestigationRun
from app.models.tenant import Tenant, User
from app.services import usage_metering
from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.ext.compiler import compiles

TENANT = uuid.UUID("cccccccc-0000-0000-0000-0000000000c1")
OTHER_TENANT = uuid.UUID("dddddddd-0000-0000-0000-0000000000d1")


class _Caller:
    """The authenticated principal, as the route reads it."""

    def __init__(self, tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id


#: A fixed window, so the assertions do not depend on when the suite runs.
DAY_ONE = date(2026, 3, 10)


@compiles(JSONB, "sqlite")
def _jsonb_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(PgUUID, "sqlite")
def _uuid_sqlite(_type_, _compiler_, **_kw_):
    return "CHAR(36)"


@compiles(INET, "sqlite")
def _inet_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@compiles(ARRAY, "sqlite")
def _array_sqlite(_type_, _compiler_, **_kw_):
    return "TEXT"


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[Alert.__table__, User.__table__, Connector.__table__, InvestigationRun.__table__, Tenant.__table__],
        )
        # The two metered tables with no ORM model in this service. Created
        # by hand with the columns the meters read, so the real SQL runs.
        await conn.execute(
            text(
                "CREATE TABLE aisoc_run_costs (run_id TEXT, tenant_id TEXT, model TEXT, "
                "total_prompt_tokens INTEGER DEFAULT 0, total_completion_tokens INTEGER DEFAULT 0, "
                "total_cost_usd REAL DEFAULT 0, total_latency_ms REAL DEFAULT 0, call_count INTEGER DEFAULT 0, "
                "recorded_at TIMESTAMP)"
            )
        )
        await conn.execute(
            text(
                "CREATE TABLE aisoc_action_records (id TEXT PRIMARY KEY, tenant_id TEXT, status TEXT, "
                "record TEXT, created_at TIMESTAMP, updated_at TIMESTAMP)"
            )
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _at(day: date, hour: int = 12) -> datetime:
    return datetime(day.year, day.month, day.day, hour, tzinfo=UTC)


async def _alert(db, *, tenant: uuid.UUID, when: datetime, ai: bool) -> None:
    db.add(
        Alert(
            tenant_id=tenant,
            title="t",
            description="d",
            severity="medium",
            status="new",
            created_at=when,
            event_time=when,
            first_seen=when,
            last_seen=when,
            ai_summary="model said so" if ai else None,
            ai_score=0.5 if ai else None,
        )
    )


@pytest_asyncio.fixture
async def seeded(session_factory):
    """A known, hand-countable corpus spanning three days and two tenants.

    Deliberately includes rows at both edges of a day and rows belonging to
    another tenant, because those are the two ways a meter over-counts.
    """
    async with session_factory() as db:
        # Day one: 3 alerts, 2 of them model-triaged.
        await _alert(db, tenant=TENANT, when=_at(DAY_ONE, 0), ai=True)  # exactly midnight
        await _alert(db, tenant=TENANT, when=_at(DAY_ONE, 13), ai=True)
        await _alert(db, tenant=TENANT, when=_at(DAY_ONE, 23), ai=False)
        # Day two: 2 alerts, neither model-triaged.
        await _alert(db, tenant=TENANT, when=_at(DAY_ONE + timedelta(days=1), 9), ai=False)
        await _alert(db, tenant=TENANT, when=_at(DAY_ONE + timedelta(days=1), 10), ai=False)
        # Day three: 1 alert, model-triaged.
        await _alert(db, tenant=TENANT, when=_at(DAY_ONE + timedelta(days=2), 1), ai=True)
        # Another tenant's rows, inside the same window. Must never be counted.
        for hour in (2, 3, 4, 5):
            await _alert(db, tenant=OTHER_TENANT, when=_at(DAY_ONE, hour), ai=True)

        db.add(
            InvestigationRun(tenant_id=TENANT, case_id="c1", status="completed", created_at=_at(DAY_ONE, 14), started_at=_at(DAY_ONE, 14))
        )
        db.add(
            InvestigationRun(
                tenant_id=OTHER_TENANT, case_id="c2", status="completed", created_at=_at(DAY_ONE, 15), started_at=_at(DAY_ONE, 15)
            )
        )

        for index, (tenant, tokens, cost, when) in enumerate(
            [
                (TENANT, 1200, 0.013, _at(DAY_ONE, 14)),
                (TENANT, 800, 0.007, _at(DAY_ONE + timedelta(days=1), 8)),
                (OTHER_TENANT, 99999, 9.99, _at(DAY_ONE, 14)),
            ]
        ):
            await db.execute(
                text(
                    "INSERT INTO aisoc_run_costs (run_id, tenant_id, model, total_prompt_tokens, "
                    "total_completion_tokens, total_cost_usd, recorded_at) "
                    "VALUES (:r, :t, 'm', :p, :c, :usd, :w)"
                ),
                {"r": f"run-{index}", "t": str(tenant), "p": tokens // 2, "c": tokens - tokens // 2, "usd": cost, "w": when},
            )

        for index, (tenant, status_value, when) in enumerate(
            [
                (TENANT, "executed", _at(DAY_ONE, 16)),
                (TENANT, "pending_approval", _at(DAY_ONE, 17)),
                (TENANT, "executed", _at(DAY_ONE + timedelta(days=2), 3)),
                (OTHER_TENANT, "executed", _at(DAY_ONE, 16)),
            ]
        ):
            await db.execute(
                text("INSERT INTO aisoc_action_records (id, tenant_id, status, record, created_at) VALUES (:i, :t, :s, '{}', :w)"),
                {"i": f"act-{index}", "t": str(tenant), "s": status_value, "w": when},
            )

        db.add(User(tenant_id=TENANT, email="a@example.com", username="a", hashed_password="!x", is_active=True))
        db.add(User(tenant_id=TENANT, email="b@example.com", username="b", hashed_password="!x", is_active=False))
        db.add(User(tenant_id=OTHER_TENANT, email="c@example.com", username="c", hashed_password="!x", is_active=True))
        await db.commit()
    return session_factory


class TestMetersEqualRowCounts:
    """Every assertion counts rows in the test, then compares."""

    async def test_alerts_match_the_row_count_for_that_day(self, seeded):
        async with seeded() as db:
            for offset, _ in enumerate([0, 1, 2]):
                day = DAY_ONE + timedelta(days=offset)
                start, end = (
                    datetime(day.year, day.month, day.day, tzinfo=UTC),
                    datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(days=1),
                )
                expected = await db.scalar(
                    select(func.count())
                    .select_from(Alert)
                    .where(Alert.tenant_id == TENANT, Alert.created_at >= start, Alert.created_at < end)
                )
                measured = await usage_metering.measure_day(db, TENANT, day)
                assert measured.values["alerts"] == expected, f"day {day} disagreed"

    async def test_triage_paths_partition_the_alerts_exactly(self, seeded):
        """Model plus deterministic must equal the total.

        A gap between them is a triage nobody is accounting for, and an
        overlap is one being counted twice.
        """
        async with seeded() as db:
            for offset in range(3):
                values = (await usage_metering.measure_day(db, TENANT, DAY_ONE + timedelta(days=offset))).values
                assert values["triages_model"] + values["triages_deterministic"] == values["alerts"]

    async def test_another_tenants_rows_are_never_counted(self, seeded):
        """The four rows seeded for the other tenant sit inside the window."""
        async with seeded() as db:
            days = await usage_metering.measure_range(db, TENANT, DAY_ONE, DAY_ONE + timedelta(days=2))
            summed = usage_metering.totals(days)

            everything = await db.scalar(select(func.count()).select_from(Alert))
            ours = await db.scalar(select(func.count()).select_from(Alert).where(Alert.tenant_id == TENANT))
            assert everything > ours, "the fixture no longer has another tenant's rows, so this proves nothing"
            assert summed["alerts"] == ours

    async def test_tokens_and_cost_sum_the_rows(self, seeded):
        async with seeded() as db:
            summed = usage_metering.totals(await usage_metering.measure_range(db, TENANT, DAY_ONE, DAY_ONE + timedelta(days=2)))
            expected_tokens = await db.scalar(
                text("SELECT SUM(total_prompt_tokens + total_completion_tokens) FROM aisoc_run_costs WHERE tenant_id = :t"),
                {"t": str(TENANT)},
            )
            expected_cost = await db.scalar(
                text("SELECT SUM(total_cost_usd) FROM aisoc_run_costs WHERE tenant_id = :t"), {"t": str(TENANT)}
            )
            assert summed["llm_tokens"] == expected_tokens
            assert summed["llm_cost_usd"] == pytest.approx(expected_cost)

    async def test_actions_split_executed_from_the_rest(self, seeded):
        async with seeded() as db:
            summed = usage_metering.totals(await usage_metering.measure_range(db, TENANT, DAY_ONE, DAY_ONE + timedelta(days=2)))
            total = await db.scalar(text("SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :t"), {"t": str(TENANT)})
            executed = await db.scalar(
                text("SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :t AND status = 'executed'"),
                {"t": str(TENANT)},
            )
            assert summed["actions"] == total
            assert summed["actions_executed"] == executed
            assert summed["actions_executed"] < summed["actions"], "the fixture no longer distinguishes the two"

    async def test_seats_count_active_users_only(self, seeded):
        async with seeded() as db:
            point = await usage_metering.measure_point_in_time(db, TENANT)
            expected = await db.scalar(select(func.count()).select_from(User).where(User.tenant_id == TENANT, User.is_active.is_(True)))
            assert point["seats"] == expected
            assert point["seats"] == 1, "one of the two seeded users is inactive"


class TestDayBoundariesDoNotDropOrDoubleCount:
    async def test_the_daily_series_sums_to_one_query_over_the_whole_range(self, seeded):
        """The reconciliation the acceptance names, run against real rows."""
        async with seeded() as db:
            report = await usage_metering.reconcile(db, TENANT, DAY_ONE, DAY_ONE + timedelta(days=2))
        disagreements = {key: entry for key, entry in report.items() if not entry["agrees"]}
        assert not disagreements, f"per-day and whole-window totals disagree: {disagreements}"

    async def test_a_row_at_exactly_midnight_is_counted_once(self, seeded):
        """The fixture puts an alert at 00:00 on day one.

        A closed interval counts it in both the preceding and the following
        day, which is invisible in any single-day assertion.
        """
        async with seeded() as db:
            before = (await usage_metering.measure_day(db, TENANT, DAY_ONE - timedelta(days=1))).values["alerts"]
            on_day = (await usage_metering.measure_day(db, TENANT, DAY_ONE)).values["alerts"]
            assert before == 0
            assert on_day == 3

    async def test_an_empty_day_reports_zero_rather_than_being_absent(self, seeded):
        """A missing day reads as a gap in a chart; zero reads as a fact."""
        async with seeded() as db:
            days = await usage_metering.measure_range(db, TENANT, DAY_ONE - timedelta(days=2), DAY_ONE)
        assert [d.day for d in days] == [DAY_ONE - timedelta(days=2), DAY_ONE - timedelta(days=1), DAY_ONE]
        assert days[0].values["alerts"] == 0


class TestHonesty:
    def test_an_unmeasurable_meter_is_named_with_a_reason_not_reported_as_zero(self):
        """Zero is a measurement.

        A reader seeing `events_ingested: 0` concludes no events arrived,
        rather than that nothing looked.
        """
        assert "events_ingested" in usage_metering.UNMEASURED
        assert usage_metering.UNMEASURED["events_ingested"]
        assert "events_ingested" not in usage_metering.METERS_BY_KEY

    def test_no_meter_carries_pricing(self):
        """13.3 says metering, not billing.

        `llm_cost_usd` is what a provider charged, which is a measurement.
        Anything named for a rate, a plan or a price is a commercial decision
        and does not belong in the code that answers what happened.
        """
        forbidden = ("price", "rate", "invoice", "bill", "tier_cost", "unit_cost", "plan_cost")
        for meter in (*usage_metering.METERS, *usage_metering.POINT_IN_TIME_METERS):
            haystack = f"{meter.key} {meter.label} {meter.sql}".lower()
            for token in forbidden:
                assert token not in haystack, f"{meter.key} looks like pricing logic"

    def test_every_meter_binds_the_tenant_as_a_parameter(self):
        """Never formatted into the string.

        The same rule the entitlement limits follow, and the reason the lake
        rewriter was made to fail closed.
        """
        for meter in (*usage_metering.METERS, *usage_metering.POINT_IN_TIME_METERS):
            assert ":tenant_id" in meter.sql or ":tenant_text" in meter.sql, meter.key
            assert "format(" not in meter.sql
            assert "%s" not in meter.sql


class TestCsvExport:
    async def test_the_csv_carries_totals_that_match_the_rows(self, seeded):
        async with seeded() as db:
            days = await usage_metering.measure_range(db, TENANT, DAY_ONE, DAY_ONE + timedelta(days=2))
            point = await usage_metering.measure_point_in_time(db, TENANT)
            expected = await db.scalar(select(func.count()).select_from(Alert).where(Alert.tenant_id == TENANT))

        body = usage_metering.to_csv(tenant_id=TENANT, org_name="Acme MSSP", days=days, point_in_time=point)
        lines = [line for line in body.splitlines() if line]
        total_row = next(line for line in lines if line.startswith("total,"))
        assert int(total_row.split(",")[1]) == expected

    async def test_the_csv_names_what_was_not_measured(self, seeded):
        async with seeded() as db:
            days = await usage_metering.measure_range(db, TENANT, DAY_ONE, DAY_ONE)
            point = await usage_metering.measure_point_in_time(db, TENANT)
        body = usage_metering.to_csv(tenant_id=TENANT, org_name=None, days=days, point_in_time=point)
        assert "not measured: events_ingested" in body
        # And it says whose numbers these are. A bare grid of figures in a
        # downloads folder cannot answer that.
        assert str(TENANT) in body

    def test_month_bounds_cover_the_whole_month_including_february(self):
        assert usage_metering.month_bounds(2026, 2) == (date(2026, 2, 1), date(2026, 2, 28))
        assert usage_metering.month_bounds(2024, 2) == (date(2024, 2, 1), date(2024, 2, 29))
        assert usage_metering.month_bounds(2026, 12) == (date(2026, 12, 1), date(2026, 12, 31))
        with pytest.raises(ValueError, match="1-12"):
            usage_metering.month_bounds(2026, 13)


class TestTheRouteAnswers:
    """The route itself, not just the service functions underneath it.

    Every test above this class passed while `GET /usage` raised `TypeError`
    on every request, because the handler called `headroom_for_tenant` without
    its `tenant_limits` argument and nothing here had ever called the handler.
    A service-layer suite cannot see that; only calling the route can.
    """

    async def test_entitlements_reflect_the_tenant_override_not_the_plan_default(self, seeded):
        """Asserts the override is *honoured*, not merely that the call returns.

        Passing `None` for `tenant_limits` would satisfy the signature and stop
        the crash while silently reporting plan headroom to a tenant whose
        ceiling was deliberately raised, so the assertion is on the number.
        """
        raised_ceiling = 4242
        async with seeded() as db:
            db.add(Tenant(id=TENANT, name="t", slug="t", limits={"seats": raised_ceiling}))
            await db.commit()

        async with seeded() as db:
            body = await get_usage(db, _Caller(TENANT))

        seats = next(row for row in body["entitlements"] if row["key"] == "seats")
        assert seats["limit"] == raised_ceiling
