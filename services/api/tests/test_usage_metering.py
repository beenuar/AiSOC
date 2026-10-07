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

Counting the evidence is not the same as counting the right evidence
--------------------------------------------------------------------
Both properties above held while `triages_model` counted something else
entirely. It read `alerts.ai_summary IS NOT NULL OR ai_score IS NOT NULL`,
and the *deterministic* triage path writes both of those columns — so on a
deployment with no model configured at all, every alert was reported as an
AI triage. The meter equalled the rows it summarised, exactly as this file
asserted; the rows just did not mean what the meter said they meant.

`TestThePathMetersReadTheRecordedPath` is the guard against that returning:
the discriminator is the path auto-triage recorded for itself, and
`TestTheProducerStillWritesWhatTheseMetersRead` pins the shape against the
producer so the fixtures here cannot quietly stop resembling production.
"""

from __future__ import annotations

import ast
import pathlib
import re
import uuid
from datetime import UTC, date, datetime, timedelta
from typing import Final

import pytest
import pytest_asyncio
from app.api.v1.endpoints.usage import get_usage
from app.db.database import Base
from app.models.alert import Alert
from app.models.connector import Connector
from app.models.investigation import InvestigationRun
from app.models.tenant import Tenant, User
from app.services import usage_metering
from app.services.entitlements import headroom_for_tenant, measure_usage
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
                "approval_tier TEXT, record TEXT, created_at TIMESTAMP, updated_at TIMESTAMP)"
            )
        )
    yield async_sessionmaker(engine, expire_on_commit=False)
    await engine.dispose()


def _at(day: date, hour: int = 12) -> datetime:
    return datetime(day.year, day.month, day.day, hour, tzinfo=UTC)


#: The quota window is the calendar month, so anything asserting against
#: `entitlements` has to be seeded inside the current one. Rows at the fixed
#: `DAY_ONE` fall outside it, and a quota test seeded there passes on a
#: broken tree because nothing is in range to miscount.
_MONTH_START: Final = datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _this_month(hour: int) -> datetime:
    return _MONTH_START + timedelta(hours=hour)


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
            ai_summary="a verdict was written here" if ai else None,
            ai_score=0.5 if ai else None,
        )
    )


#: What `persist_auto_triage` stamps into `model_used` on each path. Written
#: out here rather than imported: `services/agents` is a different service
#: with its own top-level `app` package, so importing it would shadow this
#: one. `TestTheProducerStillWritesWhatTheseMetersRead` is what keeps these
#: two literals honest.
DETERMINISTIC_RUN = "kafka:auto_triage:deterministic"
MODEL_RUN = "kafka:auto_triage:llm"


def _run(db, *, tenant: uuid.UUID, when: datetime, case: str, model_used: str | None) -> None:
    db.add(
        InvestigationRun(
            tenant_id=tenant,
            case_id=case,
            status="completed",
            created_at=when,
            started_at=when,
            model_used=model_used,
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

        # Seven runs for this tenant across the three days, in the three
        # shapes `investigation_runs` actually holds: auto-triage that
        # reached a model, auto-triage that did not, and an analyst-driven
        # investigation. All three counts differ, so a meter that collapsed
        # any two of them cannot pass by coincidence.
        _run(db, tenant=TENANT, when=_at(DAY_ONE, 0), case="a1", model_used=DETERMINISTIC_RUN)
        _run(db, tenant=TENANT, when=_at(DAY_ONE, 13), case="a2", model_used=MODEL_RUN)
        _run(db, tenant=TENANT, when=_at(DAY_ONE, 14), case="c1", model_used="aisoc-investigator-v1")
        _run(db, tenant=TENANT, when=_at(DAY_ONE + timedelta(days=1), 9), case="a3", model_used=DETERMINISTIC_RUN)
        _run(db, tenant=TENANT, when=_at(DAY_ONE + timedelta(days=1), 10), case="a4", model_used=DETERMINISTIC_RUN)
        _run(db, tenant=TENANT, when=_at(DAY_ONE + timedelta(days=2), 1), case="a5", model_used=MODEL_RUN)
        # `start_run` leaves `model_used` null when the caller names no
        # model, and `replay_redaction` already reads that as deterministic.
        # It is still an investigation, so it belongs in that meter.
        _run(db, tenant=TENANT, when=_at(DAY_ONE + timedelta(days=2), 2), case="c2", model_used=None)
        _run(db, tenant=OTHER_TENANT, when=_at(DAY_ONE, 15), case="c3", model_used=MODEL_RUN)

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

        # Statuses are `ActionStatus` members and tiers are
        # `ApprovalRequirement` members, because the fixture that preceded
        # this one invented `executed` and `pending_approval` — neither of
        # which any action can hold — and so agreed with a meter that could
        # only ever return zero. `TestTheActionMetersFilterOnStatusesThat
        # Exist` is what stops that drifting back.
        for index, (tenant, status_value, tier, when) in enumerate(
            [
                (TENANT, "completed", "automatic", _at(DAY_ONE, 16)),
                (TENANT, "awaiting_approval", "analyst", _at(DAY_ONE, 17)),
                # Written before the tier was recorded.
                (TENANT, "completed", None, _at(DAY_ONE + timedelta(days=2), 3)),
                (OTHER_TENANT, "completed", "automatic", _at(DAY_ONE, 16)),
            ]
        ):
            await db.execute(
                text(
                    "INSERT INTO aisoc_action_records (id, tenant_id, status, approval_tier, record, created_at) "
                    "VALUES (:i, :t, :s, :tier, '{}', :w)"
                ),
                {"i": f"act-{index}", "t": str(tenant), "s": status_value, "tier": tier, "w": when},
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

    async def test_the_run_meters_partition_the_runs_exactly(self, seeded):
        """Model, deterministic and investigations must equal every run.

        A gap between them is work nobody is accounting for, and an overlap
        is work counted twice. It is the runs they partition, not the
        alerts: an alert can be re-triaged, and an alert that arrived
        before auto-triage was switched on has no run at all.
        """
        async with seeded() as db:
            for offset in range(3):
                day = DAY_ONE + timedelta(days=offset)
                start, end = (
                    datetime(day.year, day.month, day.day, tzinfo=UTC),
                    datetime(day.year, day.month, day.day, tzinfo=UTC) + timedelta(days=1),
                )
                runs = await db.scalar(
                    select(func.count())
                    .select_from(InvestigationRun)
                    .where(
                        InvestigationRun.tenant_id == TENANT,
                        InvestigationRun.created_at >= start,
                        InvestigationRun.created_at < end,
                    )
                )
                values = (await usage_metering.measure_day(db, TENANT, day)).values
                assert values["triages_model"] + values["triages_deterministic"] + values["investigations"] == runs, f"day {day} disagreed"

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
            # `TestTheActionMetersFilterOnStatusesThatExist` is what makes
            # this constant safe to reuse here: it checks the status against
            # the enum `services/actions` actually defines, so the test and
            # the meter are not agreeing on a value neither can produce.
            executed = await db.scalar(
                text("SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :t AND status = :s"),
                {"t": str(TENANT), "s": usage_metering.EXECUTED_STATUS},
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


class TestThePathMetersReadTheRecordedPath:
    """The alert columns do not say which path answered. The run does.

    `complete_run` and `persist_auto_triage` write `ai_score` and
    `ai_summary` from one statement on both paths, so those columns record
    *that* a verdict exists, never *who* produced it.
    """

    async def test_a_deterministic_triage_is_not_counted_as_a_model_triage(self, session_factory):
        """A CORE deployment with no model configured, in miniature.

        Every alert on such a deployment carries `ai_summary` and
        `ai_score`, because the deterministic path writes them. Reading
        those columns, the meter reported 100% AI triage coverage on a
        deployment that had never placed an LLM call.
        """
        async with session_factory() as db:
            await _alert(db, tenant=TENANT, when=_at(DAY_ONE, 9), ai=True)
            _run(db, tenant=TENANT, when=_at(DAY_ONE, 9), case="alert-1", model_used=DETERMINISTIC_RUN)
            await db.commit()

        async with session_factory() as db:
            carries_ai_output = await db.scalar(
                select(func.count()).select_from(Alert).where(Alert.tenant_id == TENANT, Alert.ai_summary.is_not(None))
            )
            values = (await usage_metering.measure_day(db, TENANT, DAY_ONE)).values

        assert carries_ai_output == 1, "the fixture no longer reproduces the condition this meter was changed over"
        assert values["triages_model"] == 0, "a deterministic triage was counted as a model triage"
        assert values["triages_deterministic"] == 1

    async def test_a_model_triage_is_counted_as_one(self, session_factory):
        """The other half of the control.

        Without it, a meter hardcoded to zero would pass the test above.
        """
        async with session_factory() as db:
            await _alert(db, tenant=TENANT, when=_at(DAY_ONE, 9), ai=True)
            _run(db, tenant=TENANT, when=_at(DAY_ONE, 9), case="alert-1", model_used=MODEL_RUN)
            await db.commit()

        async with session_factory() as db:
            values = (await usage_metering.measure_day(db, TENANT, DAY_ONE)).values

        assert values["triages_model"] == 1
        assert values["triages_deterministic"] == 0

    async def test_an_auto_triage_is_not_also_counted_as_an_investigation(self, session_factory):
        """Auto-triage opens an `investigation_runs` row per alert.

        Counting those as investigations made the meter a second alert
        count wearing a different label, and on a busy tenant it buried the
        analyst-driven runs it was supposed to report.
        """
        async with session_factory() as db:
            _run(db, tenant=TENANT, when=_at(DAY_ONE, 9), case="alert-1", model_used=DETERMINISTIC_RUN)
            _run(db, tenant=TENANT, when=_at(DAY_ONE, 10), case="alert-2", model_used=MODEL_RUN)
            _run(db, tenant=TENANT, when=_at(DAY_ONE, 11), case="case-7", model_used="aisoc-investigator-v1")
            await db.commit()

        async with session_factory() as db:
            values = (await usage_metering.measure_day(db, TENANT, DAY_ONE)).values

        assert values["investigations"] == 1, "auto-triage runs were counted as investigations"


class TestTheProducerStillWritesWhatTheseMetersRead:
    """A cross-service contract pin, and only that.

    `services/agents` names its top-level package `app`, the same as this
    service, so importing its ledger here would shadow the module under
    test. The producer is therefore read rather than run, and this class
    proves one thing: that the two literals the path meters discriminate on
    are still the ones the producer writes, and that the alert columns the
    meters stopped reading are still written on both paths.

    It cannot prove the producer runs correctly. `tests/isolation/
    test_ledger_live.py` drives it against real Postgres.
    """

    LEDGER = pathlib.Path(__file__).resolve().parents[3] / "services" / "agents" / "app" / "investigator" / "ledger.py"

    def _persist_auto_triage(self) -> ast.FunctionDef | ast.AsyncFunctionDef:
        assert self.LEDGER.exists(), f"{self.LEDGER} has moved; this pin is no longer reading the producer"
        tree = ast.parse(self.LEDGER.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef) and node.name == "persist_auto_triage":
                return node
        raise AssertionError("persist_auto_triage is gone from the ledger; the path meters have no producer")

    def test_the_run_is_stamped_with_the_path_that_answered(self):
        """`model_used` carries `kafka:auto_triage:<tier>`.

        If the producer stops stamping it, both path meters silently drop
        to zero and the usage screen reports a tenant doing no triage at
        all.
        """
        node = self._persist_auto_triage()
        stamps = [
            part.value
            for template in ast.walk(node)
            if isinstance(template, ast.JoinedStr)
            for part in template.values
            if isinstance(part, ast.Constant) and isinstance(part.value, str) and "auto_triage" in part.value
        ]
        assert any(s.startswith("kafka:auto_triage:") for s in stamps), (
            f"the ledger no longer stamps `kafka:auto_triage:<tier>`; it writes {stamps!r}"
        )

    def test_the_alert_columns_are_written_on_both_paths(self):
        """Which is why the meters cannot read them.

        Two properties together: the same function writes `ai_summary` onto
        the alert, and nothing inside it branches on `tier`. A tier-
        conditional write would mean the old definition had become correct
        and these meters could go back to the cheaper query.
        """
        node = self._persist_auto_triage()
        statements = [
            const.value
            for const in ast.walk(node)
            if isinstance(const, ast.Constant) and isinstance(const.value, str) and "UPDATE alerts" in const.value
        ]
        assert statements, "persist_auto_triage no longer updates the alert row"
        assert any("ai_summary" in s and "ai_score" in s for s in statements), (
            "persist_auto_triage stopped writing ai_summary/ai_score; re-check what the alert columns now mean"
        )

        branches_on_tier = [
            branch
            for branch in ast.walk(node)
            if isinstance(branch, ast.If) and any(isinstance(n, ast.Name) and n.id == "tier" for n in ast.walk(branch.test))
        ]
        assert not branches_on_tier, (
            "persist_auto_triage now branches on `tier`; the alert columns may have become path-specific, "
            "which would change what these meters should read"
        )


class TestTheActionMetersFilterOnStatusesThatExist:
    """`actions_executed` filtered `status = 'executed'` for four releases.

    `ActionStatus` has no such member — the terminal success state is
    `completed` — so the meter could only ever return zero, and a tenant
    running response actions every day saw "0 executed" beside a non-zero
    total. Nothing caught it because zero is a legal count.

    Read from `services/actions` rather than imported, for the same reason
    as the ledger pin above: that service's top-level package is also
    called `app`.
    """

    MODEL = pathlib.Path(__file__).resolve().parents[3] / "services" / "actions" / "app" / "models" / "action.py"

    def _action_statuses(self) -> set[str]:
        assert self.MODEL.exists(), f"{self.MODEL} has moved; this pin is no longer reading the producer"
        tree = ast.parse(self.MODEL.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "ActionStatus":
                return {
                    stmt.value.value
                    for stmt in node.body
                    if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)
                }
        raise AssertionError("ActionStatus is gone; the action meters have no vocabulary to check against")

    def test_every_status_an_action_meter_names_is_one_an_action_can_hold(self):
        statuses = self._action_statuses()
        assert "completed" in statuses, "the fixture assumption is wrong; re-read ActionStatus"

        compared = {usage_metering.EXECUTED_STATUS}
        # Any status still written into the SQL rather than bound, which is
        # how the original `status = 'executed'` escaped review.
        for meter in usage_metering.METERS:
            if meter.source == "aisoc_action_records":
                compared.update(re.findall(r"status\s*(?:=|<>|IN)\s*\(?\s*'([^']*)'", meter.sql))

        unknown = compared - statuses
        assert not unknown, f"action meters filter on {sorted(unknown)}, which no ActionStatus member can ever hold"


class TestTheActionMetersSplitByApprovalTier:
    """One lump of "response actions" answers nobody's question.

    The operator question is how much ran without a human, and the
    commercial one is how much analyst time the platform asked for. Both
    need the tier the submission was graded at.
    """

    async def test_automatic_and_human_gated_are_counted_apart(self, seeded):
        async with seeded() as db:
            summed = usage_metering.totals(await usage_metering.measure_range(db, TENANT, DAY_ONE, DAY_ONE + timedelta(days=2)))
        assert summed["actions_automatic"] == 1
        assert summed["actions_human_gated"] == 1

    async def test_a_row_with_no_recorded_tier_is_named_rather_than_assumed(self, seeded):
        """Rows written before the tier was recorded still exist.

        Folding them into `automatic` would report actions as unsupervised
        that nobody graded, and folding them into `human_gated` would
        invent analyst work. They are counted as what they are, and the
        three sum to the total so none goes missing.
        """
        async with seeded() as db:
            summed = usage_metering.totals(await usage_metering.measure_range(db, TENANT, DAY_ONE, DAY_ONE + timedelta(days=2)))
        assert summed["actions_tier_unrecorded"] == 1
        assert summed["actions_automatic"] + summed["actions_human_gated"] + summed["actions_tier_unrecorded"] == summed["actions"]


class _LakeRows:
    """The shape `execute_lake_query` returns, narrowed to what is read."""

    def __init__(self, rows: list[list[object]]) -> None:
        self.rows = rows


class TestEventsIngestedIsMeasuredWhereTheLakeExists:
    """The doc said this meter reads "not measured" on a deployment
    *without* the lake, which told an operator it was measured on one with
    it. No code path counted lake rows on any profile.
    """

    async def test_the_meter_is_measured_when_the_lake_answers(self, monkeypatch):
        counted: dict[str, object] = {}

        async def _fake_lake(sql, *, params=None, **_kw):
            counted["sql"] = sql
            counted["params"] = params
            return _LakeRows([[date(2026, 3, 10), 41], [date(2026, 3, 12), 1]])

        monkeypatch.setattr(usage_metering, "execute_lake_query", _fake_lake)
        monkeypatch.setattr(usage_metering, "lake_is_configured", lambda: True)

        series = await usage_metering.measure_events_ingested(TENANT, DAY_ONE, DAY_ONE + timedelta(days=2))

        assert series == {DAY_ONE: 41, DAY_ONE + timedelta(days=1): 0, DAY_ONE + timedelta(days=2): 1}
        assert counted["params"]["tenant_id"] == str(TENANT), "the tenant was not bound as a query parameter"

    async def test_an_absent_lake_is_not_measured_rather_than_zero(self, monkeypatch):
        monkeypatch.setattr(usage_metering, "lake_is_configured", lambda: False)
        assert await usage_metering.measure_events_ingested(TENANT, DAY_ONE, DAY_ONE) is None


class TestTheQuotaAndTheUsageScreenCountTheSameThing:
    """`entitlements.triages_per_month` is the cap `triages_model` reports
    headroom against. Two definitions of "a triage" is how a usage screen
    and a quota screen end up disagreeing in front of a customer, and the
    quota is the half with teeth: alerts keep arriving and simply stop
    being triaged.

    Both read the same column today. This is what keeps them there.
    """

    async def test_the_quota_counts_model_runs_and_not_alerts_carrying_ai_output(self, session_factory):
        """Reproduces the expensive direction.

        A deterministic-only deployment burned its AI-triage quota on
        triages no model performed, and the symptom is silence: alerts
        keep arriving and stop being triaged.

        The quota window is the calendar month, so the rows are seeded in
        *this* month rather than at `DAY_ONE`. Seeded outside it they fall
        out of the count for a reason that has nothing to do with the
        defect, and the test passes on the broken tree.
        """
        async with session_factory() as db:
            for hour in range(5):
                await _alert(db, tenant=TENANT, when=_this_month(hour), ai=True)
                _run(db, tenant=TENANT, when=_this_month(hour), case=f"a{hour}", model_used=DETERMINISTIC_RUN)
            db.add(Tenant(id=TENANT, name="t", slug="t", limits={"triages_per_month": 10}))
            await db.commit()

        async with session_factory() as db:
            carries_ai_output = await db.scalar(
                select(func.count()).select_from(Alert).where(Alert.tenant_id == TENANT, Alert.ai_summary.is_not(None))
            )
            rows = await headroom_for_tenant(db, TENANT, {"triages_per_month": 10})

        assert carries_ai_output == 5, "the fixture no longer reproduces the condition this quota was changed over"
        triages = next(row for row in rows if row.key == "triages_per_month")
        assert triages.used == 0, "five deterministic triages were charged against the AI-triage quota"

    async def test_the_quota_and_the_meter_agree_on_the_same_rows(self, session_factory):
        """Counted through both surfaces, compared against each other.

        Neither is the authority here: they are two independent queries,
        and the assertion is that they cannot drift apart.
        """
        async with session_factory() as db:
            for index in range(3):
                _run(db, tenant=TENANT, when=_this_month(index), case=f"m{index}", model_used=MODEL_RUN)
            _run(db, tenant=TENANT, when=_this_month(5), case="d1", model_used=DETERMINISTIC_RUN)
            await db.commit()

        async with session_factory() as db:
            quota = (await measure_usage(db, TENANT))["triages_per_month"]
            metered = usage_metering.totals(await usage_metering.measure_range(db, TENANT, _MONTH_START.date(), datetime.now(UTC).date()))

        assert quota == 3
        assert metered["triages_model"] == quota


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
    def test_an_unmeasurable_meter_is_named_with_a_reason_not_reported_as_zero(self, monkeypatch):
        """Zero is a measurement.

        A reader seeing `events_ingested: 0` concludes no events arrived,
        rather than that nothing looked. The reason travels with the gap so
        they can tell which it is.
        """
        monkeypatch.setattr(usage_metering, "lake_is_configured", lambda: False)
        gaps = usage_metering.unmeasured()
        assert gaps["events_ingested"]
        assert "events_ingested" not in usage_metering.METERS_BY_KEY, "the Postgres meters cannot count a ClickHouse table"

    def test_nothing_is_reported_unmeasured_on_a_deployment_that_can_measure_it(self, monkeypatch):
        """The other half, and the reason the list became a function.

        It was a constant, so a `full`-profile deployment with a lake
        running still announced `events_ingested` as not measured — which
        is the same lie in the opposite direction.
        """
        monkeypatch.setattr(usage_metering, "lake_is_configured", lambda: True)
        assert usage_metering.unmeasured() == {}

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

    async def test_the_csv_names_what_was_not_measured(self, seeded, monkeypatch):
        """A reader must be able to tell a real zero from a gap.

        The line appears only when the lake is genuinely absent; with one
        deployed, `events_ingested` is a column like any other.
        """
        monkeypatch.setattr(usage_metering, "lake_is_configured", lambda: False)
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


class TestTheOrganisationExport:
    """A managed provider bills its own customer, not one tenant at a time.

    The per-tenant CSV carried an `# organisation` header naming the
    operator while covering exactly one tenant, which reads as a portfolio
    export and is not one. An operator with forty customers had to make
    forty requests and add up the columns themselves.
    """

    async def test_the_portfolio_csv_covers_every_managed_tenant(self, seeded):
        async with seeded() as db:
            sections = await usage_metering.measure_organization(
                db,
                tenant_ids=[TENANT, OTHER_TENANT],
                start=DAY_ONE,
                end=DAY_ONE + timedelta(days=2),
            )

        assert [section.tenant_id for section in sections] == [TENANT, OTHER_TENANT]

        async with seeded() as db:
            for section in sections:
                expected = await db.scalar(select(func.count()).select_from(Alert).where(Alert.tenant_id == section.tenant_id))
                assert section.totals["alerts"] == expected, f"{section.tenant_id} disagreed"

    async def test_the_portfolio_total_is_the_sum_of_its_tenants(self, seeded):
        """Counted independently, not read back off the same objects."""
        async with seeded() as db:
            sections = await usage_metering.measure_organization(
                db,
                tenant_ids=[TENANT, OTHER_TENANT],
                start=DAY_ONE,
                end=DAY_ONE + timedelta(days=2),
            )
            every_alert = await db.scalar(select(func.count()).select_from(Alert))

        body = usage_metering.organization_to_csv(org_name="Acme MSSP", sections=sections)
        lines = [line for line in body.splitlines() if line.startswith("portfolio total,")]
        assert len(lines) == 1, "the portfolio CSV must carry exactly one roll-up row"
        assert int(lines[0].split(",")[1]) == every_alert

    async def test_a_tenant_outside_the_portfolio_is_absent_from_the_csv(self, seeded):
        """The scope resolver is what decides the list, and nothing widens it.

        Without this, "the CSV covers the portfolio" would pass equally
        well on an export that covered every tenant on the deployment.
        """
        async with seeded() as db:
            sections = await usage_metering.measure_organization(
                db,
                tenant_ids=[TENANT],
                start=DAY_ONE,
                end=DAY_ONE + timedelta(days=2),
            )
        body = usage_metering.organization_to_csv(org_name="Acme MSSP", sections=sections)
        assert str(TENANT) in body
        assert str(OTHER_TENANT) not in body


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
