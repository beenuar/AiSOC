"""Three surfaces publishing a confident zero next to one that says "not measured".

The defects
-----------
On one deployment at one moment, with nine alerts and not one analyst
action:

* ``/metrics/funnel`` published ``signal_to_noise: 0.0`` and
  ``mttd_seconds: 0.0`` — rendered **"Signal / Noise 0%"** and **"MTTD
  0s"** — directly above a SOC Performance card correctly reading *"MTTD
  — not measured · no closures in 7d"*. Both come from the same two
  shapes this repository has already named: ``x / n if n else 0.0`` and
  ``float(None or 0.0)``. The funnel's *deltas* model is `float | None`
  with a docstring explaining that the UI renders ``None`` as "no
  baseline" rather than a misleading 0% — so the honest treatment was
  applied to the deltas and not to the values they describe.

* ``/metrics/soc`` returned ``analyst_overrides_7d: 9`` and
  ``false_positive_rate_sample_count: 5`` on a tenant where **no human
  had touched anything**. Both filtered ``disposition IS NOT NULL``,
  which the auto-triage worker writes on every alert it looks at. An
  override is a human disagreeing with the agent; counting the agent's
  own output as disagreement with itself inflates the one number that is
  supposed to measure trust. Worse, all nine dispositions were
  ``needs_review`` — an *abstention*, not a verdict — so they were also
  in the denominator of a false-positive rate they cannot inform.

* ``/dashboards/soc-insights`` rendered ``MTTA — not measured``, ``MTTR
  — not measured``, then **FP Rate 0.0%**, **Agent cost / investigation
  $0.000** and **Analyst hours saved 0h**. The card already renders
  "not measured" when ``sample_count`` is 0; those three tiles simply
  never set it.

How these tests are built
-------------------------
Every denominator is asserted against rows **this test counted itself**.
The seeded fixture mirrors the live reproduction exactly — nine alerts,
all ``needs_review``, zero SLA events, zero analyst feedback — because
the figures were wrong in a way a one-row fixture cannot show.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0c100000-0000-0000-0000-0000000000d0")


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
                f"the denominator proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _reset(session)
        try:
            yield session
        finally:
            await _reset(session)
    await engine.dispose()


async def _reset(session) -> None:
    await session.rollback()
    for table in ("alert_sla_events", "alerts"):
        await session.execute(text(f"DELETE FROM {table} WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.execute(text("DELETE FROM tenants WHERE id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.commit()


async def _seed(session, rows: Sequence[tuple[str, str, str | None]]) -> None:
    """``(status, severity, disposition)`` — the three columns every figure here reads."""
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'Denominator', 'denominator') ON CONFLICT (id) DO NOTHING"),
        {"t": str(TENANT)},
    )
    for status, severity, disposition in rows:
        await session.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, severity, status, disposition, created_at, updated_at)
                VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :ti, :s, :st, :d, NOW(), NOW())
                """
            ),
            {
                "i": str(uuid.uuid4()),
                "t": str(TENANT),
                "ti": f"{severity} alert",
                "s": severity,
                "st": status,
                "d": disposition,
            },
        )
    await session.commit()


#: The live reproduction: nine auto-triaged alerts, every one abstained on.
_LIVE_SHAPE = [("triaged", sev, "needs_review") for sev in ["critical"] * 3 + ["high"] * 4 + ["medium", "low"]]


@pytest.mark.asyncio
class TestTheFunnelSaysWhatItMeasured:
    async def test_signal_to_noise_carries_the_denominator_it_divided_by(self, db) -> None:
        """Nine abstentions are not nine verdicts. The ratio has no
        denominator, and the figure must say so rather than read 0%."""
        from app.api.v1.endpoints.metrics import _funnel_window

        await _seed(db, _LIVE_SHAPE)

        decided = await db.scalar(
            text(
                "SELECT count(*) FROM alerts WHERE tenant_id = CAST(:t AS uuid) "
                "AND disposition IN ('true_positive', 'false_positive', 'benign', 'duplicate')"
            ),
            {"t": str(TENANT)},
        )
        assert decided == 0, f"the fixture is wrong before the code is: {decided} decided verdicts"

        end = datetime.now(UTC) + timedelta(minutes=1)
        funnel = await _funnel_window(db, TENANT, end - timedelta(days=1), end, mitre_total=201)

        assert funnel["signal_to_noise_sample_count"] == 0, (
            f"the funnel claims {funnel['signal_to_noise_sample_count']} dispositioned alerts behind a "
            "signal/noise ratio computed over nine abstentions"
        )

    async def test_mttd_carries_the_count_of_rows_it_averaged(self, db) -> None:
        """Nothing in the pipeline writes `first_seen_at` — its only writers
        are analyst actions — so MTTD is structurally 0.0 until somebody
        acknowledges an alert. `/metrics/soc` ships `mttd_sample_count`
        beside its figure; the funnel shipped none."""
        from app.api.v1.endpoints.metrics import _funnel_window

        await _seed(db, _LIVE_SHAPE)

        seen = await db.scalar(
            text("SELECT count(*) FROM alerts WHERE tenant_id = CAST(:t AS uuid) AND first_seen_at IS NOT NULL"),
            {"t": str(TENANT)},
        )
        assert seen == 0

        end = datetime.now(UTC) + timedelta(minutes=1)
        funnel = await _funnel_window(db, TENANT, end - timedelta(days=1), end, mitre_total=201)

        assert funnel["mttd_sample_count"] == 0, f"MTTD claims {funnel['mttd_sample_count']} samples over zero acknowledged alerts"

    async def test_a_real_ratio_still_reports_its_denominator(self, db) -> None:
        """The positive control. A figure that reported "not measured"
        whatever happened would pass both tests above and publish nothing."""
        from app.api.v1.endpoints.metrics import _funnel_window

        await _seed(
            db,
            [
                ("resolved", "high", "true_positive"),
                ("resolved", "high", "false_positive"),
                ("resolved", "low", "benign"),
                ("resolved", "low", "benign"),
                ("triaged", "medium", "needs_review"),
            ],
        )

        decided = await db.scalar(
            text(
                "SELECT count(*) FROM alerts WHERE tenant_id = CAST(:t AS uuid) "
                "AND disposition IN ('true_positive', 'false_positive', 'benign', 'duplicate')"
            ),
            {"t": str(TENANT)},
        )
        assert decided == 4

        end = datetime.now(UTC) + timedelta(minutes=1)
        funnel = await _funnel_window(db, TENANT, end - timedelta(days=1), end, mitre_total=201)

        assert funnel["signal_to_noise_sample_count"] == 4
        assert funnel["signal_to_noise"] == 0.25, "one true positive in four decided verdicts"

    async def test_an_abstention_is_not_a_verdict(self, db) -> None:
        """`needs_review` is the agent declining to decide. Counting it in
        the denominator of a false-positive rate scores the agent on
        questions it refused to answer."""
        from app.api.v1.endpoints.metrics import _funnel_window

        await _seed(db, [("resolved", "high", "true_positive"), ("triaged", "high", "needs_review")])

        end = datetime.now(UTC) + timedelta(minutes=1)
        funnel = await _funnel_window(db, TENANT, end - timedelta(days=1), end, mitre_total=201)

        assert funnel["signal_to_noise_sample_count"] == 1
        assert funnel["signal_to_noise"] == 1.0


@pytest.mark.asyncio
class TestAnOverrideIsAHumanDisagreeing:
    async def test_the_agents_own_dispositions_are_not_analyst_overrides(self, db) -> None:
        """The reproduction: nine auto-triage dispositions, zero analyst
        actions, and the console read "Analyst Overrides (7d) 9"."""
        from app.api.v1.endpoints.metrics import _soc_disposition_counts

        await _seed(db, _LIVE_SHAPE)

        human_events = await db.scalar(
            text("SELECT count(*) FROM alert_sla_events WHERE tenant_id = CAST(:t AS uuid) AND actor_id IS NOT NULL"),
            {"t": str(TENANT)},
        )
        assert human_events == 0, "the fixture is wrong before the code is"

        counts = await _soc_disposition_counts(db, TENANT, datetime.now(UTC) - timedelta(days=7))

        assert counts["analyst_overrides"] == 0, (
            f"{counts['analyst_overrides']} analyst overrides recorded on a tenant where no human acted"
        )
        assert counts["ai_dispositions"] == 9, "the agent's own dispositions still have to be reported somewhere"

    async def test_a_real_analyst_action_is_counted(self, db) -> None:
        """The positive control, and the half that matters: a counter that
        answered zero unconditionally would pass the test above."""
        from app.api.v1.endpoints.metrics import _soc_disposition_counts

        await _seed(db, [("resolved", "high", "false_positive"), ("triaged", "low", "needs_review")])
        alert_id = await db.scalar(
            text("SELECT id FROM alerts WHERE tenant_id = CAST(:t AS uuid) AND disposition = 'false_positive'"),
            {"t": str(TENANT)},
        )
        await db.execute(
            text(
                "INSERT INTO alert_sla_events (tenant_id, alert_id, severity, event_type, actor_id) "
                "VALUES (CAST(:t AS uuid), CAST(:a AS uuid), 'high', 'resolved', CAST(:u AS uuid))"
            ),
            {"t": str(TENANT), "a": str(alert_id), "u": str(uuid.uuid4())},
        )
        await db.commit()

        counts = await _soc_disposition_counts(db, TENANT, datetime.now(UTC) - timedelta(days=7))

        assert counts["analyst_overrides"] == 1
        assert counts["ai_dispositions"] == 1

    async def test_a_backfilled_detection_event_is_not_an_analyst_action(self, db) -> None:
        """`sla_events` backfills a `detected` row with no actor when the
        first lifecycle event lands. Counting it would re-create the defect
        from the other side."""
        from app.api.v1.endpoints.metrics import _soc_disposition_counts

        await _seed(db, [("triaged", "high", "needs_review")])
        alert_id = await db.scalar(text("SELECT id FROM alerts WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
        await db.execute(
            text(
                "INSERT INTO alert_sla_events (tenant_id, alert_id, severity, event_type, actor_id) "
                "VALUES (CAST(:t AS uuid), CAST(:a AS uuid), 'high', 'detected', NULL)"
            ),
            {"t": str(TENANT), "a": str(alert_id)},
        )
        await db.commit()

        counts = await _soc_disposition_counts(db, TENANT, datetime.now(UTC) - timedelta(days=7))

        assert counts["analyst_overrides"] == 0

    async def test_the_false_positive_denominator_excludes_abstentions(self, db) -> None:
        """ "0.0% over 5 resolved alerts" on a tenant that resolved nothing.
        The denominator counted `needs_review`, which is the agent saying it
        could not tell."""
        from app.api.v1.endpoints.metrics import _soc_disposition_counts

        await _seed(db, _LIVE_SHAPE)

        counts = await _soc_disposition_counts(db, TENANT, datetime.now(UTC) - timedelta(days=7))

        assert counts["decided"] == 0, f"{counts['decided']} decided verdicts over nine abstentions"


@pytest.mark.asyncio
class TestSocInsightsTilesCarryTheirSampleCount:
    """The card already renders "not measured" when `sample_count` is 0.
    Three tiles never set it, so they rendered a confident zero beside two
    honest dashes on the same row."""

    async def test_the_three_silent_tiles_now_declare_a_denominator(self, db) -> None:
        from app.api.v1.endpoints.insights import get_soc_insights

        await _seed(db, _LIVE_SHAPE)

        response = await get_soc_insights(window="7d", user=_principal(TENANT), db=db)
        tiles = {t.key: t for t in response.tiles}

        for key in ("fp_rate", "agent_cost_per_investigation", "analyst_hours_saved"):
            assert tiles[key].sample_count is not None, f"{key} publishes a value with no denominator beside it"

    async def test_zero_llm_calls_is_not_a_zero_cost(self, db) -> None:
        """`/costs` on the same stack gets this right. A mean over no runs
        is unmeasured, and "$0.000 per investigation" is the single most
        flattering number the product can print."""
        from app.api.v1.endpoints.insights import get_soc_insights

        await _seed(db, _LIVE_SHAPE)
        runs = await db.scalar(
            text("SELECT count(*) FROM investigation_runs WHERE tenant_id = CAST(:t AS uuid)"),
            {"t": str(TENANT)},
        )
        assert runs == 0

        response = await get_soc_insights(window="7d", user=_principal(TENANT), db=db)
        cost = next(t for t in response.tiles if t.key == "agent_cost_per_investigation")

        assert cost.sample_count == 0, f"cost per investigation claims {cost.sample_count} runs on a stack that placed none"

    async def test_the_false_positive_tile_agrees_with_the_soc_card(self, db) -> None:
        """Two surfaces, one question. They disagreed because one counted
        abstentions and the other did not."""
        from app.api.v1.endpoints.insights import get_soc_insights
        from app.api.v1.endpoints.metrics import _soc_disposition_counts

        await _seed(db, _LIVE_SHAPE)

        response = await get_soc_insights(window="7d", user=_principal(TENANT), db=db)
        tile = next(t for t in response.tiles if t.key == "fp_rate")
        counts = await _soc_disposition_counts(db, TENANT, datetime.now(UTC) - timedelta(days=7))

        assert tile.sample_count == counts["decided"], (
            f"the insights tile divided by {tile.sample_count} and the SOC card by {counts['decided']}"
        )


def _principal(tenant_id: uuid.UUID) -> CurrentUser:
    """The real principal class, not a duck-typed stand-in.

    A hand-rolled object with the three attributes the handler happens to
    read is exactly the test double that is more capable than the thing it
    stands for -- it keeps passing while the handler grows a fourth.
    """
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id,
        role="admin",
        email="denominator@example.com",
    )
