"""The SLA page reported perfect compliance over a table with no rows.

The defect
----------
``/sla`` rendered **Total Alerts 0 · SLA Breaches 0 · Breach Rate 0%**
for a tenant with nine alerts, and in the panel directly below, on the
same page, *"False positive rate 0% (0 / 9)"* and *"2 breaches"*. Two
panels on one screen disagreeing about how many alerts exist is the tell.

``alert_sla_events`` had **0 rows** after nine alerts traversed the
pipeline. Its only writers are analyst actions — acknowledging an alert
and setting a disposition — so on a deployment where nobody has clicked
anything there is no SLA data at all. A breach rate of 0% over that
reads as perfect compliance; the honest answer is that nothing has been
measured.

The decision, and why
---------------------
Not "write a ``detected`` event at alert creation". ``sla_events.py``
already explains why it backfills instead: alerts are written by
``services/fusion`` on a different session, and making the hot ingest
path write into an API-owned reporting table would mean a fusion
deployment lagging the API schema stops ingesting. That reasoning still
holds, so the absence is rendered rather than manufactured — and the
response now carries ``alerts_in_window`` so the page can say *how many*
alerts have no lifecycle data instead of implying there are none.

Two more figures on the same page that could not be right
---------------------------------------------------------
``_compute_kpi_bar`` counted false positives as ``Alert.status == "fp"``.
No writer in the repository writes that value — three readers filter on
it and the bulk-close endpoint writes ``false_positive`` — so the
false-positive count was **structurally zero** and the KPI always read
as meeting its target.

And "MITRE technique coverage 22.22% · target ≥ 85% · Breach" measures
the fraction of *alerts carrying a technique tag*, which is not coverage
of ATT&CK and not what the target means. The API field has always been
named ``mitre_technique_tagging_pct``; the console renamed it on the way
to the screen.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Sequence

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0c100000-0000-0000-0000-0000000000e0")


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
                f"the SLA-absence proof did not run: {type(exc).__name__}: {exc}"
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
    for table in ("alert_sla_events", "tenant_sla_config", "alerts"):
        await session.execute(text(f"DELETE FROM {table} WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.execute(text("DELETE FROM tenants WHERE id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.commit()


async def _seed(session, rows: Sequence[tuple[str, str | None, list[str]]]) -> list[uuid.UUID]:
    """``(severity, disposition, mitre_techniques)`` — returns the ids created."""
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'SLA', 'sla-absence') ON CONFLICT (id) DO NOTHING"),
        {"t": str(TENANT)},
    )
    ids: list[uuid.UUID] = []
    for severity, disposition, techniques in rows:
        alert_id = uuid.uuid4()
        ids.append(alert_id)
        await session.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, severity, status, disposition,
                                    mitre_techniques, created_at, updated_at)
                VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :ti, :s, 'triaged', :d,
                        CAST(:m AS jsonb), NOW(), NOW())
                """
            ),
            {
                "i": str(alert_id),
                "t": str(TENANT),
                "ti": f"{severity} alert",
                "s": severity,
                "d": disposition,
                "m": _json(techniques),
            },
        )
    await session.commit()
    return ids


def _json(values: list[str]) -> str:
    import json

    return json.dumps(values)


#: The live reproduction: nine alerts, two of them tagged, nothing acknowledged.
_LIVE_SHAPE: list[tuple[str, str | None, list[str]]] = [
    ("critical", "needs_review", ["T1059.001"]),
    ("critical", "needs_review", []),
    ("critical", "needs_review", []),
    ("high", "needs_review", ["T1078.004"]),
    ("high", "needs_review", []),
    ("high", "needs_review", []),
    ("high", "needs_review", []),
    ("medium", "needs_review", []),
    ("low", "needs_review", []),
]


@pytest.mark.asyncio
class TestTheSlaPanelSaysWhenNothingWasMeasured:
    async def test_no_lifecycle_events_is_not_zero_breaches(self, db) -> None:
        """The reproduction. Nine alerts, no SLA events, and the page said
        'Breach Rate 0%' — which reads as perfect compliance."""
        from app.services.sla import compute_sla_metrics

        await _seed(db, _LIVE_SHAPE)

        events = await db.scalar(
            text("SELECT count(*) FROM alert_sla_events WHERE tenant_id = CAST(:t AS uuid)"),
            {"t": str(TENANT)},
        )
        assert events == 0, "the fixture is wrong before the code is"

        metrics = await compute_sla_metrics(db, TENANT, days=30)

        assert metrics["overall"]["measured"] is False, (
            "the SLA overall block does not declare that it measured nothing, so a breach rate of 0% "
            "is indistinguishable from perfect compliance"
        )

    async def test_the_two_panels_agree_about_how_many_alerts_exist(self, db) -> None:
        """'Total Alerts 0' sat directly above '(0 / 9)'. Both read the same
        tenant over the same window."""
        from app.services.sla import compute_sla_metrics

        await _seed(db, _LIVE_SHAPE)

        in_window = await db.scalar(
            text("SELECT count(*) FROM alerts WHERE tenant_id = CAST(:t AS uuid)"),
            {"t": str(TENANT)},
        )
        assert in_window == 9

        metrics = await compute_sla_metrics(db, TENANT, days=30)

        assert metrics["overall"]["alerts_in_window"] == 9, (
            f"the SLA card reports {metrics['overall'].get('alerts_in_window')} alerts in the window and the KPI panel below it reports 9"
        )
        assert metrics["overall"]["total_alerts"] == 0, "no alert has a lifecycle event, so none is SLA-measurable"

    async def test_a_measured_tenant_still_reports_a_breach_rate(self, db) -> None:
        """The positive control. A card that said 'not measured' whatever
        happened would pass the two tests above and report nothing ever."""
        from app.services.sla import compute_sla_metrics

        ids = await _seed(db, [("critical", "true_positive", [])])
        # Detected now, acknowledged two hours later: far past the 15-minute
        # critical MTTD target, so this is a breach the page must show.
        await db.execute(
            text(
                "INSERT INTO alert_sla_events (tenant_id, alert_id, severity, event_type, occurred_at) "
                "VALUES (CAST(:t AS uuid), CAST(:a AS uuid), 'critical', 'detected', NOW() - interval '2 hours')"
            ),
            {"t": str(TENANT), "a": str(ids[0])},
        )
        await db.execute(
            text(
                "INSERT INTO alert_sla_events (tenant_id, alert_id, severity, event_type, occurred_at, actor_id) "
                "VALUES (CAST(:t AS uuid), CAST(:a AS uuid), 'critical', 'acknowledged', NOW(), CAST(:u AS uuid))"
            ),
            {"t": str(TENANT), "a": str(ids[0]), "u": str(uuid.uuid4())},
        )
        await db.commit()

        metrics = await compute_sla_metrics(db, TENANT, days=30)

        assert metrics["overall"]["measured"] is True
        assert metrics["overall"]["total_alerts"] == 1
        assert metrics["overall"]["total_breaches"] == 1, "a two-hour acknowledgement on a 15-minute target is a breach"
        assert metrics["overall"]["breach_rate"] == 100.0


@pytest.mark.asyncio
class TestTheKpiBarMeasuresWhatItSays:
    async def test_a_false_positive_is_counted_from_the_disposition(self, db) -> None:
        """`Alert.status == "fp"` matched nothing: no writer in the tree
        writes that value. The false-positive count was structurally zero,
        so the KPI always read as meeting its target."""
        from app.services.sla import compute_sla_metrics

        await _seed(
            db,
            [
                ("high", "false_positive", []),
                ("high", "false_positive", []),
                ("high", "true_positive", []),
                ("low", "needs_review", []),
            ],
        )

        written_fp = await db.scalar(
            text("SELECT count(*) FROM alerts WHERE tenant_id = CAST(:t AS uuid) AND disposition = 'false_positive'"),
            {"t": str(TENANT)},
        )
        never_written = await db.scalar(
            text("SELECT count(*) FROM alerts WHERE tenant_id = CAST(:t AS uuid) AND status = 'fp'"),
            {"t": str(TENANT)},
        )
        assert (written_fp, never_written) == (2, 0), "the fixture is wrong before the code is"

        metrics = await compute_sla_metrics(db, TENANT, days=30)
        observed = metrics["kpi_bar"]["observed"]

        assert observed["false_positives"] == 2, (
            f"the KPI bar counted {observed['false_positives']} false positives against two recorded — "
            "it is reading a status column nothing writes"
        )
        assert observed["false_positive_rate_denominator"] == 3, "the rate is over decided verdicts, not over every alert"

    async def test_the_tagging_figure_declares_that_it_is_tagging(self, db) -> None:
        """ "MITRE technique coverage 22.22%, target >= 85%, Breach" measures
        the share of alerts carrying a technique, which is not coverage of
        ATT&CK. The API field was always named `..._tagging_pct`."""
        from app.services.sla import compute_sla_metrics

        await _seed(db, _LIVE_SHAPE)

        metrics = await compute_sla_metrics(db, TENANT, days=30)
        observed = metrics["kpi_bar"]["observed"]

        assert observed["mitre_technique_tagging_pct"] == 22.22
        assert "mitre_technique_coverage_pct" not in observed, (
            "a key named `coverage` would let the console keep calling a tagging rate coverage"
        )
