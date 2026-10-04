"""A tenant who worked their queue to zero sees zero, not their whole history.

The defect
----------
`GET /api/v1/metrics/dashboard` counted alerts like this:

    total_q    = count(where tenant_id = ...)
    critical_q = count(where tenant_id = ... and severity = 'critical')

No status filter on either. The console renders the first as **Active Alerts**
and the second under **Critical — Require immediate action**, so both numbers
were the tenant's entire historical intake. They never went down. A tenant who
had triaged and resolved every alert still saw a red critical tile demanding
immediate action on work finished months ago.

The filter was not missing for want of a definition -- `alerts.py:710`,
`metrics.py:1018` and `health.py:416` all already carried
`status.in_(("new", "triaging", "in_progress"))`. The tile was simply the one
site that never got it, which is why the fix routes them through
`app.services.alert_status` rather than adding a fifth hand-written copy.

Run against live Postgres, because the defect is a missing `WHERE` clause and
a fake session that answers any query cannot tell a filtered count from an
unfiltered one. Skips when no database answers so a local run stays green, but
**cannot** skip where it is meant to run: `integration.yml` sets
`MSSP_ISOLATION_REQUIRED=1` and an unreachable database is then a failure --
a gate that quietly declines to run is the shape this file exists to catch.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

# Fixed so a failure names something greppable.
TENANT = uuid.UUID("0c100000-0000-0000-0000-00000000000a")


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
                f"the alert-tile proof did not run: {type(exc).__name__}: {exc}"
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
    await session.execute(text("DELETE FROM alerts WHERE tenant_id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.execute(text("DELETE FROM tenants WHERE id = CAST(:t AS uuid)"), {"t": str(TENANT)})
    await session.commit()


async def _seed(session, pairs: list[tuple[str, str]]) -> None:
    await session.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'Tile Test', 'tile-test') ON CONFLICT (id) DO NOTHING"),
        {"t": str(TENANT)},
    )
    for status, severity in pairs:
        await session.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, severity, status, created_at, updated_at)
                VALUES (CAST(:i AS uuid), CAST(:t AS uuid), :ti, :s, :st, NOW(), NOW())
                """
            ),
            {
                "i": str(uuid.uuid4()),
                "t": str(TENANT),
                "ti": f"{severity} alert in {status}",
                "s": severity,
                "st": status,
            },
        )
    await session.commit()


@pytest.mark.asyncio
class TestTheActiveTileCountsOnlyOpenWork:
    async def test_a_fully_worked_queue_reports_zero_active(self, db) -> None:
        """The reproduction. Every alert resolved, so the tile must read 0.
        Before the fix it read 4."""
        from app.api.v1.endpoints.metrics import _count_alerts_by_status

        await _seed(
            db,
            [
                ("resolved", "critical"),
                ("resolved", "high"),
                ("closed", "critical"),
                ("resolved", "medium"),
            ],
        )

        counts = await _count_alerts_by_status(db, TENANT)

        assert counts["open"] == 0, (
            f"a tenant with every alert resolved shows {counts['open']} active — the tile is counting the historical backlog"
        )

    async def test_critical_counts_only_unresolved_criticals(self, db) -> None:
        """'Require immediate action' is a claim about now."""
        from app.api.v1.endpoints.metrics import _count_alerts_by_status

        await _seed(db, [("resolved", "critical"), ("new", "critical")])

        counts = await _count_alerts_by_status(db, TENANT)

        assert counts["critical"] == 1

    async def test_open_work_is_still_counted(self, db) -> None:
        """The negative control. A filter that counted nothing would pass the
        two tests above and make the dashboard useless."""
        from app.api.v1.endpoints.metrics import _count_alerts_by_status

        await _seed(db, [("new", "high"), ("triaging", "critical"), ("in_progress", "low")])

        counts = await _count_alerts_by_status(db, TENANT)

        assert counts["open"] == 3
        assert counts["critical"] == 1
        assert counts["high"] == 1

    async def test_resolved_work_is_still_reported(self, db) -> None:
        """Narrowing the tile must not lose the number. "How much did we
        close" is a real question, and the answer should not vanish because
        the other tile was corrected."""
        from app.api.v1.endpoints.metrics import _count_alerts_by_status

        await _seed(db, [("resolved", "high"), ("closed", "low"), ("new", "medium")])

        counts = await _count_alerts_by_status(db, TENANT)

        assert counts["resolved"] == 2
        assert counts["open"] == 1

    async def test_another_tenants_alerts_are_not_counted(self, db) -> None:
        """Every count here is tenant-scoped, and a regression that dropped
        the predicate would be a cross-tenant read rather than a wrong tile."""
        from app.api.v1.endpoints.metrics import _count_alerts_by_status

        await _seed(db, [("new", "critical")])
        other = uuid.uuid4()

        counts = await _count_alerts_by_status(db, other)

        assert counts["open"] == 0


class TestTheDefinitionIsSharedRatherThanCopied:
    """No database needed: these hold wherever the suite runs, and a
    module-level skip would have confined them to the integration job."""

    def test_the_dashboard_uses_the_canonical_set(self) -> None:
        from pathlib import Path

        source = (Path(__file__).resolve().parents[1] / "app" / "api" / "v1" / "endpoints" / "metrics.py").read_text(encoding="utf-8")

        assert "alert_status" in source, "metrics.py does not import the shared status definition"

    def test_an_unknown_status_counts_as_open(self) -> None:
        """The safer default for a queue: dropping an unrecognised status
        would make the backlog look smaller than it is."""
        from app.services.alert_status import is_unresolved

        assert is_unresolved("some-state-nobody-added-here") is True
        assert is_unresolved(None) is True

    def test_both_terminal_spellings_are_resolved(self) -> None:
        """`closed` arrives from vendor writeback, `resolved` from the
        console. Recognising only one leaves the other in the queue forever."""
        from app.services.alert_status import is_resolved

        assert is_resolved("resolved") is True
        assert is_resolved("closed") is True
        assert is_resolved("triaging") is False
