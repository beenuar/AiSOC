"""Nine alerts in the queue, "Active Alerts 0" on the tile above them.

The defect
----------
``UNRESOLVED_STATUSES`` listed ``new | triaging | in_progress``. The
auto-triage worker writes ``triaged`` (``services/agents`` →
``investigator/ledger.py``, the ``WHEN status = 'new' … THEN 'triaged'``
arm), which is in neither that tuple nor ``RESOLVED_STATUSES`` — so a
triaged alert fell out of **both** buckets and ``/metrics/dashboard``
returned ``{"total": 0, "critical": 0, "high": 0, "resolved": 0}`` for a
tenant with nine unresolved alerts. A live QA pass watched the critical
tile decay 3 → 2 → 1 → 0 as each alert was auto-triaged, on the same
screen as an Operations Funnel reading "Alerts Generated 9".

Two things make it worse than an omission. ``alert_status`` ships
``is_unresolved()``, whose unknown-status default is correct and which
the SQL ``IN`` never runs; and ``cases.py`` carried a second, different,
hand-written copy of the same vocabulary that *did* contain ``triaged``.
Two declarations of one vocabulary that disagree is the drift this
module was written to stop.

How these tests are built
-------------------------
Every count is asserted against rows **this test counted itself**, never
against a second call to the thing being measured — four defects in this
family shipped because the test re-ran the producer and compared it with
itself.

The literal is pinned on both sides: :class:`TestTheWriterAndReaderAgree`
reads the status literals out of the *worker's* SQL and requires the
reader's vocabulary to contain them, because a test that seeds the shape
its author imagined rather than the one production writes has passed
here before.
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

#: Fixed so a failure names something greppable, and distinct from every
#: other suite's tenant so a parallel run cannot see these rows.
TENANT = uuid.UUID("0c100000-0000-0000-0000-0000000000a5")

_REPO_ROOT = Path(__file__).resolve().parents[3]
_LEDGER = _REPO_ROOT / "services" / "agents" / "app" / "investigator" / "ledger.py"


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
                f"the status-vocabulary proof did not run: {type(exc).__name__}: {exc}"
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
        text("INSERT INTO tenants (id, name, slug) VALUES (CAST(:t AS uuid), 'Vocab Test', 'vocab-test') ON CONFLICT (id) DO NOTHING"),
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


def _worker_written_statuses() -> set[str]:
    """The status literals the auto-triage worker actually writes.

    Read out of the worker's own SQL rather than retyped here, so this
    test cannot drift from the writer the way the reader's tuple did.
    """
    source = _LEDGER.read_text(encoding="utf-8")
    start = source.index("UPDATE alerts")
    body = source[start : start + 2000]
    case = re.search(r"status\s*=\s*CASE(.*?)END", body, re.DOTALL)
    assert case, "the worker's `status = CASE` block is no longer where this test looks — re-point it"
    return set(re.findall(r"THEN\s+'([a-z_]+)'", case.group(1)))


class TestTheWriterAndReaderAgree:
    """Pin the literal on both sides. No database needed."""

    def test_every_status_the_worker_writes_is_in_the_vocabulary(self) -> None:
        from app.services.alert_status import WRITTEN_STATUSES

        written = _worker_written_statuses()
        assert written, "read no status literals out of the worker — the regex found nothing to compare"

        missing = sorted(written - set(WRITTEN_STATUSES))
        assert not missing, (
            f"the auto-triage worker writes {missing} and the reader's vocabulary does not contain it, "
            "so alerts in that state fall out of both the unresolved and the resolved bucket"
        )

    def test_triaged_is_unresolved(self) -> None:
        """The specific reproduction: an auto-triaged alert is still the
        analyst's problem. It has a verdict, not an outcome."""
        from app.services.alert_status import UNRESOLVED_STATUSES, is_resolved, is_unresolved

        assert is_unresolved("triaged") is True
        assert is_resolved("triaged") is False
        assert "triaged" in UNRESOLVED_STATUSES

    def test_the_vocabulary_partitions_with_nothing_left_over(self) -> None:
        """Every known status is in exactly one bucket. A status in neither
        is invisible to every count on the dashboard, which is how nine
        alerts rendered as zero."""
        from app.services.alert_status import RESOLVED_STATUSES, UNRESOLVED_STATUSES, WRITTEN_STATUSES

        classified = set(RESOLVED_STATUSES) | set(UNRESOLVED_STATUSES)
        orphans = sorted(set(WRITTEN_STATUSES) - classified)
        assert not orphans, f"{orphans} is in neither bucket"
        overlap = sorted(set(RESOLVED_STATUSES) & set(UNRESOLVED_STATUSES))
        assert not overlap, f"{overlap} is in both buckets, so it is counted twice"

    def test_the_sql_predicate_agrees_with_the_python_predicate(self) -> None:
        """`is_unresolved()` treats an unknown status as unresolved; the
        tuple used in a SQL `IN` could not. They are now one definition,
        so a status nobody added here is still counted.

        Read off the rendered SQL rather than the result, because the
        inclusion form returns the right answer for every status someone
        remembered to list -- which is precisely why nobody noticed.
        """
        from app.models.alert import Alert
        from app.services.alert_status import is_unresolved, unresolved_filter

        rendered = str(unresolved_filter(Alert.status).compile(compile_kwargs={"literal_binds": True}))

        assert "NOT IN" in rendered.upper(), (
            f"the unresolved predicate is still an inclusion list ({rendered}) — an unrecognised status "
            "will silently drop out of the queue count again"
        )
        assert "'triaged'" not in rendered, "`triaged` appears in the terminal list; it is open work"
        assert is_unresolved("some-state-nobody-added-here") is True


@pytest.mark.asyncio
class TestTheDashboardCountsEveryUnresolvedAlert:
    async def test_the_total_equals_the_rows_this_test_counted(self, db) -> None:
        """The reproduction, asserted against an independent count.

        Nine alerts in the statuses the pipeline and the worker actually
        write. The expected number is computed here from the seed list,
        and cross-checked against a `SELECT count(*)` this test issues
        itself — never against a second call to the thing being measured.
        """
        from app.api.v1.endpoints.metrics import _count_alerts_by_status
        from app.services.alert_status import RESOLVED_STATUSES

        seeded = [
            ("new", "critical"),
            ("triaged", "critical"),
            ("triaged", "critical"),
            ("triaged", "high"),
            ("triaged", "high"),
            ("triaging", "high"),
            ("in_progress", "high"),
            ("triaged", "medium"),
            ("investigating", "low"),
            ("resolved", "high"),
            ("closed", "critical"),
        ]
        await _seed(db, seeded)

        expected_open = sum(1 for status, _ in seeded if status not in RESOLVED_STATUSES)
        independent = await db.scalar(
            text(
                "SELECT count(*) FROM alerts WHERE tenant_id = CAST(:t AS uuid) "
                "AND status NOT IN ('resolved', 'closed', 'false_positive', 'fp', 'dismissed')"
            ),
            {"t": str(TENANT)},
        )
        assert independent == expected_open == 9, f"the fixture is wrong before the code is: {independent} vs {expected_open}"

        counts = await _count_alerts_by_status(db, TENANT)

        assert counts["open"] == 9, (
            f"nine unresolved alerts, the dashboard reports {counts['open']} — a status the workers write is falling out of both buckets"
        )
        assert counts["critical"] == 3
        assert counts["high"] == 4
        assert counts["medium"] == 1
        assert counts["resolved"] == 2

    async def test_a_status_nobody_declared_still_counts_as_open(self, db) -> None:
        """The structural half. The next worker to invent a status must not
        be able to make the backlog look smaller by not telling anyone."""
        from app.api.v1.endpoints.metrics import _count_alerts_by_status

        await _seed(db, [("awaiting_vendor", "critical"), ("new", "low")])

        counts = await _count_alerts_by_status(db, TENANT)

        assert counts["open"] == 2, (
            f"an unrecognised status dropped out of the queue count ({counts['open']} of 2) — "
            "`is_unresolved()` says unknown means open and the SQL disagrees"
        )
        assert counts["critical"] == 1

    async def test_terminal_work_is_still_excluded(self, db) -> None:
        """The negative control for the widening. A predicate that counted
        everything would pass both tests above and make the tile useless."""
        from app.api.v1.endpoints.metrics import _count_alerts_by_status

        await _seed(
            db,
            [
                ("resolved", "critical"),
                ("closed", "high"),
                ("false_positive", "high"),
                ("dismissed", "medium"),
                ("fp", "low"),
            ],
        )

        counts = await _count_alerts_by_status(db, TENANT)

        assert counts["open"] == 0, f"terminal alerts are being counted as open work ({counts['open']} of 5)"
        assert counts["critical"] == 0

    async def test_the_queue_depth_on_the_funnel_agrees_with_the_tile(self, db) -> None:
        """The two numbers sit on one screen. They read 9 and 0 against the
        same rows, which is the tell that one of them is wrong."""
        from app.api.v1.endpoints.metrics import _count_alerts_by_status, _funnel_window

        await _seed(db, [("triaged", "critical"), ("triaged", "high"), ("new", "low")])

        counts = await _count_alerts_by_status(db, TENANT)
        end = datetime.now(UTC) + timedelta(minutes=1)
        funnel = await _funnel_window(db, TENANT, end - timedelta(days=1), end, mitre_total=201)

        assert counts["open"] == 3
        assert funnel["analyst_queue_depth"] == 3, (
            f"the funnel reports {funnel['analyst_queue_depth']} in the queue and the tile reports "
            f"{counts['open']} — two surfaces disagreeing about the same rows"
        )

    async def test_another_tenants_alerts_are_not_counted(self, db) -> None:
        """Widening a status predicate must not widen the tenant one."""
        from app.api.v1.endpoints.metrics import _count_alerts_by_status

        await _seed(db, [("triaged", "critical")])

        counts = await _count_alerts_by_status(db, uuid.uuid4())

        assert counts["open"] == 0
