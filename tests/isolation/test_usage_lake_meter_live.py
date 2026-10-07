"""`events_ingested` against a real ClickHouse carrying the shipped DDL.

The offline suite drives this meter through a stand-in for
`execute_lake_query`, which proves the branching — measured, not
measured, per-day fill — and cannot prove the SQL is valid ClickHouse or
that `toDate(ingest_time)` buckets the way this module assumes. Those are
exactly the two things that would make a usage figure wrong on a
customer's deployment and right in CI.

What is proven here
--------------------
* the statement parses and runs against the table `001_init.sql` creates,
  loaded verbatim rather than from a hand-written subset;
* days with no events come back as a measured `0` rather than absent;
* another tenant's rows sit inside the same window and are never counted;
* the per-day series and one scan over the whole window agree, which is
  the reconciliation the API exposes and the only place a timezone
  disagreement between Python's day window and ClickHouse's `toDate`
  can show up.

The negative control
--------------------
`test_another_tenants_events_are_never_counted` is what stops the rest
passing against a surface that counts every row: the fixture seeds a
second tenant inside the window on purpose.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

# Skip as a *module*, not only in the fixture. The offline isolation job
# collects this directory with no stores running, and a test that did not
# take the fixture would run there and fail — a failure about the harness,
# reported against a capability.
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CLICKHOUSE_HOST", "").strip(),
        reason="ISOLATION_CLICKHOUSE_HOST is not set; this suite needs live infrastructure",
    ),
]

TENANT_A = uuid.UUID("3a3a3a3a-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("3b3b3b3b-0000-0000-0000-00000000000b")

DDL = "services/api/clickhouse/001_init.sql"

#: Three consecutive days, ending yesterday so nothing races the clock.
LAST_DAY: date = datetime.now(UTC).date() - timedelta(days=1)
FIRST_DAY: date = LAST_DAY - timedelta(days=2)

#: What the fixture writes, by ingest day. The middle day is deliberately
#: empty: an absent day reads as a gap in a chart, and this one is a
#: measured zero.
SEEDED: dict[date, int] = {FIRST_DAY: 3, FIRST_DAY + timedelta(days=1): 0, LAST_DAY: 1}

#: Inside the same window, and never this tenant's.
SEEDED_OTHER_TENANT = 5

if os.environ.get("ISOLATION_CLICKHOUSE_HOST"):
    os.environ.setdefault("CLICKHOUSE_HOST", os.environ["ISOLATION_CLICKHOUSE_HOST"])
    os.environ.setdefault("CLICKHOUSE_PORT", os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000"))
    os.environ.setdefault("CLICKHOUSE_USER", os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"))
    os.environ.setdefault("CLICKHOUSE_PASSWORD", os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""))
    os.environ.setdefault("CLICKHOUSE_DATABASE", "aisoc")


def _statements(sql: str) -> list[str]:
    """Split the DDL into statements the driver can send one at a time.

    Comments are dropped first so a `--` containing a semicolon cannot
    split a statement in the wrong place.
    """
    lines = [line for line in sql.splitlines() if not line.strip().startswith("--")]
    return [statement.strip() for statement in "\n".join(lines).split(";") if statement.strip()]


def _at(day: date, hour: int) -> datetime:
    """ClickHouse's `DateTime64` columns take a naive UTC value."""
    return datetime(day.year, day.month, day.day, hour, tzinfo=UTC).replace(tzinfo=None)


@pytest.fixture(scope="module")
def lake():
    """A ClickHouse carrying the product's own schema and a known corpus."""
    driver = pytest.importorskip("clickhouse_driver")
    client = driver.Client(
        host=os.environ["ISOLATION_CLICKHOUSE_HOST"],
        port=int(os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000")),
        user=os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"),
        password=os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""),
    )

    root = Path(os.environ.get("ISOLATION_REPO_ROOT", "."))
    for statement in _statements((root / DDL).read_text(encoding="utf-8")):
        client.execute(statement)
    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")

    rows = []
    for day, count in SEEDED.items():
        rows.extend(
            # `ingest_time` is the clock this meter uses — when AiSOC
            # received the event. `event_time` is the vendor's, and a
            # backfill would otherwise land a week of usage on one day.
            (TENANT_A, _at(day, hour), _at(day, hour), 2001, 2, 4, "high", "{}")
            for hour in range(count)
        )
    rows.extend((TENANT_B, _at(FIRST_DAY, hour), _at(FIRST_DAY, hour), 2001, 2, 4, "high", "{}") for hour in range(SEEDED_OTHER_TENANT))

    client.execute(
        "INSERT INTO aisoc.raw_events "
        "(tenant_id, event_time, ingest_time, class_uid, category_uid, severity_id, severity, raw_payload) VALUES",
        rows,
    )
    yield client
    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")


class TestTheNegativeControl:
    async def test_the_corpus_is_there_and_spans_two_tenants(self, lake) -> None:  # noqa: ANN001
        """Without this, every assertion below could pass on an empty table."""
        total = lake.execute("SELECT count() FROM aisoc.raw_events")[0][0]
        assert total == sum(SEEDED.values()) + SEEDED_OTHER_TENANT, total


class TestTheMeterCountsTheLake:
    async def test_the_daily_series_matches_the_rows_seeded_for_each_day(self) -> None:
        from app.services import usage_metering

        series = await usage_metering.measure_events_ingested(TENANT_A, FIRST_DAY, LAST_DAY)

        assert series is not None, "the meter reported 'not measured' against a lake that is running"
        assert series == SEEDED

    async def test_a_day_with_no_events_is_a_measured_zero(self) -> None:
        """Present with a count, not absent.

        An absent day reads as a gap, and a gap means "we did not look".
        """
        from app.services import usage_metering

        series = await usage_metering.measure_events_ingested(TENANT_A, FIRST_DAY, LAST_DAY)
        empty = FIRST_DAY + timedelta(days=1)
        assert empty in (series or {})
        assert series[empty] == 0

    async def test_another_tenants_events_are_never_counted(self) -> None:
        from app.services import usage_metering

        series = await usage_metering.measure_events_ingested(TENANT_A, FIRST_DAY, LAST_DAY)
        assert sum((series or {}).values()) == sum(SEEDED.values())
        assert sum(SEEDED.values()) < sum(SEEDED.values()) + SEEDED_OTHER_TENANT, "the fixture no longer seeds another tenant"

    async def test_the_series_and_one_scan_over_the_window_agree(self) -> None:
        """The reconciliation the API exposes, against real rows.

        The two are different ClickHouse queries — one grouped by
        `toDate(ingest_time)`, one not — so a timezone disagreement
        between the day window this module builds and ClickHouse's own
        bucketing shows up here and in no single-day assertion.
        """
        from app.services import usage_metering

        series = await usage_metering.measure_events_ingested(TENANT_A, FIRST_DAY, LAST_DAY)
        whole_window = await usage_metering.count_events_ingested(TENANT_A, FIRST_DAY, LAST_DAY)

        assert whole_window is not None
        assert sum((series or {}).values()) == whole_window


class TestTheMeterIsHonestAboutAnAbsentLake:
    async def test_no_lake_configured_reads_not_measured_rather_than_zero(self, monkeypatch) -> None:  # noqa: ANN001
        """The same code path a CORE deployment takes.

        Asserted here as well as offline because this is the branch a
        reader of the API response depends on: `0` would tell them their
        connectors had stopped.
        """
        from app.core.config import settings
        from app.services import usage_metering

        monkeypatch.setattr(settings, "CLICKHOUSE_HOST", "", raising=False)
        assert await usage_metering.measure_events_ingested(TENANT_A, FIRST_DAY, LAST_DAY) is None
