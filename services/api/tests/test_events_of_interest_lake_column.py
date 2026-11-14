"""The funnel's lake query must filter on a column the lake actually has.

Discussion #1568 attached, underneath an SSO lockout, a second symptom:

    [aisoc-api] events_of_interest ClickHouse fallback: clickhouse query
    failed: Code: 47. DB::Exception: Missing columns: 'ingested_at'

`_events_of_interest` filtered `aisoc.raw_events` on `ingested_at`, a column
that does not exist — the lake has `event_time` (when the event occurred) and
`ingest_time` (when it landed). So the query raised `Code: 47` on every call
and the funnel silently served its Postgres fallback on every deployment with
a reachable lake. The primary source was dead and nothing said so.

This test derives the real column set from the committed ClickHouse DDL and
asserts every column the funnel query filters on is a member. It fails on the
pre-fix tree (`ingested_at` is not in the DDL) and would catch any future
query that invents a column, not only this one.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

from app.api.v1.endpoints.metrics import _events_of_interest_sql

_DDL = Path(__file__).resolve().parents[1] / "clickhouse" / "001_init.sql"


def _raw_events_columns() -> set[str]:
    """Column names declared for `aisoc.raw_events` in the canonical DDL."""
    sql = _DDL.read_text(encoding="utf-8")
    body = re.search(
        r"CREATE TABLE IF NOT EXISTS aisoc\.raw_events\s*\((.*?)\)\s*ENGINE",
        sql,
        re.DOTALL | re.IGNORECASE,
    )
    assert body, "could not locate the aisoc.raw_events CREATE TABLE in 001_init.sql"
    columns: set[str] = set()
    for line in body.group(1).splitlines():
        token = line.strip()
        if not token or token.startswith("--"):
            continue
        name = token.split()[0].strip(",")
        if re.fullmatch(r"[a-z_][a-z0-9_]*", name):
            columns.add(name)
    return columns


def _filtered_columns(sql: str) -> set[str]:
    """Columns the query compares against in its WHERE clause."""
    return set(re.findall(r"(?:WHERE|AND)\s+([a-z_][a-z0-9_]*)\s*(?:>=|<=|<|>|=)", sql))


def test_the_funnel_query_filters_on_a_real_lake_column() -> None:
    start = datetime(2026, 10, 30, 0, 0, tzinfo=UTC)
    end = datetime(2026, 10, 30, 1, 0, tzinfo=UTC)
    sql = _events_of_interest_sql(start, end)

    columns = _raw_events_columns()
    # Guard the guard: if the DDL parse ever returns nothing, the membership
    # assertion below would pass vacuously.
    assert {"event_time", "ingest_time"} <= columns, columns

    filtered = _filtered_columns(sql)
    assert filtered, f"no filter column parsed from: {sql}"
    missing = filtered - columns
    assert not missing, f"funnel query filters on columns absent from aisoc.raw_events: {missing}"


def test_the_dead_column_name_is_gone() -> None:
    sql = _events_of_interest_sql(datetime(2026, 10, 30, tzinfo=UTC), datetime(2026, 10, 31, tzinfo=UTC))
    assert "ingested_at" not in sql
    assert "ingest_time" in sql
