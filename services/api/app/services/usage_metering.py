"""Per-tenant, per-day usage, counted from the rows that record the work.

Why there is no counter table
------------------------------
The obvious design is a `usage_daily` table incremented as things happen.
That design has one failure mode and this repository has already paid for it
twice: a counter drifts from the table it summarises, nothing notices,
and two surfaces then disagree about the same rows. `cases_closed_7d` read a
status that was intermediate; `mttr_hours` averaged a column ordinary case
work never writes and published emptiness as a confident `0.0`.

So every meter here is a `SELECT` against the table that holds the evidence,
evaluated when somebody asks. The number cannot drift from the rows because
it *is* the rows. That is also what makes the acceptance test possible:
insert a known number of rows, ask the meter, compare. A counter table could
only be tested against itself.

The cost is that a query runs per request rather than a lookup. Bounded by
the indexes these tables already carry on `(tenant_id, created_at)`, and a
usage screen is not on a hot path.

Why a meter can read "not measured"
------------------------------------
`events_ingested` lives in the ClickHouse event lake, which is a `full`
profile service and is absent on CORE. A meter whose source is not deployed
reports ``None``, and every surface renders that as "not measured". It must
never render as `0`: zero is a measurement, and a reader who sees it
concludes no events arrived rather than that nothing looked.

There is no pricing logic here, deliberately. These are counts and measured
costs. What they are worth is a commercial question and belongs nowhere near
the code that answers "what happened".
"""

from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final

from sqlalchemy import DateTime, String, Uuid, bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class Meter:
    """One measurable quantity.

    ``sql`` must bind the tenant and the day window as parameters and never
    format them into the string. It returns exactly one row with one column.

    ``source`` names the table the number comes from, so a reader can check
    it, and so :func:`reconcile` can state what it compared.
    """

    key: str
    label: str
    description: str
    source: str
    sql: str
    #: A quantity that is summed rather than counted. Only affects how a
    #: total across days is labelled, never how it is computed.
    is_sum: bool = False


#: Anything a tenant does that this deployment can count from its own rows.
#:
#: `alerts` and `triages_*` intentionally mirror the definitions
#: `app.services.entitlements` uses for the limits they map to, because two
#: definitions of "a triage" is exactly how a usage screen and a quota screen
#: end up disagreeing in front of a customer.
METERS: Final[tuple[Meter, ...]] = (
    Meter(
        "alerts",
        "Alerts",
        "Alerts created in the window.",
        "alerts",
        "SELECT count(*) FROM alerts WHERE tenant_id = :tenant_id AND created_at >= :start AND created_at < :end",
    ),
    Meter(
        # "By path" is the distinction that matters to an operator: how much
        # of the queue a model touched. An alert carrying AI output is the
        # row a model triage writes, which is the same evidence
        # `entitlements.triages_per_month` counts.
        "triages_model",
        "AI triages",
        "Alerts carrying model-generated triage output.",
        "alerts",
        (
            "SELECT count(*) FROM alerts WHERE tenant_id = :tenant_id AND created_at >= :start AND created_at < :end "
            "AND (ai_summary IS NOT NULL OR ai_score IS NOT NULL)"
        ),
    ),
    Meter(
        "triages_deterministic",
        "Deterministic triages",
        "Alerts resolved without model output: rule verdicts and institutional-memory suppression.",
        "alerts",
        (
            "SELECT count(*) FROM alerts WHERE tenant_id = :tenant_id AND created_at >= :start AND created_at < :end "
            "AND ai_summary IS NULL AND ai_score IS NULL"
        ),
    ),
    Meter(
        "investigations",
        "Investigations",
        "Agent investigation runs started in the window.",
        "investigation_runs",
        "SELECT count(*) FROM investigation_runs WHERE tenant_id = :tenant_id AND created_at >= :start AND created_at < :end",
    ),
    Meter(
        "llm_tokens",
        "LLM tokens",
        "Prompt plus completion tokens recorded against this tenant's runs.",
        "aisoc_run_costs",
        (
            "SELECT COALESCE(SUM(total_prompt_tokens + total_completion_tokens), 0) FROM aisoc_run_costs "
            "WHERE tenant_id = :tenant_text AND recorded_at >= :start AND recorded_at < :end"
        ),
        is_sum=True,
    ),
    Meter(
        "llm_cost_usd",
        "LLM cost (USD)",
        "Measured model spend. Not a price: what the provider charged for the calls this tenant caused.",
        "aisoc_run_costs",
        (
            "SELECT COALESCE(SUM(total_cost_usd), 0) FROM aisoc_run_costs "
            "WHERE tenant_id = :tenant_text AND recorded_at >= :start AND recorded_at < :end"
        ),
        is_sum=True,
    ),
    Meter(
        "actions",
        "Response actions",
        "Response actions recorded in the window, across every approval tier.",
        "aisoc_action_records",
        "SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :tenant_text AND created_at >= :start AND created_at < :end",
    ),
    Meter(
        "actions_executed",
        "Actions executed",
        "Of those, the ones that reached a vendor. 'executed' is the single status that means a vendor was touched.",
        "aisoc_action_records",
        (
            "SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :tenant_text "
            "AND created_at >= :start AND created_at < :end AND status = 'executed'"
        ),
    ),
)

#: Meters that describe the current shape of the deployment rather than
#: activity in a window. Counting them per day would report today's value
#: against every historical day, which is a plausible-looking lie.
POINT_IN_TIME_METERS: Final[tuple[Meter, ...]] = (
    Meter(
        "active_connectors",
        "Active connectors",
        "Enabled data sources right now.",
        "connectors",
        "SELECT count(*) FROM connectors WHERE tenant_id = :tenant_id AND is_enabled",
    ),
    Meter(
        "seats",
        "Seats",
        "Active user accounts right now.",
        "users",
        "SELECT count(*) FROM users WHERE tenant_id = :tenant_id AND is_active",
    ),
)

METERS_BY_KEY: Final[dict[str, Meter]] = {m.key: m for m in (*METERS, *POINT_IN_TIME_METERS)}

#: Meters whose source is not in Postgres. Reported as ``None`` rather than
#: zero, and named here so the API can say *which* meter was not measured and
#: why, instead of leaving a silent gap in the series.
UNMEASURED: Final[dict[str, str]] = {
    "events_ingested": ("counted in the ClickHouse event lake, which runs in the `full` profile. Not measured on a deployment without it."),
}


@dataclass(frozen=True)
class DailyUsage:
    """One tenant, one day, every meter."""

    day: date
    values: dict[str, float | int]

    def as_dict(self) -> dict[str, Any]:
        return {"day": self.day.isoformat(), **self.values}


def _window(day: date) -> tuple[datetime, datetime]:
    """The half-open UTC day ``[start, end)``.

    Half-open so a row landing exactly at midnight is counted once. Counting
    it in both days is how a monthly total exceeds the row count it claims to
    summarise.
    """
    start = datetime(day.year, day.month, day.day, tzinfo=UTC)
    return start, start + timedelta(days=1)


#: Bind types for the four parameters the meters use. Declared rather than
#: inferred because these statements are raw SQL: without a type, the driver
#: is handed a `uuid.UUID` and a timezone-aware `datetime` and has to guess.
#: asyncpg guesses correctly and other drivers do not, which would make the
#: meters work in production and fail in any harness that is not Postgres.
_BIND_TYPES: Final[dict[str, Any]] = {
    "tenant_id": Uuid(as_uuid=True),
    # `aisoc_run_costs` and `aisoc_action_records` store the tenant as TEXT,
    # so those meters bind a string. Two names rather than one cast, because
    # a cast in the SQL would defeat the index on those columns.
    "tenant_text": String(),
    "start": DateTime(timezone=True),
    "end": DateTime(timezone=True),
}


def _statement(sql: str) -> Any:
    """A ``text()`` clause with every parameter it uses explicitly typed."""
    clause = text(sql)
    present = [bindparam(name, type_=kind) for name, kind in _BIND_TYPES.items() if f":{name}" in sql]
    return clause.bindparams(*present) if present else clause


async def measure_day(db: AsyncSession, tenant_id: uuid.UUID, day: date) -> DailyUsage:
    """Every windowed meter for one tenant on one day."""
    start, end = _window(day)
    params = {"tenant_id": tenant_id, "tenant_text": str(tenant_id), "start": start, "end": end}

    values: dict[str, float | int] = {}
    for meter in METERS:
        raw = await db.scalar(_statement(meter.sql), params)
        values[meter.key] = float(raw or 0) if meter.key.endswith("_usd") else int(raw or 0)
    return DailyUsage(day=day, values=values)


async def measure_range(db: AsyncSession, tenant_id: uuid.UUID, start: date, end: date) -> list[DailyUsage]:
    """Daily usage across ``[start, end]`` inclusive."""
    if end < start:
        raise ValueError("end is before start")
    days: list[DailyUsage] = []
    cursor = start
    while cursor <= end:
        days.append(await measure_day(db, tenant_id, cursor))
        cursor += timedelta(days=1)
    return days


async def measure_point_in_time(db: AsyncSession, tenant_id: uuid.UUID) -> dict[str, int]:
    """Connectors and seats as they stand now."""
    values: dict[str, int] = {}
    for meter in POINT_IN_TIME_METERS:
        raw = await db.scalar(_statement(meter.sql), {"tenant_id": tenant_id})
        values[meter.key] = int(raw or 0)
    return values


def totals(days: Sequence[DailyUsage]) -> dict[str, float | int]:
    """Sum each meter across the range.

    Every meter here is additive over disjoint day windows, which is why the
    windows are half-open. A meter that was not additive would have to be
    recomputed over the whole range instead, and none is.
    """
    summed: dict[str, float | int] = {}
    for meter in METERS:
        values = [day.values.get(meter.key, 0) for day in days]
        summed[meter.key] = round(sum(float(v) for v in values), 6) if meter.key.endswith("_usd") else sum(int(v) for v in values)
    return summed


async def reconcile(db: AsyncSession, tenant_id: uuid.UUID, start: date, end: date) -> dict[str, dict[str, Any]]:
    """Compare the daily sum against one query over the whole window.

    This is what makes "metering matches row counts" checkable rather than
    asserted. The per-day path and the whole-window path are different
    queries over the same rows; if the day boundaries drop a row or count one
    twice, these disagree.

    Returns one entry per meter with both figures and whether they agree, so
    a caller reports every mismatch rather than the first.
    """
    days = await measure_range(db, tenant_id, start, end)
    per_day = totals(days)

    whole_start, _ = _window(start)
    _, whole_end = _window(end)
    params = {"tenant_id": tenant_id, "tenant_text": str(tenant_id), "start": whole_start, "end": whole_end}

    report: dict[str, dict[str, Any]] = {}
    for meter in METERS:
        raw = await db.scalar(_statement(meter.sql), params)
        direct = float(raw or 0) if meter.key.endswith("_usd") else int(raw or 0)
        summed = per_day[meter.key]
        agrees = abs(float(direct) - float(summed)) < 1e-6
        report[meter.key] = {"source": meter.source, "per_day_total": summed, "single_query": direct, "agrees": agrees}
    return report


def to_csv(
    *,
    tenant_id: uuid.UUID,
    org_name: str | None,
    days: Sequence[DailyUsage],
    point_in_time: dict[str, int],
) -> str:
    """The monthly CSV.

    Carries a header block naming the tenant, the organisation and the
    generation time, because a bare grid of numbers in somebody's downloads
    folder cannot answer what it is about. Unmeasured meters are listed by
    name with their reason rather than omitted, so a reader can tell a gap
    from a zero.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")

    writer.writerow(["# AiSOC usage export"])
    writer.writerow(["# tenant", str(tenant_id)])
    writer.writerow(["# organisation", org_name or "(none)"])
    writer.writerow(["# generated", datetime.now(UTC).isoformat()])
    for key, reason in UNMEASURED.items():
        writer.writerow([f"# not measured: {key}", reason])
    writer.writerow([])

    columns = [m.key for m in METERS]
    writer.writerow(["day", *columns])
    for day in days:
        writer.writerow([day.day.isoformat(), *[day.values.get(key, 0) for key in columns]])

    summed = totals(days)
    writer.writerow(["total", *[summed[key] for key in columns]])
    writer.writerow([])

    writer.writerow(["# point-in-time, at generation"])
    for meter in POINT_IN_TIME_METERS:
        writer.writerow([meter.key, point_in_time.get(meter.key, 0)])

    return buffer.getvalue()


def month_bounds(year: int, month: int) -> tuple[date, date]:
    """First and last day of a calendar month."""
    if not 1 <= month <= 12:
        raise ValueError("month must be 1-12")
    first = date(year, month, 1)
    last = date(year + (month == 12), 1 if month == 12 else month + 1, 1) - timedelta(days=1)
    return first, last
