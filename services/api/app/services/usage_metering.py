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

Why the triage meters read `investigation_runs` and not `alerts`
-----------------------------------------------------------------
Because `alerts.ai_summary` and `alerts.ai_score` do not record which path
produced the verdict. `persist_auto_triage` writes them from one statement
on both the model and the deterministic path, so reading them counted a
deployment with no LLM configured at all as 100% AI-triaged. The path is
recorded — `model_used` on the run — and that is what these meters read.

There is no pricing logic here, deliberately. These are counts and measured
costs. What they are worth is a commercial question and belongs nowhere near
the code that answers "what happened".
"""

from __future__ import annotations

import csv
import io
import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, Final

from sqlalchemy import DateTime, String, Uuid, bindparam, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.clickhouse import LakeQueryError, LakeQueryNotConfiguredError, execute_lake_query

logger = logging.getLogger("aisoc.usage_metering")

#: What `services/agents` stamps into `investigation_runs.model_used` for a
#: run the Kafka auto-triage worker started: `kafka:auto_triage:<tier>`,
#: where the tier is `llm` or `deterministic`
#: (`services/agents/app/investigator/ledger.py`, `persist_auto_triage`).
#:
#: Pinned against that producer by
#: `TestTheProducerStillWritesWhatTheseMetersRead`, because the two services
#: both name their top-level package `app` and cannot import each other.
AUTO_TRIAGE_PREFIX: Final[str] = "kafka:auto_triage:"
DETERMINISTIC_RUN: Final[str] = f"{AUTO_TRIAGE_PREFIX}deterministic"

#: The approval tier `services/actions` grades a submission at, recorded on
#: the action row at submit time. `automatic` is the only value that means
#: the platform would run it unattended; everything else needed a human or
#: was refused outright.
AUTOMATIC_TIER: Final[str] = "automatic"

#: The terminal status an action reaches when its executor ran and
#: succeeded. `ActionStatus` has no `executed` member and never had one,
#: which is why the meter that filtered on it could only return zero.
EXECUTED_STATUS: Final[str] = "completed"


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
        # of the queue a model touched.
        #
        # Runs, not alerts. An alert can be re-triaged, and an alert that
        # arrived before auto-triage was switched on has no run at all, so
        # these two never summed to the alert count however they were
        # written. What they do partition exactly, with `investigations`,
        # is `investigation_runs`.
        "triages_model",
        "AI triages",
        "Auto-triage runs that reached a model.",
        "investigation_runs",
        (
            "SELECT count(*) FROM investigation_runs WHERE tenant_id = :tenant_id "
            "AND created_at >= :start AND created_at < :end "
            "AND model_used LIKE :auto_triage_prefix || '%' AND model_used <> :deterministic_run"
        ),
    ),
    Meter(
        "triages_deterministic",
        "Deterministic triages",
        "Auto-triage runs answered without a model: rule verdicts and institutional-memory suppression.",
        "investigation_runs",
        (
            "SELECT count(*) FROM investigation_runs WHERE tenant_id = :tenant_id "
            "AND created_at >= :start AND created_at < :end AND model_used = :deterministic_run"
        ),
    ),
    Meter(
        # Auto-triage opens one of these per alert, so counting every row
        # made this a second alert count wearing a different label and
        # buried the analyst-driven runs an operator comes here to see.
        "investigations",
        "Investigations",
        "Investigation runs that are not auto-triage: an analyst asked for these, or an escalation did.",
        "investigation_runs",
        (
            "SELECT count(*) FROM investigation_runs WHERE tenant_id = :tenant_id "
            "AND created_at >= :start AND created_at < :end "
            "AND (model_used IS NULL OR model_used NOT LIKE :auto_triage_prefix || '%')"
        ),
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
        "Response actions recorded in the window, at every approval tier.",
        "aisoc_action_records",
        "SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :tenant_text AND created_at >= :start AND created_at < :end",
    ),
    Meter(
        "actions_executed",
        "Actions executed",
        "Of those, the ones whose executor ran and succeeded.",
        "aisoc_action_records",
        (
            "SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :tenant_text "
            "AND created_at >= :start AND created_at < :end AND status = :executed_status"
        ),
    ),
    # The three tier meters below partition `actions` exactly, which is what
    # makes "unrecorded" a meter rather than a silence. A row written before
    # `approval_tier` existed is neither automatic nor human-gated, and
    # folding it into either would either report unsupervised actions
    # nobody graded or invent analyst work that never happened.
    Meter(
        "actions_automatic",
        "Automatic actions",
        "Graded as runnable without a human, under the tenant's autonomy tier.",
        "aisoc_action_records",
        (
            "SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :tenant_text "
            "AND created_at >= :start AND created_at < :end AND approval_tier = :automatic_tier"
        ),
    ),
    Meter(
        "actions_human_gated",
        "Human-gated actions",
        "Graded as needing a human, or refused by the action's contract. Anything the platform would not run unattended.",
        "aisoc_action_records",
        (
            "SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :tenant_text "
            "AND created_at >= :start AND created_at < :end "
            "AND approval_tier IS NOT NULL AND approval_tier <> '' AND approval_tier <> :automatic_tier"
        ),
    ),
    Meter(
        "actions_tier_unrecorded",
        "Actions with no recorded tier",
        "Submitted before the approval tier was recorded on the row. Counted so the three tiers still sum to the total.",
        "aisoc_action_records",
        (
            "SELECT count(*) FROM aisoc_action_records WHERE tenant_id = :tenant_text "
            "AND created_at >= :start AND created_at < :end AND (approval_tier IS NULL OR approval_tier = '')"
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

#: The one meter whose source is not Postgres, and the reason it can be
#: absent. Reported as ``None`` rather than zero on a deployment without the
#: lake, and named here so the API can say *which* meter was not measured
#: and why, instead of leaving a silent gap in the series.
#:
#: :func:`unmeasured` is what callers should use: this dictionary describes
#: the *possible* gap, and whether it is a gap today depends on whether the
#: lake is actually configured.
UNMEASURABLE_WITHOUT: Final[dict[str, str]] = {
    "events_ingested": ("counted in the ClickHouse event lake, which runs in the `full` profile. Not measured on a deployment without it."),
}

EVENTS_INGESTED = Meter(
    "events_ingested",
    "Events ingested",
    "Normalised events written to the lake, by the time AiSOC received them.",
    "aisoc.raw_events",
    # Grouped in ClickHouse rather than one query per day: this is a
    # columnar scan over a partitioned table, and thirty of them to draw
    # one month would be thirty scans.
    (
        "SELECT toDate(ingest_time) AS day, count() AS events FROM aisoc.raw_events "
        "WHERE tenant_id = %(tenant_id)s AND ingest_time >= %(start)s AND ingest_time < %(end)s "
        "GROUP BY day ORDER BY day"
    ),
    is_sum=True,
)

#: The same window as one scan, for :func:`reconcile`. Deliberately not
#: ``sum()`` over the grouped result, which would be the daily path
#: compared against a copy of itself.
_EVENTS_INGESTED_WHOLE_WINDOW: Final[str] = (
    "SELECT count() FROM aisoc.raw_events WHERE tenant_id = %(tenant_id)s AND ingest_time >= %(start)s AND ingest_time < %(end)s"
)


def lake_is_configured() -> bool:
    """Whether this deployment has an event lake to count.

    A separate function rather than an inline settings read so a caller can
    distinguish "the lake is absent" from "the lake is present and errored",
    and so the tests can drive both without a container.
    """
    return bool((settings.CLICKHOUSE_HOST or "").strip())


def unmeasured() -> dict[str, str]:
    """The meters this deployment cannot take, with the reason for each.

    Empty on a deployment where everything is measurable. The API renders
    whatever is in here as "not measured" and never as ``0``.
    """
    return {} if lake_is_configured() else dict(UNMEASURABLE_WITHOUT)


async def measure_events_ingested(tenant_id: uuid.UUID, start: date, end: date) -> dict[date, int] | None:
    """Lake events per day across ``[start, end]`` inclusive.

    ``None`` means the lake is not deployed or did not answer, which every
    surface renders as "not measured". Returning ``0`` for an unreachable
    store would tell an operator their connectors had stopped.

    Days with no events are present with a count of ``0``: an absent day
    reads as a gap in a chart, and here it really is a measured zero.

    The lake is a ``ReplacingMergeTree`` keyed on the event id, so a
    connector that replays an event writes a second row which a background
    merge later collapses. This counts rows as stored, which can therefore
    exceed the number of distinct events until that merge runs.
    """
    if not lake_is_configured():
        return None

    window_start, _ = _window(start)
    _, window_end = _window(end)
    try:
        result = await execute_lake_query(
            EVENTS_INGESTED.sql,
            params={"tenant_id": str(tenant_id), "start": window_start, "end": window_end},
        )
    except (LakeQueryError, LakeQueryNotConfiguredError) as exc:
        # Not measured, not zero. A lake that is deployed and unreachable is
        # an operational fault, so it is logged at warning rather than
        # swallowed, and the surface still says "not measured".
        logger.warning("usage_metering.events_ingested_unavailable tenant=%s error=%s", tenant_id, exc)
        return None

    counted = {_as_date(row[0]): int(row[1]) for row in result.rows}
    series: dict[date, int] = {}
    cursor = start
    while cursor <= end:
        series[cursor] = counted.get(cursor, 0)
        cursor += timedelta(days=1)
    return series


async def count_events_ingested(tenant_id: uuid.UUID, start: date, end: date) -> int | None:
    """One scan over the whole window, for :func:`reconcile` to compare."""
    if not lake_is_configured():
        return None
    window_start, _ = _window(start)
    _, window_end = _window(end)
    try:
        result = await execute_lake_query(
            _EVENTS_INGESTED_WHOLE_WINDOW,
            params={"tenant_id": str(tenant_id), "start": window_start, "end": window_end},
        )
    except (LakeQueryError, LakeQueryNotConfiguredError) as exc:
        logger.warning("usage_metering.events_ingested_unavailable tenant=%s error=%s", tenant_id, exc)
        return None
    return int(result.rows[0][0]) if result.rows else 0


def _as_date(value: Any) -> date:
    """ClickHouse returns a ``date`` for ``toDate``; drivers have differed."""
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


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
    # Bound rather than written into the statement, for the same reason the
    # tenant is: these are the values that decide what a meter counts, and a
    # meter whose discriminator is a string literal in SQL is one a reader
    # has to diff against the producer by eye.
    "auto_triage_prefix": String(),
    "deterministic_run": String(),
    "automatic_tier": String(),
    "executed_status": String(),
}

#: Every discriminator the windowed meters bind, beside the tenant and the
#: window. Constant per deployment, so they are assembled once here rather
#: than threaded through each call site.
_DISCRIMINATORS: Final[dict[str, str]] = {
    "auto_triage_prefix": AUTO_TRIAGE_PREFIX,
    "deterministic_run": DETERMINISTIC_RUN,
    "automatic_tier": AUTOMATIC_TIER,
    "executed_status": EXECUTED_STATUS,
}


def _statement(sql: str) -> Any:
    """A ``text()`` clause with every parameter it uses explicitly typed."""
    clause = text(sql)
    present = [bindparam(name, type_=kind) for name, kind in _BIND_TYPES.items() if f":{name}" in sql]
    return clause.bindparams(*present) if present else clause


async def measure_day(db: AsyncSession, tenant_id: uuid.UUID, day: date) -> DailyUsage:
    """Every windowed Postgres meter for one tenant on one day.

    `events_ingested` is not here: it lives in ClickHouse and is counted
    for a whole range in one grouped scan by
    :func:`measure_events_ingested`.
    """
    start, end = _window(day)
    params = {"tenant_id": tenant_id, "tenant_text": str(tenant_id), "start": start, "end": end, **_DISCRIMINATORS}

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
    # `events_ingested` is summed only when it was measured, so a total of
    # `0` is never printed for a meter nobody took.
    metered = [*METERS, EVENTS_INGESTED] if any(EVENTS_INGESTED.key in day.values for day in days) else list(METERS)
    for meter in metered:
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
    params = {"tenant_id": tenant_id, "tenant_text": str(tenant_id), "start": whole_start, "end": whole_end, **_DISCRIMINATORS}

    report: dict[str, dict[str, Any]] = {}
    for meter in METERS:
        raw = await db.scalar(_statement(meter.sql), params)
        direct = float(raw or 0) if meter.key.endswith("_usd") else int(raw or 0)
        summed = per_day[meter.key]
        agrees = abs(float(direct) - float(summed)) < 1e-6
        report[meter.key] = {"source": meter.source, "per_day_total": summed, "single_query": direct, "agrees": agrees}

    # The lake meter gets the same treatment, and it needs it most: its
    # daily figures come from a `GROUP BY toDate(...)` whose bucketing is
    # ClickHouse's rather than this module's, so a timezone disagreement
    # between the two shows up here and nowhere else.
    whole_window = await count_events_ingested(tenant_id, start, end)
    if whole_window is not None:
        series = await measure_events_ingested(tenant_id, start, end)
        per_day_events = sum((series or {}).values())
        report[EVENTS_INGESTED.key] = {
            "source": EVENTS_INGESTED.source,
            "per_day_total": per_day_events,
            "single_query": whole_window,
            "agrees": per_day_events == whole_window,
        }
    return report


def _columns(days: Sequence[DailyUsage]) -> list[str]:
    """The meter columns a grid should carry.

    `events_ingested` appears only when it was measured. A column of zeros
    for a meter nobody took is the exact confusion the "not measured" line
    exists to prevent, and it would be worse inside a grid than beside it.
    """
    columns = [m.key for m in METERS]
    if any(EVENTS_INGESTED.key in day.values for day in days):
        columns.append(EVENTS_INGESTED.key)
    return columns


def _grid(writer: Any, days: Sequence[DailyUsage], *, total_label: str) -> None:
    columns = _columns(days)
    writer.writerow(["day", *columns])
    for day in days:
        writer.writerow([day.day.isoformat(), *[day.values.get(key, 0) for key in columns]])
    summed = totals(days)
    writer.writerow([total_label, *[summed.get(key, 0) for key in columns]])


def to_csv(
    *,
    tenant_id: uuid.UUID,
    org_name: str | None,
    days: Sequence[DailyUsage],
    point_in_time: dict[str, int],
) -> str:
    """The monthly CSV for one tenant.

    Carries a header block naming the tenant, the organisation and the
    generation time, because a bare grid of numbers in somebody's downloads
    folder cannot answer what it is about. Unmeasured meters are listed by
    name with their reason rather than omitted, so a reader can tell a gap
    from a zero.

    An operator billing a portfolio wants :func:`organization_to_csv`
    instead. This file names an organisation and covers one tenant, which
    is the right shape only when they are the same thing.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")

    writer.writerow(["# AiSOC usage export"])
    writer.writerow(["# tenant", str(tenant_id)])
    writer.writerow(["# organisation", org_name or "(none)"])
    writer.writerow(["# generated", datetime.now(UTC).isoformat()])
    for key, reason in unmeasured().items():
        writer.writerow([f"# not measured: {key}", reason])
    writer.writerow([])

    _grid(writer, days, total_label="total")
    writer.writerow([])

    writer.writerow(["# point-in-time, at generation"])
    for meter in POINT_IN_TIME_METERS:
        writer.writerow([meter.key, point_in_time.get(meter.key, 0)])

    return buffer.getvalue()


@dataclass(frozen=True)
class TenantSection:
    """One managed tenant's slice of an organisation export."""

    tenant_id: uuid.UUID
    tenant_name: str | None
    days: list[DailyUsage]
    point_in_time: dict[str, int]

    @property
    def totals(self) -> dict[str, float | int]:
        return totals(self.days)


async def measure_organization(
    db: AsyncSession,
    *,
    tenant_ids: Sequence[uuid.UUID],
    start: date,
    end: date,
    names: dict[uuid.UUID, str] | None = None,
) -> list[TenantSection]:
    """Daily usage for each tenant in a portfolio.

    Takes the tenant list rather than an organisation id, and that is the
    whole safety property: the list comes from
    :func:`app.services.org_scope.resolve_portfolio_scope`, which is the
    one place that decides which tenants a principal may read across. A
    function here that resolved "every tenant in org X" would be a second
    answer to that question, and the member-level grants would not be in
    it.

    An empty list returns an empty export rather than every tenant. Every
    cross-tenant leak in this codebase took the shape of an absent scope
    treated as "no filter".
    """
    sections: list[TenantSection] = []
    for tenant_id in tenant_ids:
        days = await measure_range(db, tenant_id, start, end)
        if lake_is_configured():
            events = await measure_events_ingested(tenant_id, start, end)
            if events is not None:
                for day in days:
                    day.values[EVENTS_INGESTED.key] = events.get(day.day, 0)
        sections.append(
            TenantSection(
                tenant_id=tenant_id,
                tenant_name=(names or {}).get(tenant_id),
                days=days,
                point_in_time=await measure_point_in_time(db, tenant_id),
            )
        )
    return sections


def organization_to_csv(*, org_name: str | None, sections: Sequence[TenantSection]) -> str:
    """The portfolio CSV: one grid per managed tenant, then a roll-up.

    The roll-up is the row an operator invoices against, so it is computed
    from the sections rather than asserted: a tenant missing from the
    grids above is missing from the total below, and the two cannot
    disagree.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")

    writer.writerow(["# AiSOC usage export (organisation)"])
    writer.writerow(["# organisation", org_name or "(none)"])
    writer.writerow(["# tenants", len(sections)])
    writer.writerow(["# generated", datetime.now(UTC).isoformat()])
    for key, reason in unmeasured().items():
        writer.writerow([f"# not measured: {key}", reason])
    writer.writerow([])

    for section in sections:
        writer.writerow(["# tenant", str(section.tenant_id), section.tenant_name or ""])
        _grid(writer, section.days, total_label="total")
        for meter in POINT_IN_TIME_METERS:
            writer.writerow([meter.key, section.point_in_time.get(meter.key, 0)])
        writer.writerow([])

    rolled: list[DailyUsage] = [day for section in sections for day in section.days]
    columns = _columns(rolled)
    summed = totals(rolled)
    writer.writerow(["# portfolio"])
    writer.writerow(["scope", *columns])
    writer.writerow(["portfolio total", *[summed.get(key, 0) for key in columns]])
    for meter in POINT_IN_TIME_METERS:
        writer.writerow([meter.key, sum(section.point_in_time.get(meter.key, 0) for section in sections)])

    return buffer.getvalue()


def month_bounds(year: int, month: int) -> tuple[date, date]:
    """First and last day of a calendar month."""
    if not 1 <= month <= 12:
        raise ValueError("month must be 1-12")
    first = date(year, month, 1)
    last = date(year + (month == 12), 1 if month == 12 else month + 1, 1) - timedelta(days=1)
    return first, last
