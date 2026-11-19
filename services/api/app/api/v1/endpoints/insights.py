"""SOC Insights aggregator (T3.1 — v8.0 parallel team).

``GET /v1/insights/soc`` returns a single, deterministic snapshot that
backs the SOC Insights dashboard at
``apps/web/src/app/(app)/dashboards/soc-insights/page.tsx``.

The dashboard answers a small set of executive-readout questions in one
hop:

    * **MTTA** — mean time-to-acknowledge (alert.created_at →
      alert.first_seen_at), captured for the current window and the
      previous window so the UI can render a delta.
    * **MTTR** — mean time-to-resolve (alert.created_at →
      alert.resolved_at).
    * **FP rate** — false-positive disposition over dispositioned
      alerts.
    * **Alerts/day** — average alerts seen per day across the window.
    * **Cases/day** — average cases opened per day across the window.
    * **Agent cost per investigation** — total LLM USD spend (from
      ``aisoc_run_costs``) divided by distinct ``run_id`` count over
      the window.
    * **Analyst hours saved** — closed cases × the named
      ``MANUAL_INVESTIGATION_MINUTES`` heuristic.

Every tile also returns a 24-bucket sparkline for the window so the UI
can render an inline trendline without a follow-up request. Three grouped
queries cover both comparison windows and return at most 25 rows each,
independent of the number of alerts, cases or cost records.

Tenant scoping
--------------

Auth + tenant resolution match ``metrics.py`` and ``costs.py``: we read
``current_user.tenant_id`` and filter every aggregate by it. We never
trust a query-string tenant override.

Why a new router?
-----------------

The existing ``metrics.py`` already exposes a ``/metrics/soc`` payload,
but that route is shaped around the v1.x analyst dashboard (ATT&CK
heatmap + calibration curve). The v8.0 SOC Insights dashboard wants a
different *shape* — seven uniform tiles with delta + sparkline — so we
keep the two endpoints distinct rather than overloading
``/metrics/soc``.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import Integer, case, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from app.api.v1.deps import AuthUser, DBSession
from app.db.best_effort import savepoint
from app.models.alert import Alert
from app.models.case import Case
from app.services import case_status
from app.services.alert_disposition import decided_filter

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/insights", tags=["insights"])


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# heuristic: closed cases × avg manual investigation time (45 min)
#
# Calibrated against community benchmarks for analyst tier-1 triage on a
# medium-severity incident. Surfaced as a tile assumption in the docs so
# operators can recalibrate against their own time-and-motion study and
# re-evaluate the "hours saved" number.
MANUAL_INVESTIGATION_MINUTES: int = 45

# Sparkline bucket count. 24 keeps the SVG simple (one polyline, no axes)
# while remaining readable at a tile's typical 80-100px width.
_SPARKLINE_BUCKETS: int = 24

# Hard bound on the window so a tampered query-string can't trigger a
# 365-day full-table scan. The dashboard only exposes 24h / 7d / 30d.
_VALID_WINDOWS: dict[str, int] = {"24h": 1, "7d": 7, "30d": 30}


# ---------------------------------------------------------------------------
# Pydantic response model
# ---------------------------------------------------------------------------


WindowLiteral = Literal["24h", "7d", "30d"]


class InsightSparkline(BaseModel):
    """A bucketed time-series the UI renders as a tiny inline SVG."""

    points: list[float] = Field(
        default_factory=list,
        description="Bucket values, oldest → newest. Length == 24.",
    )


class InsightTile(BaseModel):
    """One tile on the SOC Insights dashboard."""

    key: str = Field(description="Stable identifier — used as a React key.")
    label: str = Field(description="Human-readable tile heading.")
    value: float = Field(
        description=(
            "Headline metric for the current window. Read it with `sample_count`: a mean "
            "over zero rows is reported as 0.0 and is *not* a measurement. The mean is not "
            "nullable because that is a breaking response change for every existing client, "
            "which is the same decision `/metrics/soc` took with `mttd_sample_count`."
        ),
    )
    sample_count: int | None = Field(
        default=None,
        description="Rows behind `value`. A mean over three and over three thousand differ.",
    )
    unit: str = Field(
        description=(
            "Display unit. The UI picks formatting per unit "
            "(``hours`` → 1 decimal, ``pct`` → percentage, ``usd`` → "
            "currency, ``count`` → integer, ``hours_saved`` → integer)."
        )
    )
    previous_value: float = Field(
        description=("Value of the same metric over the immediately preceding window of equal length. Used to compute the delta.")
    )
    delta_pct: float | None = Field(
        default=None,
        description=(
            "Percentage change vs ``previous_value``. ``None`` when the "
            "previous window had no data (so the percent change is "
            "undefined rather than misleadingly infinite)."
        ),
    )
    sparkline: InsightSparkline = Field(default_factory=InsightSparkline)


class SOCInsightsResponse(BaseModel):
    """Aggregated SOC insights payload."""

    window: WindowLiteral
    generated_at: datetime
    tenant_id: uuid.UUID
    tiles: list[InsightTile]
    # The named manual-investigation constant is surfaced in the response
    # so the dashboard can show "assumes 45 min per case" beside the
    # hours-saved tile without hard-coding the same number client-side.
    manual_investigation_minutes: int = MANUAL_INVESTIGATION_MINUTES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _window_to_timedelta(window: str) -> timedelta:
    """Return the timedelta for the named window. Raises ``HTTPException``
    on an unrecognised value so callers can't trip a default scan."""
    if window not in _VALID_WINDOWS:
        raise HTTPException(
            status_code=400,
            detail=f"window must be one of {sorted(_VALID_WINDOWS)}",
        )
    return timedelta(days=_VALID_WINDOWS[window])


def _delta_pct(current: float | None, previous: float | None) -> float | None:
    """Percent change, or ``None`` when there is no honest one to give.

    Three cases return `None` rather than a number: an undefined division
    by a zero baseline, and either side being unmeasured. That last one is
    the important addition — treating an unmeasured window as zero turns
    "we did not measure this before" into a 100% improvement.
    """
    if current is None or previous is None or previous == 0:
        return None
    return round(((current - previous) / previous) * 100.0, 2)


@dataclass
class _AlertTotals:
    count: int = 0
    mtta_sum: Decimal = Decimal(0)
    mtta_n: int = 0
    mttr_sum: Decimal = Decimal(0)
    mttr_n: int = 0
    decided: int = 0
    false_positives: int = 0

    @property
    def mtta(self) -> float:
        return round(float(self.mtta_sum / self.mtta_n), 2) if self.mtta_n else 0.0

    @property
    def mttr(self) -> float:
        return round(float(self.mttr_sum / self.mttr_n), 2) if self.mttr_n else 0.0

    @property
    def fp_rate(self) -> float:
        return round(self.false_positives / self.decided, 4) if self.decided else 0.0


@dataclass
class _CaseTotals:
    count: int = 0
    closed: int = 0


@dataclass
class _CostTotals:
    cost: float = 0.0
    runs: int = 0


def _bucket(column: Any, start: datetime, end: datetime) -> ColumnElement[int]:
    """One previous-window group and 24 current-window groups.

    The WHERE clause bounds the read to two windows. Folding the entire
    previous window into -1 avoids transferring buckets we never display.
    """
    bucket_seconds = (end - start).total_seconds() / _SPARKLINE_BUCKETS
    return (
        case(
            (column < start, -1),
            else_=func.floor(func.extract("epoch", column - start) / bucket_seconds),
        )
        .cast(Integer)
        .label("bucket")
    )


async def _alert_aggregates(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    prev_start: datetime,
    start: datetime,
    end: datetime,
) -> tuple[_AlertTotals, _AlertTotals, list[float]]:
    """Aggregate counts, duration numerators and verdicts in one bounded read."""
    bucket = _bucket(Alert.created_at, start, end)
    rows = (
        await db.execute(
            select(
                bucket,
                func.count().label("count"),
                func.sum(func.extract("epoch", Alert.first_seen_at - Alert.created_at) / 3600).label("mtta_sum"),
                func.count(Alert.first_seen_at).label("mtta_n"),
                func.sum(func.extract("epoch", Alert.resolved_at - Alert.created_at) / 3600).label("mttr_sum"),
                func.count(Alert.resolved_at).label("mttr_n"),
                func.count().filter(decided_filter(Alert.disposition)).label("decided"),
                func.count().filter(Alert.disposition == "false_positive").label("false_positives"),
            )
            .where(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= prev_start,
                Alert.created_at < end,
            )
            .group_by(bucket)
        )
    ).mappings()
    current, previous = _AlertTotals(), _AlertTotals()
    sparkline = [0.0] * _SPARKLINE_BUCKETS
    for row in rows:
        idx = int(row["bucket"])
        totals = previous if idx == -1 else current
        totals.count += int(row["count"])
        # Add numerators and denominators, not means: unevenly populated
        # buckets must retain their weight in the window-wide average. Keep
        # PostgreSQL numeric sums as Decimal until the final rounding step.
        totals.mtta_sum += row["mtta_sum"] or Decimal(0)
        totals.mtta_n += int(row["mtta_n"])
        totals.mttr_sum += row["mttr_sum"] or Decimal(0)
        totals.mttr_n += int(row["mttr_n"])
        totals.decided += int(row["decided"])
        totals.false_positives += int(row["false_positives"])
        if idx >= 0:
            sparkline[idx] = float(row["count"])
    return current, previous, sparkline


async def _case_aggregates(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    prev_start: datetime,
    start: datetime,
    end: datetime,
) -> tuple[_CaseTotals, _CaseTotals, list[float]]:
    bucket = _bucket(Case.created_at, start, end)
    rows = (
        await db.execute(
            select(
                bucket,
                func.count().label("count"),
                # Use the same terminal-state vocabulary in both windows;
                # resolved cases still await closure on an analyst's queue.
                func.count().filter(Case.status.in_(case_status.CLOSED_STATUSES)).label("closed"),
            )
            .where(
                Case.tenant_id == tenant_id,
                Case.created_at >= prev_start,
                Case.created_at < end,
            )
            .group_by(bucket)
        )
    ).mappings()
    current, previous = _CaseTotals(), _CaseTotals()
    sparkline = [0.0] * _SPARKLINE_BUCKETS
    for row in rows:
        idx = int(row["bucket"])
        totals = previous if idx == -1 else current
        totals.count += int(row["count"])
        totals.closed += int(row["closed"])
        if idx >= 0:
            sparkline[idx] = float(row["count"])
    return current, previous, sparkline


async def _cost_aggregates(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    prev_start: datetime,
    start: datetime,
    end: datetime,
) -> tuple[_CostTotals, _CostTotals, list[float]]:
    """Measured spend, distinct runs and spend buckets from one optional read.

    Scope costs through their investigation: historical cost writers also
    used tenant aliases, while the investigation owns the authenticated
    tenant UUID. A run has one started_at, so it belongs to exactly one
    bucket even when several model-cost records contribute to its spend.

    Materialize the permitted runs before the text-key join. With RLS on
    both tables, cardinality underestimation otherwise allows a nested-loop
    plan that repeatedly scans runs and evaluates their visibility policy
    for each cost record. This keeps both policies in force while evaluating
    the run filter once, regardless of the join plan chosen afterwards.
    """
    sql = text(
        """
        WITH scoped_runs AS MATERIALIZED (
            SELECT r.id::text AS run_id, r.started_at
            FROM investigation_runs r
            WHERE r.tenant_id = :tenant_id
              AND r.started_at >= :prev_start
              AND r.started_at < :end_at
        )
        SELECT CASE WHEN r.started_at < :start_at THEN -1
                    ELSE FLOOR(EXTRACT(EPOCH FROM (r.started_at - :start_at))
                               / :bucket_seconds)::integer END AS bucket,
               COALESCE(SUM(c.measured_cost_usd), 0.0) AS cost,
               COUNT(DISTINCT c.run_id) AS runs
        FROM scoped_runs r
        JOIN aisoc_run_costs c ON c.run_id = r.run_id
        GROUP BY 1
        """
    )
    current, previous = _CostTotals(), _CostTotals()
    sparkline = [0.0] * _SPARKLINE_BUCKETS
    try:
        # Catching a PostgreSQL statement error alone leaves the surrounding
        # transaction aborted. Roll back only this optional read so the
        # request's session and its later work remain usable.
        async with savepoint(db):
            rows = (
                await db.execute(
                    sql,
                    {
                        "tenant_id": tenant_id,
                        "prev_start": prev_start,
                        "start_at": start,
                        "end_at": end,
                        "bucket_seconds": (end - start).total_seconds() / _SPARKLINE_BUCKETS,
                    },
                )
            ).mappings()
            for row in rows:
                idx = int(row["bucket"])
                totals = previous if idx == -1 else current
                totals.cost += float(row["cost"])
                totals.runs += int(row["runs"])
                if idx >= 0:
                    sparkline[idx] = float(row["cost"])
    except SQLAlchemyError:
        logger.debug("insights.cost_aggregate_unavailable", exc_info=True)
        return _CostTotals(), _CostTotals(), [0.0] * _SPARKLINE_BUCKETS
    return current, previous, sparkline


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/soc",
    response_model=SOCInsightsResponse,
    summary="SOC Insights dashboard aggregate (T3.1)",
)
async def get_soc_insights(
    user: AuthUser,
    db: DBSession,
    window: WindowLiteral = Query(
        "24h",
        description="Rolling window. One of 24h, 7d, 30d.",
    ),
) -> SOCInsightsResponse:
    """Return the seven-tile SOC Insights payload for the tenant.

    Tenant scoping is enforced by ``current_user.tenant_id`` plus an
    explicit ``tenant_id`` predicate in every aggregate, so the payload
    is safe to render for any role that can read the dashboard.
    """
    tenant_id = user.tenant_id
    now = datetime.now(UTC)
    delta = _window_to_timedelta(window)
    start = now - delta
    prev_start = start - delta
    window_days = max(_VALID_WINDOWS[window], 1)

    alerts, prev_alerts, alert_spark = await _alert_aggregates(db, tenant_id, prev_start, start, now)
    cases, prev_cases, case_spark = await _case_aggregates(db, tenant_id, prev_start, start, now)
    costs, prev_costs, cost_spark = await _cost_aggregates(db, tenant_id, prev_start, start, now)

    alerts_per_day = round(alerts.count / window_days, 2)
    cases_per_day = round(cases.count / window_days, 2)
    prev_alerts_per_day = round(prev_alerts.count / window_days, 2)
    prev_cases_per_day = round(prev_cases.count / window_days, 2)

    cost_per_inv = round(costs.cost / costs.runs, 4) if costs.runs else 0.0
    prev_cost_per_inv = round(prev_costs.cost / prev_costs.runs, 4) if prev_costs.runs else 0.0

    hours_saved = round((cases.closed * MANUAL_INVESTIGATION_MINUTES) / 60.0, 2)
    prev_hours_saved = round((prev_cases.closed * MANUAL_INVESTIGATION_MINUTES) / 60.0, 2)

    tiles: list[InsightTile] = [
        InsightTile(
            key="mtta",
            label="MTTA",
            value=alerts.mtta,
            sample_count=alerts.mtta_n,
            unit="hours",
            previous_value=prev_alerts.mtta,
            delta_pct=_delta_pct(
                alerts.mtta if alerts.mtta_n else None,
                prev_alerts.mtta if prev_alerts.mtta_n else None,
            ),
            sparkline=InsightSparkline(points=alert_spark),
        ),
        InsightTile(
            key="mttr",
            label="MTTR",
            value=alerts.mttr,
            sample_count=alerts.mttr_n,
            unit="hours",
            previous_value=prev_alerts.mttr,
            delta_pct=_delta_pct(
                alerts.mttr if alerts.mttr_n else None,
                prev_alerts.mttr if prev_alerts.mttr_n else None,
            ),
            sparkline=InsightSparkline(points=alert_spark),
        ),
        InsightTile(
            key="fp_rate",
            label="FP Rate",
            value=alerts.fp_rate,
            sample_count=alerts.decided,
            unit="pct",
            previous_value=prev_alerts.fp_rate,
            delta_pct=_delta_pct(
                alerts.fp_rate if alerts.decided else None,
                prev_alerts.fp_rate if prev_alerts.decided else None,
            ),
            sparkline=InsightSparkline(points=alert_spark),
        ),
        InsightTile(
            key="alerts_per_day",
            label="Alerts / day",
            value=alerts_per_day,
            unit="count",
            previous_value=prev_alerts_per_day,
            delta_pct=_delta_pct(alerts_per_day, prev_alerts_per_day),
            sparkline=InsightSparkline(points=alert_spark),
        ),
        InsightTile(
            key="cases_per_day",
            label="Cases / day",
            value=cases_per_day,
            unit="count",
            previous_value=prev_cases_per_day,
            delta_pct=_delta_pct(cases_per_day, prev_cases_per_day),
            sparkline=InsightSparkline(points=case_spark),
        ),
        InsightTile(
            key="agent_cost_per_investigation",
            label="Agent cost / investigation",
            value=cost_per_inv,
            # A mean over zero investigations is unmeasured, not free. A
            # deployment that placed no model call at all rendered "$0.000",
            # which is the most flattering number this product can print and
            # describes a measurement nobody took. `/costs` on the same
            # stack already got this right.
            sample_count=costs.runs,
            unit="usd",
            previous_value=prev_cost_per_inv,
            delta_pct=_delta_pct(
                cost_per_inv if costs.runs else None,
                prev_cost_per_inv if prev_costs.runs else None,
            ),
            sparkline=InsightSparkline(points=cost_spark),
        ),
        InsightTile(
            key="analyst_hours_saved",
            label="Analyst hours saved",
            value=hours_saved,
            # Modelled, not measured: `cases.closed * MANUAL_INVESTIGATION_MINUTES`.
            # With no closures the model has no input, and "0h" presents
            # an estimate built on nothing as an observation. The count of
            # closures the estimate rests on travels with it.
            sample_count=cases.closed,
            unit="hours_saved",
            previous_value=prev_hours_saved,
            delta_pct=_delta_pct(
                hours_saved if cases.closed else None,
                prev_hours_saved if prev_cases.closed else None,
            ),
            sparkline=InsightSparkline(points=case_spark),
        ),
    ]

    return SOCInsightsResponse(
        window=window,
        generated_at=now,
        tenant_id=tenant_id,
        tiles=tiles,
        manual_investigation_minutes=MANUAL_INVESTIGATION_MINUTES,
    )
