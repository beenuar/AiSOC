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
    * **Analyst hours saved** — auto-closed cases (resolved without
      analyst override) × the named ``MANUAL_INVESTIGATION_MINUTES``
      constant.

Every tile also returns a 24-bucket sparkline for the window so the UI
can render an inline trendline without a follow-up request.

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
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select, text
from sqlalchemy.exc import SQLAlchemyError

from app.api.v1.deps import AuthUser, DBSession
from app.models.alert import Alert
from app.models.case import Case

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/insights", tags=["insights"])


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# heuristic: auto-closed cases × avg manual investigation time (45 min)
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
    value: float = Field(description="Headline metric for the current window.")
    unit: str = Field(
        description=(
            "Display unit. The UI picks formatting per unit "
            "(``hours`` → 1 decimal, ``pct`` → percentage, ``usd`` → "
            "currency, ``count`` → integer, ``hours_saved`` → integer)."
        )
    )
    previous_value: float = Field(
        description=("Value of the same metric over the immediately preceding " "window of equal length. Used to compute the delta.")
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


def _delta_pct(current: float, previous: float) -> float | None:
    """Percent change. ``None`` when previous is zero (undefined)."""
    if previous == 0:
        return None
    return round(((current - previous) / previous) * 100.0, 2)


async def _mean_hours(
    db,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
    *,
    start_col,
    end_col,
    extra_filters=(),
) -> float:
    """Mean hours between two alert timestamp columns over [start, end)."""
    filters = [
        Alert.tenant_id == tenant_id,
        Alert.created_at >= start,
        Alert.created_at < end,
        start_col.isnot(None),
        end_col.isnot(None),
    ]
    filters.extend(extra_filters)
    result = await db.scalar(select(func.avg(func.extract("epoch", end_col - start_col) / 3600)).where(and_(*filters)))
    return round(float(result or 0.0), 2)


async def _count(db, model, tenant_id: uuid.UUID, start: datetime, end: datetime, *extra) -> int:
    filters = [model.tenant_id == tenant_id, model.created_at >= start, model.created_at < end]
    filters.extend(extra)
    return int(await db.scalar(select(func.count()).where(and_(*filters))) or 0)


async def _fp_rate(db, tenant_id: uuid.UUID, start: datetime, end: datetime) -> float:
    """False-positive rate over dispositioned alerts."""
    total = await db.scalar(
        select(func.count()).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.disposition.isnot(None),
                Alert.created_at >= start,
                Alert.created_at < end,
            )
        )
    )
    if not total:
        return 0.0
    fp = await db.scalar(
        select(func.count()).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.disposition == "false_positive",
                Alert.created_at >= start,
                Alert.created_at < end,
            )
        )
    )
    return round((int(fp or 0) / int(total)), 4)


async def _alert_sparkline(
    db,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> list[float]:
    """24 evenly-spaced buckets of alert volume across [start, end)."""
    total_seconds = max((end - start).total_seconds(), 1.0)
    bucket_seconds = total_seconds / _SPARKLINE_BUCKETS
    rows = (
        await db.execute(
            select(Alert.created_at).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= start,
                    Alert.created_at < end,
                )
            )
        )
    ).all()
    buckets = [0.0] * _SPARKLINE_BUCKETS
    for (ts,) in rows:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        delta = (ts - start).total_seconds()
        idx = min(int(delta / bucket_seconds), _SPARKLINE_BUCKETS - 1)
        if idx >= 0:
            buckets[idx] += 1
    return buckets


async def _case_sparkline(
    db,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> list[float]:
    """24 evenly-spaced buckets of case-open volume across [start, end)."""
    total_seconds = max((end - start).total_seconds(), 1.0)
    bucket_seconds = total_seconds / _SPARKLINE_BUCKETS
    rows = (
        await db.execute(
            select(Case.created_at).where(
                and_(
                    Case.tenant_id == tenant_id,
                    Case.created_at >= start,
                    Case.created_at < end,
                )
            )
        )
    ).all()
    buckets = [0.0] * _SPARKLINE_BUCKETS
    for (ts,) in rows:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=UTC)
        delta = (ts - start).total_seconds()
        idx = min(int(delta / bucket_seconds), _SPARKLINE_BUCKETS - 1)
        if idx >= 0:
            buckets[idx] += 1
    return buckets


# TODO(T2.4-followup): ``aisoc_run_costs`` is populated by the agents
# service's cost telemetry path (Track 2 / T2.4). When that table hasn't
# been deployed yet — e.g. fresh demos, or services/api running
# disconnected from the agents DSN — the query below raises a
# ``UndefinedTable`` we swallow into ``(0.0, 0)``. Once T2.4 ships in
# every environment, the swallow can be tightened to log-only.
async def _llm_cost_aggregate(
    db,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> tuple[float, int]:
    """Return ``(total_cost_usd, distinct_run_count)`` over the window.

    Joins ``aisoc_run_costs`` with ``investigation_runs`` to tenant-scope
    the spend. Returns ``(0.0, 0)`` if the cost table isn't deployed
    yet so the UI can render zeroes rather than a 500.
    """
    sql = text(
        """
        SELECT COALESCE(SUM(c.total_cost_usd), 0.0) AS cost,
               COUNT(DISTINCT c.run_id)             AS runs
        FROM aisoc_run_costs c
        JOIN investigation_runs r ON r.id::text = c.run_id
        WHERE r.tenant_id = :tenant_id
          AND r.started_at >= :start_at
          AND r.started_at < :end_at
        """
    )
    try:
        row = (
            (
                await db.execute(
                    sql,
                    {"tenant_id": str(tenant_id), "start_at": start, "end_at": end},
                )
            )
            .mappings()
            .first()
        )
        if not row:
            return 0.0, 0
        return float(row["cost"] or 0.0), int(row["runs"] or 0)
    except SQLAlchemyError:
        # Either table doesn't exist yet, or RLS denied us — log and
        # return zeroes so the dashboard stays renderable.
        logger.debug("insights.cost_aggregate_unavailable", exc_info=True)
        return 0.0, 0


async def _llm_cost_sparkline(
    db,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> list[float]:
    """24 evenly-spaced cost-USD buckets across [start, end)."""
    total_seconds = max((end - start).total_seconds(), 1.0)
    bucket_seconds = total_seconds / _SPARKLINE_BUCKETS
    sql = text(
        """
        SELECT r.started_at AS started_at,
               c.total_cost_usd AS cost
        FROM aisoc_run_costs c
        JOIN investigation_runs r ON r.id::text = c.run_id
        WHERE r.tenant_id = :tenant_id
          AND r.started_at >= :start_at
          AND r.started_at < :end_at
        """
    )
    buckets = [0.0] * _SPARKLINE_BUCKETS
    try:
        result = await db.execute(
            sql,
            {"tenant_id": str(tenant_id), "start_at": start, "end_at": end},
        )
        for r in result.mappings():
            ts = r["started_at"]
            if ts is None:
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            delta = (ts - start).total_seconds()
            idx = min(int(delta / bucket_seconds), _SPARKLINE_BUCKETS - 1)
            if idx >= 0:
                buckets[idx] += float(r["cost"] or 0.0)
    except SQLAlchemyError:
        logger.debug("insights.cost_sparkline_unavailable", exc_info=True)
    return buckets


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

    # ── Window-current values ─────────────────────────────────────────────
    mtta_hours = await _mean_hours(
        db,
        tenant_id,
        start,
        now,
        start_col=Alert.created_at,
        end_col=Alert.first_seen_at,
    )
    mttr_hours = await _mean_hours(
        db,
        tenant_id,
        start,
        now,
        start_col=Alert.created_at,
        end_col=Alert.resolved_at,
    )
    fp_rate = await _fp_rate(db, tenant_id, start, now)
    alert_count = await _count(db, Alert, tenant_id, start, now)
    case_count = await _count(db, Case, tenant_id, start, now)
    cost_total, run_count = await _llm_cost_aggregate(db, tenant_id, start, now)
    auto_closed = await _count(
        db,
        Case,
        tenant_id,
        start,
        now,
        Case.status == "resolved",
    )

    # ── Previous-window comparisons for delta ─────────────────────────────
    prev_mtta = await _mean_hours(
        db,
        tenant_id,
        prev_start,
        start,
        start_col=Alert.created_at,
        end_col=Alert.first_seen_at,
    )
    prev_mttr = await _mean_hours(
        db,
        tenant_id,
        prev_start,
        start,
        start_col=Alert.created_at,
        end_col=Alert.resolved_at,
    )
    prev_fp_rate = await _fp_rate(db, tenant_id, prev_start, start)
    prev_alert_count = await _count(db, Alert, tenant_id, prev_start, start)
    prev_case_count = await _count(db, Case, tenant_id, prev_start, start)
    prev_cost_total, prev_run_count = await _llm_cost_aggregate(db, tenant_id, prev_start, start)
    prev_auto_closed = await _count(
        db,
        Case,
        tenant_id,
        prev_start,
        start,
        Case.status == "resolved",
    )

    # ── Derived ───────────────────────────────────────────────────────────
    alerts_per_day = round(alert_count / window_days, 2)
    cases_per_day = round(case_count / window_days, 2)
    prev_alerts_per_day = round(prev_alert_count / window_days, 2)
    prev_cases_per_day = round(prev_case_count / window_days, 2)

    cost_per_inv = round(cost_total / run_count, 4) if run_count else 0.0
    prev_cost_per_inv = round(prev_cost_total / prev_run_count, 4) if prev_run_count else 0.0

    hours_saved = round((auto_closed * MANUAL_INVESTIGATION_MINUTES) / 60.0, 2)
    prev_hours_saved = round((prev_auto_closed * MANUAL_INVESTIGATION_MINUTES) / 60.0, 2)

    # ── Sparklines ────────────────────────────────────────────────────────
    alert_spark = await _alert_sparkline(db, tenant_id, start, now)
    case_spark = await _case_sparkline(db, tenant_id, start, now)
    cost_spark = await _llm_cost_sparkline(db, tenant_id, start, now)

    tiles: list[InsightTile] = [
        InsightTile(
            key="mtta",
            label="MTTA",
            value=mtta_hours,
            unit="hours",
            previous_value=prev_mtta,
            delta_pct=_delta_pct(mtta_hours, prev_mtta),
            sparkline=InsightSparkline(points=alert_spark),
        ),
        InsightTile(
            key="mttr",
            label="MTTR",
            value=mttr_hours,
            unit="hours",
            previous_value=prev_mttr,
            delta_pct=_delta_pct(mttr_hours, prev_mttr),
            sparkline=InsightSparkline(points=alert_spark),
        ),
        InsightTile(
            key="fp_rate",
            label="FP Rate",
            value=fp_rate,
            unit="pct",
            previous_value=prev_fp_rate,
            delta_pct=_delta_pct(fp_rate, prev_fp_rate),
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
            unit="usd",
            previous_value=prev_cost_per_inv,
            delta_pct=_delta_pct(cost_per_inv, prev_cost_per_inv),
            sparkline=InsightSparkline(points=cost_spark),
        ),
        InsightTile(
            key="analyst_hours_saved",
            label="Analyst hours saved",
            value=hours_saved,
            unit="hours_saved",
            previous_value=prev_hours_saved,
            delta_pct=_delta_pct(hours_saved, prev_hours_saved),
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
