"""Dashboard metrics endpoint — aggregated counts for the frontend KPI tiles.

Tier 1.4 (SOC metrics dashboard) — exposes:
  * MTTD (mean time to detect): alert.created_at → alert.first_seen_at
  * MTTR (mean time to respond): alert.created_at → alert.resolved_at
  * MTTC (mean time to contain): alert.created_at → alert.resolved_at for
    alerts with disposition='true_positive' (proxy for confirmed-contained)
  * False-positive rate (FPR): disposition='false_positive' / total resolved
  * Escalation rate: RemediationGateLog.decision in {'escalate','review'} /
    total decisions
  * Analyst overrides 7d: alerts with disposition set in last 7 days
  * Confidence calibration over time: reliability curve buckets — actual
    true-positive rate within each predicted-confidence bin
  * ATT&CK heatmap: tactic × technique counts

v1.5 (SOC Console parity) adds:
  * /metrics/funnel — live tenant funnel (events → correlations → alerts →
    analyst queue) with period support (1h|24h|7d|30d) and period-over-period
    deltas. Powers the new Funnel KPI bar + Efficiency Report on the
    dashboard.
"""

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, select

from app.api.v1.deps import AuthUser, DBSession
from app.core.config import settings
from app.models.alert import Alert
from app.models.case import Case
from app.models.connector import Connector
from app.models.detection_rule import DetectionRule
from app.models.remediation import RemediationGateLog

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/metrics", tags=["metrics"])


class AlertMetrics(BaseModel):
    total: int
    new: int
    critical: int
    high: int
    medium: int
    low: int
    resolvedToday: int
    mttr: float


class CaseMetrics(BaseModel):
    open: int
    inProgress: int
    resolvedThisWeek: int


class SourceStat(BaseModel):
    name: str
    count: int
    status: str


class MitreTactic(BaseModel):
    tactic: str
    count: int


class TrendPoint(BaseModel):
    timestamp: str
    count: int
    severity: str


class SourceThreat(BaseModel):
    source: str
    count: int


class DashboardMetrics(BaseModel):
    alerts: AlertMetrics
    cases: CaseMetrics
    sources: list[SourceStat]
    topMitre: list[MitreTactic]
    alertsTrend: list[TrendPoint]
    threatsBySource: list[SourceThreat]


# ───────────────────────────── v1.5 Funnel models ─────────────────────────────
#
# These models back the new /metrics/funnel endpoint exposed by the SOC
# Console (v1.5 — Tier 6, W1 + W9). The endpoint is read by:
#   * apps/web — <FunnelKpiBar /> on /dashboard
#   * apps/web — <EfficiencyReport /> tile
#   * apps/web — <NoiseRatio /> tile (replaces synthetic signal:noise)
#
# Shape is contract-frozen against the v1.5 SOC Console parity plan; do not
# rename fields without bumping the apps/web TS types in lockstep.


class MitreCoverage(BaseModel):
    """Slice of the MITRE ATT&CK landscape we have observable coverage for.

    ``covered`` counts the distinct techniques observed via either:
      * a tenant alert in the selected window (``Alert.mitre_techniques``), or
      * an enabled tenant/platform detection rule
        (``DetectionRule.mitre_techniques`` where ``status == 'enabled'``).

    ``total`` is configurable via ``AISOC_FUNNEL_MITRE_TOTAL`` and defaults to
    the MITRE ATT&CK Enterprise v17 technique count (201) so the ratio is
    interpretable as "% of ATT&CK we're watching for". The ratio is clamped to
    ``[0.0, 1.0]`` even if operators downsize the universe.
    """

    covered: int
    total: int
    ratio: float


class FunnelDeltas(BaseModel):
    """Period-over-period percentage deltas for the funnel KPI bar."""

    events_of_interest: float
    correlation_instances: float
    alerts_generated: float
    signal_to_noise: float
    mttd_seconds: float
    analyst_queue_depth: float


class FunnelMetrics(BaseModel):
    """Tenant funnel + efficiency for the selected period.

    All counts are absolute for ``period``. ``signal_to_noise`` is the
    fraction of *resolved* alerts that ended in disposition ``true_positive``
    (i.e. signal / (signal + noise)). ``mttd_seconds`` mirrors /metrics/soc's
    MTTD definition (Alert.created_at → Alert.first_seen_at) but expressed in
    seconds for funnel-level precision. ``deltas`` compares this period to the
    immediately preceding period of the same length.
    """

    period: str
    events_of_interest: int
    correlation_instances: int
    alerts_generated: int
    signal_to_noise: float
    mttd_seconds: float
    analyst_queue_depth: int
    correlation_efficiency: float
    alert_yield: float
    mitre_coverage: MitreCoverage
    deltas: FunnelDeltas
    generated_at: datetime


# ────────────────────────── v1.5 Pipeline-health models ───────────────────────
#
# Backs GET /health/pipeline. Surfaces a stage-by-stage health summary for the
# ingest → normalize → fuse → correlate → alert pipeline, which the SOC
# Console renders as the Pipeline Health strip on /dashboard.


class PipelineStage(BaseModel):
    """One row in the pipeline health strip.

    ``status`` follows the green/yellow/red/unknown ladder used by
    ``app.services.connector_freshness``. ``backlog`` is the number of items
    currently waiting at this stage (e.g. enabled-but-stale connectors for
    ``ingest``, unacked alerts for ``alert``). ``p95_latency_ms`` is the 95th
    percentile end-to-end latency for items that traversed this stage in the
    last hour. ``error_rate`` is errors / processed in the same window.
    """

    stage: str
    backlog: int
    p95_latency_ms: float
    error_rate: float
    status: str


class PipelineHealth(BaseModel):
    """Top-level response for ``GET /health/pipeline``."""

    overall_status: str
    stages: list[PipelineStage]
    generated_at: datetime


@router.get("/dashboard", response_model=DashboardMetrics)
async def get_dashboard_metrics(
    user: AuthUser,
    db: DBSession,
) -> DashboardMetrics:
    """Return aggregated KPI metrics for the dashboard overview tiles."""
    tenant_id = user.tenant_id
    now = datetime.now(UTC)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)

    # ── Alert counts ──────────────────────────────────────────────────────────
    total_q = await db.scalar(select(func.count()).where(Alert.tenant_id == tenant_id))
    new_q = await db.scalar(select(func.count()).where(and_(Alert.tenant_id == tenant_id, Alert.status == "new")))
    critical_q = await db.scalar(select(func.count()).where(and_(Alert.tenant_id == tenant_id, Alert.severity == "critical")))
    high_q = await db.scalar(select(func.count()).where(and_(Alert.tenant_id == tenant_id, Alert.severity == "high")))
    medium_q = await db.scalar(select(func.count()).where(and_(Alert.tenant_id == tenant_id, Alert.severity == "medium")))
    low_q = await db.scalar(select(func.count()).where(and_(Alert.tenant_id == tenant_id, Alert.severity == "low")))
    resolved_today_q = await db.scalar(
        select(func.count()).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.status == "resolved",
                Alert.updated_at >= today_start,
            )
        )
    )

    # MTTR for the dashboard tile: average resolved-alert duration over last 7d
    mttr_dashboard_q = await db.scalar(
        select(func.avg(func.extract("epoch", Alert.resolved_at - Alert.created_at) / 3600)).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.resolved_at.isnot(None),
                Alert.created_at >= week_start,
            )
        )
    )

    alert_metrics = AlertMetrics(
        total=total_q or 0,
        new=new_q or 0,
        critical=critical_q or 0,
        high=high_q or 0,
        medium=medium_q or 0,
        low=low_q or 0,
        resolvedToday=resolved_today_q or 0,
        mttr=round(float(mttr_dashboard_q or 0.0), 2),
    )

    # ── Case counts ───────────────────────────────────────────────────────────
    open_cases_q = await db.scalar(select(func.count()).where(and_(Case.tenant_id == tenant_id, Case.status == "open")))
    in_progress_q = await db.scalar(select(func.count()).where(and_(Case.tenant_id == tenant_id, Case.status == "in_progress")))
    resolved_week_q = await db.scalar(
        select(func.count()).where(
            and_(
                Case.tenant_id == tenant_id,
                Case.status == "resolved",
                Case.updated_at >= week_start,
            )
        )
    )

    case_metrics = CaseMetrics(
        open=open_cases_q or 0,
        inProgress=in_progress_q or 0,
        resolvedThisWeek=resolved_week_q or 0,
    )

    # ── Sources (connectors) ──────────────────────────────────────────────────
    connectors_rows = (
        await db.execute(select(Connector.name, Connector.connector_type, Connector.health_status).where(Connector.tenant_id == tenant_id))
    ).all()

    # Count alerts per connector_type
    source_counts_rows = (
        await db.execute(
            select(Alert.connector_type, func.count().label("cnt")).where(Alert.tenant_id == tenant_id).group_by(Alert.connector_type)
        )
    ).all()
    source_count_map: dict[str, int] = {row.connector_type: row.cnt for row in source_counts_rows if row.connector_type}

    sources: list[SourceStat] = []
    seen: set[str] = set()
    for row in connectors_rows:
        key = row.connector_type or row.name
        if key in seen:
            continue
        seen.add(key)
        sources.append(
            SourceStat(
                name=row.name,
                count=source_count_map.get(row.connector_type or "", 0),
                status=row.health_status or "active",
            )
        )

    # ── Top MITRE tactics ─────────────────────────────────────────────────────
    # Python-side aggregation: avoids set-returning-function-in-SELECT pitfalls
    # across Postgres versions and gives identical results for our scale
    # (typically <10k alerts/tenant). Driver tests proved a SQL-level
    # jsonb_array_elements_text + GROUP BY in the same SELECT 500s on some
    # Postgres builds.
    tactic_rows = (
        await db.execute(select(Alert.mitre_tactics).where(and_(Alert.tenant_id == tenant_id, Alert.mitre_tactics.isnot(None))))
    ).all()

    tactic_counts: dict[str, int] = {}
    for (tactics,) in tactic_rows:
        if not tactics:
            continue
        for t in tactics:
            if isinstance(t, str) and t:
                tactic_counts[t] = tactic_counts.get(t, 0) + 1

    top_mitre = [
        MitreTactic(tactic=tactic, count=count) for tactic, count in sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    # ── 24-hour trend (hourly buckets) ────────────────────────────────────────
    trend_start = now - timedelta(hours=24)
    trend_rows = (
        await db.execute(
            select(
                func.date_trunc("hour", Alert.created_at).label("bucket"),
                Alert.severity,
                func.count().label("cnt"),
            )
            .where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= trend_start,
                )
            )
            .group_by("bucket", Alert.severity)
            .order_by("bucket")
        )
    ).all()

    alerts_trend = [
        TrendPoint(
            timestamp=r.bucket.isoformat() if r.bucket else now.isoformat(),
            count=r.cnt,
            severity=r.severity,
        )
        for r in trend_rows
    ]

    # ── Threats by source ─────────────────────────────────────────────────────
    threats_by_source = [SourceThreat(source=k, count=v) for k, v in source_count_map.items()]

    return DashboardMetrics(
        alerts=alert_metrics,
        cases=case_metrics,
        sources=sources,
        topMitre=top_mitre,
        alertsTrend=alerts_trend,
        threatsBySource=threats_by_source,
    )


class SOCKpis(BaseModel):
    mttd_hours: float
    mttr_hours: float
    mttc_hours: float
    false_positive_rate: float
    escalation_rate: float
    alert_volume_7d: int
    cases_opened_7d: int
    cases_closed_7d: int
    analyst_overrides_7d: int


class AttackHeatmapCell(BaseModel):
    tactic: str
    technique: str
    count: int


class CalibrationBucket(BaseModel):
    """One bucket of the agent confidence reliability curve.

    `predicted_lower` and `predicted_upper` define the AI-confidence range
    (e.g., 0.8–1.0). `actual_tp_rate` is the observed true-positive rate
    among analyst-dispositioned alerts whose ai_score landed in that bucket
    — i.e., the empirical hit-rate the model claimed.
    """

    predicted_lower: float
    predicted_upper: float
    sample_count: int
    actual_tp_rate: float


class SOCMetrics(BaseModel):
    kpis: SOCKpis
    attack_heatmap: list[AttackHeatmapCell]
    calibration_curve: list[CalibrationBucket]


@router.get("/soc", response_model=SOCMetrics)
async def get_soc_metrics(
    user: AuthUser,
    db: DBSession,
) -> SOCMetrics:
    """Return SOC-level KPIs, ATT&CK heatmap, and confidence calibration curve.

    Tier 1.4 metrics:
      - MTTD, MTTR, MTTC, FPR, escalation rate, analyst overrides
      - ATT&CK technique × tactic heatmap
      - Confidence calibration over time (reliability curve)
    """
    tenant_id = user.tenant_id
    now = datetime.now(UTC)
    week_start = now - timedelta(days=7)

    # ── MTTD ──────────────────────────────────────────────────────────────────
    # Mean time from alert creation to first analyst view (first_seen_at).
    mttd_q = await db.scalar(
        select(func.avg(func.extract("epoch", Alert.first_seen_at - Alert.created_at) / 3600)).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.first_seen_at.isnot(None),
                Alert.created_at >= week_start,
            )
        )
    )
    mttd_hours = float(mttd_q or 0.0)

    # ── MTTR ──────────────────────────────────────────────────────────────────
    # Mean time from alert creation to resolved_at, for any resolved alert.
    mttr_q = await db.scalar(
        select(func.avg(func.extract("epoch", Alert.resolved_at - Alert.created_at) / 3600)).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.resolved_at.isnot(None),
                Alert.created_at >= week_start,
            )
        )
    )
    mttr_hours = float(mttr_q or 0.0)

    # ── MTTC (Mean Time to Contain) ───────────────────────────────────────────
    # For confirmed true-positive alerts only — proxy for "incident contained".
    # Uses resolved_at since we don't track a separate contained_at.
    mttc_q = await db.scalar(
        select(func.avg(func.extract("epoch", Alert.resolved_at - Alert.created_at) / 3600)).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.resolved_at.isnot(None),
                Alert.disposition == "true_positive",
                Alert.created_at >= week_start,
            )
        )
    )
    mttc_hours = float(mttc_q or 0.0)

    # ── FPR ───────────────────────────────────────────────────────────────────
    # False-positive dispositions / total resolved-and-dispositioned alerts.
    total_resolved = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.disposition.isnot(None),
                    Alert.created_at >= week_start,
                )
            )
        )
        or 0
    )
    fp_count = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.disposition == "false_positive",
                    Alert.created_at >= week_start,
                )
            )
        )
        or 0
    )
    fpr = (fp_count / total_resolved) if total_resolved > 0 else 0.0

    # ── Escalation rate ───────────────────────────────────────────────────────
    # Fraction of remediation gate decisions that escaped autonomous handling.
    escalation_decisions = {"escalate", "review"}
    total_decisions = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    RemediationGateLog.tenant_id == tenant_id,
                    RemediationGateLog.created_at >= week_start,
                )
            )
        )
        or 0
    )
    escalated_count = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    RemediationGateLog.tenant_id == tenant_id,
                    RemediationGateLog.created_at >= week_start,
                    RemediationGateLog.decision.in_(escalation_decisions),
                )
            )
        )
        or 0
    )
    escalation_rate = escalated_count / total_decisions if total_decisions > 0 else 0.0

    # ── Volume / case counts ──────────────────────────────────────────────────
    alert_vol = await db.scalar(select(func.count()).where(and_(Alert.tenant_id == tenant_id, Alert.created_at >= week_start))) or 0
    cases_opened = await db.scalar(select(func.count()).where(and_(Case.tenant_id == tenant_id, Case.created_at >= week_start))) or 0
    cases_closed = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Case.tenant_id == tenant_id,
                    Case.status == "resolved",
                    Case.updated_at >= week_start,
                )
            )
        )
        or 0
    )

    # ── Analyst overrides (7d) ────────────────────────────────────────────────
    # Any alert with a disposition set in the last 7 days = analyst weighed in.
    overrides_q = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.disposition.isnot(None),
                    Alert.updated_at >= week_start,
                )
            )
        )
        or 0
    )

    kpis = SOCKpis(
        mttd_hours=round(mttd_hours, 2),
        mttr_hours=round(mttr_hours, 2),
        mttc_hours=round(mttc_hours, 2),
        false_positive_rate=round(fpr, 4),
        escalation_rate=round(escalation_rate, 4),
        alert_volume_7d=alert_vol,
        cases_opened_7d=cases_opened,
        cases_closed_7d=cases_closed,
        analyst_overrides_7d=overrides_q,
    )

    # ── ATT&CK heatmap ────────────────────────────────────────────────────────
    # Python-side aggregation. Combining two set-returning functions with
    # GROUP BY + aggregate in the same SELECT raises on modern Postgres
    # ("set-returning functions are not allowed in GROUP BY") and was the
    # root cause of /metrics/soc returning 500. For each alert we pair every
    # (tactic, technique) Cartesian-style, then aggregate in Python.
    heatmap_src_rows = (
        await db.execute(
            select(Alert.mitre_tactics, Alert.mitre_techniques).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.mitre_tactics.isnot(None),
                    Alert.mitre_techniques.isnot(None),
                )
            )
        )
    ).all()

    pair_counts: dict[tuple[str, str], int] = {}
    for tactics, techniques in heatmap_src_rows:
        if not tactics or not techniques:
            continue
        for tactic in tactics:
            if not isinstance(tactic, str) or not tactic:
                continue
            for technique in techniques:
                if not isinstance(technique, str) or not technique:
                    continue
                key = (tactic, technique)
                pair_counts[key] = pair_counts.get(key, 0) + 1

    heatmap = [
        AttackHeatmapCell(tactic=tactic, technique=technique, count=count)
        for (tactic, technique), count in sorted(pair_counts.items(), key=lambda x: x[1], reverse=True)[:50]
    ]

    # ── Confidence calibration curve ──────────────────────────────────────────
    # 5 buckets across [0, 1]. For each bucket, count alerts with ai_score in
    # range AND a non-null disposition, plus the fraction that were
    # 'true_positive' (i.e., the model was correct to be confident).
    bucket_edges = [(0.0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1.0001)]
    calibration_curve: list[CalibrationBucket] = []
    for lower, upper in bucket_edges:
        # Total dispositioned alerts in this bucket
        bucket_total_q = await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.ai_score.isnot(None),
                    Alert.ai_score >= lower,
                    Alert.ai_score < upper,
                    Alert.disposition.isnot(None),
                    Alert.created_at >= now - timedelta(days=30),
                )
            )
        )
        bucket_total = int(bucket_total_q or 0)

        # True-positives in this bucket
        bucket_tp_q = await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.ai_score.isnot(None),
                    Alert.ai_score >= lower,
                    Alert.ai_score < upper,
                    Alert.disposition == "true_positive",
                    Alert.created_at >= now - timedelta(days=30),
                )
            )
        )
        bucket_tp = int(bucket_tp_q or 0)

        actual_tp_rate = (bucket_tp / bucket_total) if bucket_total > 0 else 0.0
        calibration_curve.append(
            CalibrationBucket(
                predicted_lower=round(lower, 2),
                predicted_upper=round(min(upper, 1.0), 2),
                sample_count=bucket_total,
                actual_tp_rate=round(actual_tp_rate, 4),
            )
        )

    return SOCMetrics(
        kpis=kpis,
        attack_heatmap=heatmap,
        calibration_curve=calibration_curve,
    )


@router.get("/alerts/trend")
async def get_alert_trend(
    user: AuthUser,
    db: DBSession,
    period: str = "24h",
) -> dict:
    """Return alert count trend data bucketed by time period."""
    now = datetime.now(UTC)
    period_map = {
        "1h": (timedelta(hours=1), "minute"),
        "24h": (timedelta(hours=24), "hour"),
        "7d": (timedelta(days=7), "day"),
        "30d": (timedelta(days=30), "day"),
    }
    delta, trunc = period_map.get(period, (timedelta(hours=24), "hour"))
    start = now - delta

    rows = (
        await db.execute(
            select(
                func.date_trunc(trunc, Alert.created_at).label("bucket"),
                func.count().label("cnt"),
            )
            .where(
                and_(
                    Alert.tenant_id == user.tenant_id,
                    Alert.created_at >= start,
                )
            )
            .group_by("bucket")
            .order_by("bucket")
        )
    ).all()

    return {
        "data": [
            {
                "timestamp": r.bucket.isoformat() if r.bucket else now.isoformat(),
                "count": r.cnt,
            }
            for r in rows
        ]
    }


# ──────────────────────────── v1.5 funnel endpoint ────────────────────────────


_FUNNEL_PERIOD_MAP: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


def _pct_delta(current: float, previous: float) -> float:
    """Compute period-over-period percentage change.

    Returns 0.0 when the previous value is zero (avoids `inf`). Otherwise:

        ((current - previous) / previous) * 100, rounded to 2 decimals.
    """
    if previous == 0:
        return 0.0
    return round(((current - previous) / previous) * 100.0, 2)


async def _events_of_interest(db, tenant_id, start, end) -> int:
    """Count tenant raw events that landed in the analytical lake.

    Primary source is ``aisoc.raw_events`` in ClickHouse — the same table the
    fusion correlator reads — which is the source-of-truth for "events of
    interest" (i.e. anything an ingest connector emitted after enrichment but
    before alerting).

    Falls back to a PostgreSQL-derived count (sum of distinct
    ``source_event_ids`` across alerts in the window) when ClickHouse is
    disabled via ``AISOC_DISABLE_CLICKHOUSE`` or unreachable. This keeps the
    endpoint usable in air-gapped / Postgres-only deployments and in tests.
    """
    if getattr(settings, "AISOC_DISABLE_CLICKHOUSE", False):
        return await _events_of_interest_from_alerts(db, tenant_id, start, end)

    try:
        from app.db.clickhouse import (
            LakeQueryError,
            LakeQueryNotConfiguredError,
            execute_lake_query,
        )
        from app.services.lake_sql import rewrite_for_tenant
    except Exception:  # pragma: no cover — defensive
        return await _events_of_interest_from_alerts(db, tenant_id, start, end)

    sql = (
        "SELECT count() AS cnt "
        "FROM aisoc.raw_events "
        f"WHERE ingested_at >= toDateTime('{start.strftime('%Y-%m-%d %H:%M:%S')}') "
        f"AND ingested_at < toDateTime('{end.strftime('%Y-%m-%d %H:%M:%S')}')"
    )

    try:
        rewrite = rewrite_for_tenant(sql, tenant_id, row_cap=1)
        result = await execute_lake_query(rewrite.sql, timeout_seconds=5.0)
    except LakeQueryNotConfiguredError:
        return await _events_of_interest_from_alerts(db, tenant_id, start, end)
    except LakeQueryError as exc:
        logger.warning("events_of_interest ClickHouse fallback: %s", exc)
        return await _events_of_interest_from_alerts(db, tenant_id, start, end)
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("events_of_interest unexpected error: %s", exc)
        return await _events_of_interest_from_alerts(db, tenant_id, start, end)

    if not result.rows:
        return 0
    try:
        return int(result.rows[0][0] or 0)
    except (TypeError, ValueError, IndexError):
        return 0


async def _events_of_interest_from_alerts(db, tenant_id, start, end) -> int:
    """Fallback EOI: sum of ``jsonb_array_length(source_event_ids)`` across
    alerts in the window. Conservative — only counts events that already
    correlated into an alert — but never lies in air-gapped deployments.
    """
    val = await db.scalar(
        select(func.coalesce(func.sum(func.jsonb_array_length(Alert.source_event_ids)), 0)).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= start,
                Alert.created_at < end,
            )
        )
    )
    return int(val or 0)


async def _funnel_window(db, tenant_id, start, end, *, mitre_total: int) -> dict:
    """Compute the funnel for a single [start, end) window."""
    events_of_interest = await _events_of_interest(db, tenant_id, start, end)

    # Correlation instances = alerts whose source_event_ids has >= 2 events
    # (i.e. multiple raw events fused into a single alert). Single-event
    # alerts are excluded so the ratio stays meaningful when one detection
    # rule fires repeatedly.
    correlation_instances = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= start,
                    Alert.created_at < end,
                    func.jsonb_array_length(Alert.source_event_ids) >= 2,
                )
            )
        )
        or 0
    )

    alerts_generated = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= start,
                    Alert.created_at < end,
                )
            )
        )
        or 0
    )

    # Signal-to-noise: of *resolved* alerts in the window, what fraction
    # ended in disposition='true_positive'? Closed alerts with no disposition
    # are excluded from both numerator and denominator so the ratio reflects
    # analyst judgement, not lifecycle state.
    sig_total = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= start,
                    Alert.created_at < end,
                    Alert.disposition.in_(("true_positive", "false_positive", "benign", "duplicate")),
                )
            )
        )
        or 0
    )
    sig_tp = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= start,
                    Alert.created_at < end,
                    Alert.disposition == "true_positive",
                )
            )
        )
        or 0
    )
    signal_to_noise = round((sig_tp / sig_total), 4) if sig_total else 0.0

    # MTTD in seconds for alerts created in this window that have been seen.
    mttd_seconds_raw = await db.scalar(
        select(func.avg(func.extract("epoch", Alert.first_seen_at - Alert.created_at))).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.first_seen_at.isnot(None),
                Alert.created_at >= start,
                Alert.created_at < end,
            )
        )
    )
    mttd_seconds = round(float(mttd_seconds_raw or 0.0), 2)

    # Analyst queue depth = open alerts (snapshot, not window-bound) that an
    # analyst would see in their queue right now: status in {new, triaging,
    # in_progress} and no disposition.
    analyst_queue_depth = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.status.in_(("new", "triaging", "in_progress")),
                    Alert.disposition.is_(None),
                )
            )
        )
        or 0
    )

    # Correlation efficiency = correlation_instances / events_of_interest.
    # "What share of raw events did the fusion engine collapse into a
    # correlated incident?" Capped at 1.0 in case EOI is under-counted by the
    # PostgreSQL fallback.
    if events_of_interest > 0:
        correlation_efficiency = round(min(correlation_instances / events_of_interest, 1.0), 4)
    else:
        correlation_efficiency = 0.0

    # Alert yield = alerts_generated / events_of_interest. "How many of the
    # raw events that landed in the lake became analyst-visible alerts?"
    if events_of_interest > 0:
        alert_yield = round(min(alerts_generated / events_of_interest, 1.0), 4)
    else:
        alert_yield = 0.0

    # MITRE coverage: union of distinct techniques across (a) alerts in the
    # window and (b) enabled detection rules visible to the tenant (platform
    # rules + tenant rules).
    covered = await _mitre_covered(db, tenant_id, start, end)
    ratio = round(min(covered / mitre_total, 1.0), 4) if mitre_total > 0 else 0.0
    coverage = MitreCoverage(covered=covered, total=mitre_total, ratio=ratio)

    return {
        "events_of_interest": int(events_of_interest),
        "correlation_instances": int(correlation_instances),
        "alerts_generated": int(alerts_generated),
        "signal_to_noise": signal_to_noise,
        "mttd_seconds": mttd_seconds,
        "analyst_queue_depth": int(analyst_queue_depth),
        "correlation_efficiency": correlation_efficiency,
        "alert_yield": alert_yield,
        "mitre_coverage": coverage,
    }


async def _mitre_covered(db, tenant_id, start, end) -> int:
    """Count distinct MITRE techniques visible to this tenant.

    Union of:
      * techniques observed on alerts created in the window
      * techniques referenced by enabled detection rules (tenant-scoped or
        platform-wide where ``tenant_id IS NULL``)
    """
    alert_techs = (
        (
            await db.execute(
                select(func.distinct(func.jsonb_array_elements_text(Alert.mitre_techniques))).where(
                    and_(
                        Alert.tenant_id == tenant_id,
                        Alert.created_at >= start,
                        Alert.created_at < end,
                    )
                )
            )
        )
        .scalars()
        .all()
    )

    rule_techs = (
        (
            await db.execute(
                select(func.distinct(func.jsonb_array_elements_text(DetectionRule.mitre_techniques))).where(
                    and_(
                        DetectionRule.status == "enabled",
                        (DetectionRule.tenant_id == tenant_id) | (DetectionRule.tenant_id.is_(None)),
                    )
                )
            )
        )
        .scalars()
        .all()
    )

    techniques = {t for t in alert_techs if t} | {t for t in rule_techs if t}
    return len(techniques)


@router.get("/funnel", response_model=FunnelMetrics)
async def get_funnel_metrics(
    user: AuthUser,
    db: DBSession,
    period: str = Query("24h", pattern=r"^(1h|24h|7d|30d)$"),
) -> FunnelMetrics:
    """Return the live tenant funnel for the SOC Console (v1.5).

    Funnel: events_of_interest → correlation_instances → alerts_generated →
    analyst_queue_depth, plus efficiency ratios and MITRE coverage.

    ``deltas`` compares the current window to the immediately preceding window
    of the same length (e.g. for ``period=24h`` we compare to the 24h ending
    24h ago). Values are percentage changes rounded to two decimals; a delta
    of ``0.0`` means "no meaningful baseline" (the previous window was empty).
    """
    delta = _FUNNEL_PERIOD_MAP[period]
    now = datetime.now(UTC)
    end = now
    start = end - delta
    prev_end = start
    prev_start = prev_end - delta

    mitre_total = int(getattr(settings, "AISOC_FUNNEL_MITRE_TOTAL", 201)) or 201

    current = await _funnel_window(db, user.tenant_id, start, end, mitre_total=mitre_total)
    previous = await _funnel_window(db, user.tenant_id, prev_start, prev_end, mitre_total=mitre_total)

    deltas = FunnelDeltas(
        events_of_interest=_pct_delta(current["events_of_interest"], previous["events_of_interest"]),
        correlation_instances=_pct_delta(current["correlation_instances"], previous["correlation_instances"]),
        alerts_generated=_pct_delta(current["alerts_generated"], previous["alerts_generated"]),
        signal_to_noise=_pct_delta(current["signal_to_noise"], previous["signal_to_noise"]),
        mttd_seconds=_pct_delta(current["mttd_seconds"], previous["mttd_seconds"]),
        analyst_queue_depth=_pct_delta(current["analyst_queue_depth"], previous["analyst_queue_depth"]),
    )

    return FunnelMetrics(
        period=period,
        events_of_interest=current["events_of_interest"],
        correlation_instances=current["correlation_instances"],
        alerts_generated=current["alerts_generated"],
        signal_to_noise=current["signal_to_noise"],
        mttd_seconds=current["mttd_seconds"],
        analyst_queue_depth=current["analyst_queue_depth"],
        correlation_efficiency=current["correlation_efficiency"],
        alert_yield=current["alert_yield"],
        mitre_coverage=current["mitre_coverage"],
        deltas=deltas,
        generated_at=now,
    )
