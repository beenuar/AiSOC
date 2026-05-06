"""Dashboard metrics endpoint — aggregated counts for the frontend KPI tiles."""

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter
from pydantic import BaseModel
from sqlalchemy import and_, func, select

from app.api.v1.deps import AuthUser, DBSession
from app.models.alert import Alert
from app.models.case import Case
from app.models.connector import Connector

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

    alert_metrics = AlertMetrics(
        total=total_q or 0,
        new=new_q or 0,
        critical=critical_q or 0,
        high=high_q or 0,
        medium=medium_q or 0,
        low=low_q or 0,
        resolvedToday=resolved_today_q or 0,
        mttr=0.0,
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
    mitre_rows = (
        await db.execute(
            select(
                func.jsonb_array_elements_text(Alert.mitre_tactics).label("tactic"),
                func.count().label("cnt"),
            )
            .where(Alert.tenant_id == tenant_id)
            .group_by("tactic")
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()

    top_mitre = [MitreTactic(tactic=r.tactic, count=r.cnt) for r in mitre_rows]

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
    false_positive_rate: float
    alert_volume_7d: int
    cases_opened_7d: int
    cases_closed_7d: int
    analyst_overrides_7d: int


class AttackHeatmapCell(BaseModel):
    tactic: str
    technique: str
    count: int


class SOCMetrics(BaseModel):
    kpis: SOCKpis
    attack_heatmap: list[AttackHeatmapCell]


@router.get("/soc", response_model=SOCMetrics)
async def get_soc_metrics(
    user: AuthUser,
    db: DBSession,
) -> SOCMetrics:
    """Return SOC-level KPIs: MTTD, MTTR, FPR, and ATT&CK heatmap data."""
    tenant_id = user.tenant_id
    now = datetime.now(UTC)
    week_start = now - timedelta(days=7)

    # MTTD: mean time from alert creation to first investigation start
    mttd_q = await db.scalar(
        select(func.avg(
            func.extract("epoch", Alert.first_seen_at - Alert.created_at) / 3600
        )).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.first_seen_at.isnot(None),
                Alert.created_at >= week_start,
            )
        )
    )
    mttd_hours = float(mttd_q or 0.0)

    # MTTR: mean time from alert creation to resolution
    mttr_q = await db.scalar(
        select(func.avg(
            func.extract("epoch", Alert.updated_at - Alert.created_at) / 3600
        )).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.status == "resolved",
                Alert.created_at >= week_start,
            )
        )
    )
    mttr_hours = float(mttr_q or 0.0)

    # FPR: false positives / total resolved alerts (last 7d)
    total_resolved = await db.scalar(
        select(func.count()).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.status == "resolved",
                Alert.created_at >= week_start,
            )
        )
    ) or 0
    fp_count = await db.scalar(
        select(func.count()).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.status == "resolved",
                Alert.disposition == "false_positive",
                Alert.created_at >= week_start,
            )
        )
    ) or 0
    fpr = (fp_count / total_resolved) if total_resolved > 0 else 0.0

    # Alert volume 7d
    alert_vol = await db.scalar(
        select(func.count()).where(
            and_(Alert.tenant_id == tenant_id, Alert.created_at >= week_start)
        )
    ) or 0

    # Cases opened/closed 7d
    cases_opened = await db.scalar(
        select(func.count()).where(
            and_(Case.tenant_id == tenant_id, Case.created_at >= week_start)
        )
    ) or 0
    cases_closed = await db.scalar(
        select(func.count()).where(
            and_(
                Case.tenant_id == tenant_id,
                Case.status == "resolved",
                Case.updated_at >= week_start,
            )
        )
    ) or 0

    kpis = SOCKpis(
        mttd_hours=round(mttd_hours, 2),
        mttr_hours=round(mttr_hours, 2),
        false_positive_rate=round(fpr, 4),
        alert_volume_7d=alert_vol,
        cases_opened_7d=cases_opened,
        cases_closed_7d=cases_closed,
        analyst_overrides_7d=0,
    )

    # ATT&CK heatmap: technique + tactic breakdown
    heatmap_rows = (
        await db.execute(
            select(
                func.jsonb_array_elements_text(Alert.mitre_tactics).label("tactic"),
                func.jsonb_array_elements_text(Alert.mitre_techniques).label("technique"),
                func.count().label("cnt"),
            )
            .where(Alert.tenant_id == tenant_id)
            .group_by("tactic", "technique")
            .order_by(func.count().desc())
            .limit(50)
        )
    ).all()

    heatmap = [
        AttackHeatmapCell(tactic=r.tactic, technique=r.technique, count=r.cnt)
        for r in heatmap_rows
    ]

    return SOCMetrics(kpis=kpis, attack_heatmap=heatmap)


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
