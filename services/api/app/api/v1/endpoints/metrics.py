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
