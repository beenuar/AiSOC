"""Executive weekly digest builder.

WS-G2 — buyer-value plan
========================
Produces a deterministic, board-ready snapshot of the SOC over a fixed window
(default: the last 7 days). The output is plain Python dataclasses /
dictionaries that downstream renderers convert into:

  * JSON  — for the web UI to render an interactive panel.
  * HTML  — for `print to PDF` (no external PDF dependency required).

The module is intentionally split into:

  1. ``build_digest_from_rows`` — a *pure* function that consumes already-
     queried rows and produces an ``ExecutiveDigest``. This is what tests
     exercise; it has no async / DB dependencies and is fully deterministic.

  2. ``build_weekly_digest`` — a thin async orchestrator that runs SQL
     queries against the live tenant database and forwards rows into the
     pure builder. It contains *only* DB plumbing.

Keeping the heavy logic pure means we can ship a 100% deterministic test
matrix without spinning up Postgres, and we can later swap the data layer
(e.g. read replicas, OLAP store) without touching the digest contract.
"""

from __future__ import annotations

import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.case import Case
from app.models.remediation import RemediationGateLog

# ---------------------------------------------------------------------------
# Output schemas (Pydantic) — what the endpoint actually returns.
# ---------------------------------------------------------------------------


class DigestPeriod(BaseModel):
    start: datetime
    end: datetime
    label: str  # e.g. "May 2 – May 9, 2026"


class SeveritySplit(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AlertSummary(BaseModel):
    total: int
    new: int
    resolved: int
    open_at_period_end: int
    severity: SeveritySplit


class CaseSummary(BaseModel):
    opened: int
    closed: int
    open_at_period_end: int
    sla_breached: int


class MttSummary(BaseModel):
    """Mean time-to-X in hours (None if no qualifying samples)."""

    mttd_hours: float | None
    mttr_hours: float | None
    mttc_hours: float | None


class TacticHighlight(BaseModel):
    tactic: str
    count: int
    delta_from_prior: int  # positive = increase vs prior week


class TopSourceHighlight(BaseModel):
    connector_type: str
    count: int


class HighRiskAlertHighlight(BaseModel):
    alert_id: str
    title: str
    severity: str
    ai_score: float | None
    mitre_tactics: list[str]
    event_time: datetime


class AutomationSummary(BaseModel):
    total_decisions: int
    auto_executed: int
    escalated: int
    review_pending: int


class DigestRecommendation(BaseModel):
    severity: str  # "info" | "warning" | "critical"
    title: str
    body: str


class ExecutiveDigest(BaseModel):
    """Top-level deterministic snapshot of one digest window."""

    tenant_id: uuid.UUID
    period: DigestPeriod
    headline: str
    alerts: AlertSummary
    cases: CaseSummary
    mtt: MttSummary
    top_tactics: list[TacticHighlight] = Field(default_factory=list)
    top_sources: list[TopSourceHighlight] = Field(default_factory=list)
    high_risk_alerts: list[HighRiskAlertHighlight] = Field(default_factory=list)
    automation: AutomationSummary
    recommendations: list[DigestRecommendation] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Pure-data input rows — what the orchestrator hands to the builder.
# Plain dataclasses keep the test surface decoupled from SQLAlchemy.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AlertRow:
    severity: str
    status: str
    created_at: datetime
    resolved_at: datetime | None
    first_seen_at: datetime | None
    disposition: str | None
    mitre_tactics: list[str]
    connector_type: str | None
    ai_score: float | None
    title: str
    alert_id: str
    event_time: datetime


@dataclass(frozen=True)
class CaseRow:
    status: str
    created_at: datetime
    closed_at: datetime | None
    sla_breached: bool


@dataclass(frozen=True)
class GateLogRow:
    decision: str  # "auto" | "review" | "escalate" | other


@dataclass
class DigestInputs:
    """Bundle of pre-fetched rows for a tenant + period."""

    tenant_id: uuid.UUID
    period_start: datetime
    period_end: datetime
    current_alerts: list[AlertRow] = field(default_factory=list)
    prior_alerts: list[AlertRow] = field(default_factory=list)
    cases: list[CaseRow] = field(default_factory=list)
    gate_log: list[GateLogRow] = field(default_factory=list)
    open_alerts_at_period_end: int = 0
    open_cases_at_period_end: int = 0


# ---------------------------------------------------------------------------
# Pure helpers (independently unit-tested).
# ---------------------------------------------------------------------------


def _format_period_label(start: datetime, end: datetime) -> str:
    """Render a human-friendly span like "May 2 – May 9, 2026".

    Inclusive on the end side for readability; the actual query uses [start, end).
    """
    same_year = start.year == end.year
    same_month = same_year and start.month == end.month
    if same_month:
        return f"{start.strftime('%b %-d')} – {end.strftime('%-d, %Y')}"
    if same_year:
        return f"{start.strftime('%b %-d')} – {end.strftime('%b %-d, %Y')}"
    return f"{start.strftime('%b %-d, %Y')} – {end.strftime('%b %-d, %Y')}"


def _severity_split(rows: list[AlertRow]) -> SeveritySplit:
    counts = Counter(r.severity for r in rows)
    return SeveritySplit(
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        info=counts.get("info", 0),
    )


def _mean_hours(deltas: list[timedelta]) -> float | None:
    if not deltas:
        return None
    seconds = sum(d.total_seconds() for d in deltas)
    return round(seconds / len(deltas) / 3600, 2)


def _compute_mtt(rows: list[AlertRow]) -> MttSummary:
    """MTTD/MTTR/MTTC over a window."""
    detect: list[timedelta] = []
    respond: list[timedelta] = []
    contain: list[timedelta] = []

    for r in rows:
        if r.first_seen_at and r.first_seen_at >= r.created_at:
            detect.append(r.first_seen_at - r.created_at)
        if r.resolved_at and r.resolved_at >= r.created_at:
            respond.append(r.resolved_at - r.created_at)
            if r.disposition == "true_positive":
                contain.append(r.resolved_at - r.created_at)

    return MttSummary(
        mttd_hours=_mean_hours(detect),
        mttr_hours=_mean_hours(respond),
        mttc_hours=_mean_hours(contain),
    )


def _tactic_counts(rows: list[AlertRow]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for r in rows:
        for tactic in r.mitre_tactics or []:
            if isinstance(tactic, str) and tactic.strip():
                counter[tactic.strip()] += 1
    return counter


def _top_tactics(
    current: list[AlertRow],
    prior: list[AlertRow],
    *,
    limit: int = 5,
) -> list[TacticHighlight]:
    cur = _tactic_counts(current)
    pri = _tactic_counts(prior)
    highlights = [
        TacticHighlight(
            tactic=tactic,
            count=count,
            delta_from_prior=count - pri.get(tactic, 0),
        )
        for tactic, count in cur.most_common(limit)
    ]
    return highlights


def _top_sources(rows: list[AlertRow], *, limit: int = 5) -> list[TopSourceHighlight]:
    counter: Counter[str] = Counter()
    for r in rows:
        if r.connector_type:
            counter[r.connector_type] += 1
    return [TopSourceHighlight(connector_type=ct, count=cnt) for ct, cnt in counter.most_common(limit)]


def _high_risk_alerts(rows: list[AlertRow], *, limit: int = 5) -> list[HighRiskAlertHighlight]:
    """Return the top N alerts ranked by severity then ai_score then time.

    Severity ranking is deterministic regardless of input order.
    """
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def sort_key(r: AlertRow) -> tuple[int, float, float]:
        sev = severity_rank.get(r.severity, 5)
        # Higher AI score = more interesting; flip the sign so it sorts ascending.
        score = -1.0 * (r.ai_score if r.ai_score is not None else 0.0)
        # More recent first
        # Subtract from a fixed epoch so ordering is purely deterministic.
        return (sev, score, -r.event_time.timestamp())

    ranked = sorted(rows, key=sort_key)[:limit]
    return [
        HighRiskAlertHighlight(
            alert_id=r.alert_id,
            title=r.title,
            severity=r.severity,
            ai_score=r.ai_score,
            mitre_tactics=list(r.mitre_tactics or []),
            event_time=r.event_time,
        )
        for r in ranked
    ]


def _automation_summary(gate_log: list[GateLogRow]) -> AutomationSummary:
    counts = Counter(g.decision for g in gate_log)
    return AutomationSummary(
        total_decisions=len(gate_log),
        auto_executed=counts.get("auto", 0),
        escalated=counts.get("escalate", 0),
        review_pending=counts.get("review", 0),
    )


def _case_summary(rows: list[CaseRow], open_at_end: int, period_start: datetime, period_end: datetime) -> CaseSummary:
    opened = sum(1 for r in rows if period_start <= r.created_at < period_end)
    closed = sum(1 for r in rows if r.closed_at is not None and period_start <= r.closed_at < period_end)
    breached = sum(1 for r in rows if r.sla_breached)
    return CaseSummary(
        opened=opened,
        closed=closed,
        open_at_period_end=open_at_end,
        sla_breached=breached,
    )


def _alert_summary(
    rows: list[AlertRow],
    open_at_end: int,
    period_start: datetime,
    period_end: datetime,
) -> AlertSummary:
    new = sum(1 for r in rows if period_start <= r.created_at < period_end)
    resolved = sum(1 for r in rows if r.resolved_at is not None and period_start <= r.resolved_at < period_end)
    return AlertSummary(
        total=len(rows),
        new=new,
        resolved=resolved,
        open_at_period_end=open_at_end,
        severity=_severity_split(rows),
    )


def _build_headline(alerts: AlertSummary, mtt: MttSummary, automation: AutomationSummary) -> str:
    """One-line summary the CISO sees first."""
    parts: list[str] = []
    parts.append(f"{alerts.new} alerts ingested")
    if alerts.severity.critical:
        parts.append(f"{alerts.severity.critical} critical")
    parts.append(f"{alerts.resolved} resolved")
    if mtt.mttr_hours is not None:
        parts.append(f"MTTR {mtt.mttr_hours:.1f}h")
    if automation.total_decisions:
        auto_pct = round(automation.auto_executed / automation.total_decisions * 100)
        parts.append(f"{auto_pct}% auto-actioned")
    return " · ".join(parts)


def _build_recommendations(
    alerts: AlertSummary,
    cases: CaseSummary,
    mtt: MttSummary,
    automation: AutomationSummary,
    top_tactics: list[TacticHighlight],
) -> list[DigestRecommendation]:
    """Heuristic, deterministic CISO-facing call-to-actions.

    All thresholds are fixed and explainable; no ML required.
    """
    recs: list[DigestRecommendation] = []

    if alerts.severity.critical >= 5:
        recs.append(
            DigestRecommendation(
                severity="critical",
                title="Critical alert surge",
                body=(
                    f"{alerts.severity.critical} critical-severity alerts this period — "
                    "review the high-risk-alerts table below and confirm ownership."
                ),
            )
        )

    if cases.sla_breached > 0:
        recs.append(
            DigestRecommendation(
                severity="warning",
                title=f"{cases.sla_breached} SLA breach{'es' if cases.sla_breached != 1 else ''}",
                body=("One or more cases breached their SLA. Check assignment, escalation paths, and on-call coverage."),
            )
        )

    if mtt.mttr_hours is not None and mtt.mttr_hours > 24.0:
        recs.append(
            DigestRecommendation(
                severity="warning",
                title=f"MTTR is {mtt.mttr_hours:.1f}h",
                body=(
                    "Mean time to respond exceeded 24h. Consider tuning playbooks, "
                    "auto-actions for high-confidence detections, or analyst staffing."
                ),
            )
        )

    if automation.total_decisions and automation.review_pending / max(automation.total_decisions, 1) > 0.3:
        recs.append(
            DigestRecommendation(
                severity="info",
                title="High review-queue ratio",
                body=(
                    f"{automation.review_pending}/{automation.total_decisions} automation decisions "
                    "are still awaiting analyst review. Consider expanding the auto-execute "
                    "whitelist for low-blast-radius actions."
                ),
            )
        )

    rising = [t for t in top_tactics if t.delta_from_prior >= 5]
    if rising:
        names = ", ".join(t.tactic for t in rising[:3])
        recs.append(
            DigestRecommendation(
                severity="info",
                title="Rising MITRE tactics",
                body=f"Notable week-over-week increase in {names}.",
            )
        )

    if not recs:
        recs.append(
            DigestRecommendation(
                severity="info",
                title="No significant deviations",
                body="All headline metrics are within expected bounds for this tenant.",
            )
        )

    return recs


# ---------------------------------------------------------------------------
# Pure top-level builder.
# ---------------------------------------------------------------------------


def build_digest_from_rows(inputs: DigestInputs) -> ExecutiveDigest:
    """Pure function: rows in → ExecutiveDigest out. Deterministic."""
    period = DigestPeriod(
        start=inputs.period_start,
        end=inputs.period_end,
        label=_format_period_label(inputs.period_start, inputs.period_end),
    )

    alerts = _alert_summary(
        inputs.current_alerts,
        inputs.open_alerts_at_period_end,
        inputs.period_start,
        inputs.period_end,
    )
    cases = _case_summary(
        inputs.cases,
        inputs.open_cases_at_period_end,
        inputs.period_start,
        inputs.period_end,
    )
    mtt = _compute_mtt(inputs.current_alerts)
    top_tactics = _top_tactics(inputs.current_alerts, inputs.prior_alerts)
    top_sources = _top_sources(inputs.current_alerts)
    high_risk = _high_risk_alerts(inputs.current_alerts)
    automation = _automation_summary(inputs.gate_log)
    headline = _build_headline(alerts, mtt, automation)
    recommendations = _build_recommendations(alerts, cases, mtt, automation, top_tactics)

    return ExecutiveDigest(
        tenant_id=inputs.tenant_id,
        period=period,
        headline=headline,
        alerts=alerts,
        cases=cases,
        mtt=mtt,
        top_tactics=top_tactics,
        top_sources=top_sources,
        high_risk_alerts=high_risk,
        automation=automation,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# DB orchestrator — the only place SQLAlchemy lives.
# ---------------------------------------------------------------------------


async def _fetch_alerts(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> list[AlertRow]:
    rows: list[AlertRow] = []
    result = await db.execute(
        select(
            Alert.id,
            Alert.title,
            Alert.severity,
            Alert.status,
            Alert.created_at,
            Alert.resolved_at,
            Alert.first_seen_at,
            Alert.disposition,
            Alert.mitre_tactics,
            Alert.connector_type,
            Alert.ai_score,
            Alert.event_time,
        ).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= start,
                Alert.created_at < end,
            )
        )
    )
    for r in result.all():
        rows.append(
            AlertRow(
                alert_id=str(r.id),
                title=r.title or "",
                severity=r.severity or "info",
                status=r.status or "new",
                created_at=r.created_at,
                resolved_at=r.resolved_at,
                first_seen_at=r.first_seen_at,
                disposition=r.disposition,
                mitre_tactics=list(r.mitre_tactics or []),
                connector_type=r.connector_type,
                ai_score=float(r.ai_score) if r.ai_score is not None else None,
                event_time=r.event_time or r.created_at,
            )
        )
    return rows


async def _fetch_cases(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> list[CaseRow]:
    rows: list[CaseRow] = []
    result = await db.execute(
        select(
            Case.status,
            Case.created_at,
            Case.closed_at,
            Case.sla_breached,
        ).where(
            and_(
                Case.tenant_id == tenant_id,
                # Pull any case touched in the window: created OR closed in [start, end)
                # We keep this simple: created_at filter for opens, closed_at filter for closes.
                # Because we want both we union them.
                # (start window ≤ end window — guarded at the endpoint.)
                # SQLAlchemy doesn't have a clean OR boundary expression here,
                # so use a permissive lower-bound: created_at >= start - 30d, then
                # the pure builder filters precisely by date.
                Case.created_at >= start - timedelta(days=30),
            )
        )
    )
    for r in result.all():
        rows.append(
            CaseRow(
                status=r.status or "open",
                created_at=r.created_at,
                closed_at=r.closed_at,
                sla_breached=bool(r.sla_breached),
            )
        )
    return rows


async def _fetch_gate_log(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> list[GateLogRow]:
    result = await db.execute(
        select(RemediationGateLog.decision).where(
            and_(
                RemediationGateLog.tenant_id == tenant_id,
                RemediationGateLog.created_at >= start,
                RemediationGateLog.created_at < end,
            )
        )
    )
    return [GateLogRow(decision=r.decision or "unknown") for r in result.all()]


async def _count_open_alerts(db: AsyncSession, tenant_id: uuid.UUID, at: datetime) -> int:
    """Open == not resolved as of `at`."""
    val = await db.scalar(
        select(func.count()).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at < at,
                Alert.status != "resolved",
                Alert.status != "fp",
                Alert.status != "closed",
            )
        )
    )
    return int(val or 0)


async def _count_open_cases(db: AsyncSession, tenant_id: uuid.UUID, at: datetime) -> int:
    val = await db.scalar(
        select(func.count()).where(
            and_(
                Case.tenant_id == tenant_id,
                Case.created_at < at,
                Case.status != "resolved",
                Case.status != "closed",
            )
        )
    )
    return int(val or 0)


async def build_weekly_digest(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    period_start: datetime | None = None,
    period_end: datetime | None = None,
) -> ExecutiveDigest:
    """Async orchestrator: query the tenant DB and build an ``ExecutiveDigest``.

    Defaults to the most recent 7-day window ending now.
    """
    end = period_end or datetime.now(UTC)
    start = period_start or (end - timedelta(days=7))
    if start >= end:
        raise ValueError("period_start must be earlier than period_end")

    prior_start = start - (end - start)
    prior_end = start

    current_alerts = await _fetch_alerts(db, tenant_id, start, end)
    prior_alerts = await _fetch_alerts(db, tenant_id, prior_start, prior_end)
    cases = await _fetch_cases(db, tenant_id, start, end)
    gate_log = await _fetch_gate_log(db, tenant_id, start, end)
    open_alerts = await _count_open_alerts(db, tenant_id, end)
    open_cases = await _count_open_cases(db, tenant_id, end)

    inputs = DigestInputs(
        tenant_id=tenant_id,
        period_start=start,
        period_end=end,
        current_alerts=current_alerts,
        prior_alerts=prior_alerts,
        cases=cases,
        gate_log=gate_log,
        open_alerts_at_period_end=open_alerts,
        open_cases_at_period_end=open_cases,
    )
    return build_digest_from_rows(inputs)


__all__ = [
    "AlertRow",
    "AlertSummary",
    "AutomationSummary",
    "CaseRow",
    "CaseSummary",
    "DigestInputs",
    "DigestPeriod",
    "DigestRecommendation",
    "ExecutiveDigest",
    "GateLogRow",
    "HighRiskAlertHighlight",
    "MttSummary",
    "SeveritySplit",
    "TacticHighlight",
    "TopSourceHighlight",
    "build_digest_from_rows",
    "build_weekly_digest",
    "_internal_helpers",  # accessed by test suite for private helper coverage
]


# Internal helpers exported for tests.
_internal_helpers: dict[str, Any] = {
    "_format_period_label": _format_period_label,
    "_severity_split": _severity_split,
    "_mean_hours": _mean_hours,
    "_compute_mtt": _compute_mtt,
    "_top_tactics": _top_tactics,
    "_top_sources": _top_sources,
    "_high_risk_alerts": _high_risk_alerts,
    "_automation_summary": _automation_summary,
    "_case_summary": _case_summary,
    "_alert_summary": _alert_summary,
    "_build_headline": _build_headline,
    "_build_recommendations": _build_recommendations,
}
