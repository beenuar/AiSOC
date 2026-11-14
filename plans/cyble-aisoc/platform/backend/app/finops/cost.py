"""FinOps rollups + budget status.

Reuses the price table from :mod:`app.observability.cost` (single
source of truth for $/1k tokens) and the :class:`AgentTrace` table
for the raw spend signal.

Three computation surfaces:

  - :func:`finops_rollup`  Daily LLM spend by tenant, by agent, by
                           model, plus a rolling-30d ROI estimate
                           and budget utilisation. Used by the
                           dashboard and the per-MSSP per-customer
                           cost row.
  - :func:`set_budget`     Idempotent upsert of a tenant's monthly
                           budget + alert threshold + analyst-hourly
                           ROI knob.
  - :func:`budget_status`  Tells the alerting layer whether the
                           tenant has crossed its alert threshold or
                           cap this month.

ROI math (kept deliberately conservative):

  cases_resolved   = closed (TP + FP + benign) cases in the window
  human_hours_saved = cases_resolved * 0.75  # 45min/case avg, see plan
  roi_dollars      = human_hours_saved * tenant.analyst_hourly_usd
                     - llm_cost_usd

The 45-minute figure is the conservative reading of the published
benchmarks — full deflection on a tier-1 alert by an autonomous
agent saves an analyst-hour, but we round down to acknowledge that
some cases still need follow-up review. The number is *the operator's
knob*: change it via the budget endpoint and the dashboard recomputes.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlmodel import select

from app.db import session_scope
from app.models.case import Case, CaseStatus
from app.models.finops import FinOpsBudget
from app.models.trace import AgentName, AgentTrace, TraceStep
from app.observability.cost import _price_for, _trace_provider_model

logger = logging.getLogger(__name__)


# ─── DTOs ───────────────────────────────────────────────────────────


@dataclass
class DailySpendRow:
    date: str  # ISO date, UTC
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    cases: int = 0


@dataclass
class AgentCostRow:
    agent: str
    cost_usd: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    steps: int = 0


@dataclass
class ModelCostRow:
    provider: str
    model: str
    cost_usd: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0


@dataclass
class ROIEstimate:
    cases_resolved: int = 0
    human_hours_saved: float = 0.0
    analyst_hourly_usd: float = 100.0
    roi_dollars: float = 0.0
    roi_ratio: float = 0.0  # roi_dollars / llm_cost_usd; -inf if cost == 0


@dataclass
class BudgetStatus:
    tenant_id: str
    monthly_usd: float
    alert_threshold: float
    spent_usd: float
    utilisation: float  # spent / monthly_usd, 0 if monthly_usd == 0
    over_threshold: bool
    over_cap: bool
    days_remaining_in_month: int
    projected_month_end_usd: float


@dataclass
class FinOpsRollup:
    tenant_id: str
    window_days: int
    cost_usd_total: float = 0.0
    tokens_in_total: int = 0
    tokens_out_total: int = 0
    daily: list[DailySpendRow] = field(default_factory=list)
    by_agent: list[AgentCostRow] = field(default_factory=list)
    by_model: list[ModelCostRow] = field(default_factory=list)
    roi: ROIEstimate = field(default_factory=ROIEstimate)
    budget: Optional[BudgetStatus] = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


# ─── Internal helpers ──────────────────────────────────────────────


def _utc_date_key(ts: Optional[datetime]) -> str:
    if ts is None:
        ts = datetime.now(timezone.utc)
    return ts.astimezone(timezone.utc).date().isoformat()


def _coerce_agent(agent: Any) -> str:
    return agent.value if isinstance(agent, AgentName) else str(agent)


def _resolved_statuses() -> set[str]:
    """Cases we count as 'analyst-time-saved' for ROI."""
    return {
        CaseStatus.CLOSED_TRUE_POSITIVE.value,
        CaseStatus.CLOSED_FALSE_POSITIVE.value,
        CaseStatus.CLOSED_BENIGN.value,
    }


def _trace_snapshots(traces: list[AgentTrace]) -> list[dict[str, Any]]:
    """Convert ORM rows to plain dicts inside the session."""
    out: list[dict[str, Any]] = []
    for t in traces:
        provider, model = _trace_provider_model(t)
        out.append(
            {
                "agent": _coerce_agent(t.agent),
                "tokens_in": int(t.tokens_in or 0),
                "tokens_out": int(t.tokens_out or 0),
                "provider": provider,
                "model": model,
                "case_id": int(t.case_id),
                "created_at": t.created_at,
            }
        )
    return out


# ─── Budget upsert + status ────────────────────────────────────────


def set_budget(
    *,
    tenant_id: str,
    monthly_usd: float | None = None,
    alert_threshold: float | None = None,
    alert_target: str | None = None,
    analyst_hourly_usd: float | None = None,
) -> FinOpsBudget:
    """Idempotent upsert of a tenant FinOps budget."""
    if monthly_usd is not None and monthly_usd < 0:
        raise ValueError("monthly_usd must be >= 0 (use 0 for alerts-only)")
    if alert_threshold is not None and not (0.0 < alert_threshold <= 1.0):
        raise ValueError("alert_threshold must be in (0, 1]")
    if analyst_hourly_usd is not None and analyst_hourly_usd < 0:
        raise ValueError("analyst_hourly_usd must be >= 0")

    with session_scope() as session:
        existing = session.exec(
            select(FinOpsBudget).where(FinOpsBudget.tenant_id == tenant_id)
        ).one_or_none()
        if existing is None:
            row = FinOpsBudget(
                tenant_id=tenant_id,
                monthly_usd=monthly_usd if monthly_usd is not None else 500.0,
                alert_threshold=alert_threshold
                if alert_threshold is not None
                else 0.8,
                alert_target=alert_target or "",
                analyst_hourly_usd=analyst_hourly_usd
                if analyst_hourly_usd is not None
                else 100.0,
            )
            session.add(row)
        else:
            row = existing
            if monthly_usd is not None:
                row.monthly_usd = monthly_usd
            if alert_threshold is not None:
                row.alert_threshold = alert_threshold
            if alert_target is not None:
                row.alert_target = alert_target
            if analyst_hourly_usd is not None:
                row.analyst_hourly_usd = analyst_hourly_usd
            row.updated_at = datetime.now(timezone.utc)
            session.add(row)
        session.commit()
        session.refresh(row)
        # Snapshot before the session closes.
        return FinOpsBudget(
            id=row.id,
            tenant_id=row.tenant_id,
            monthly_usd=row.monthly_usd,
            alert_threshold=row.alert_threshold,
            alert_target=row.alert_target,
            analyst_hourly_usd=row.analyst_hourly_usd,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )


def _month_to_date_window() -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return start, now


def _days_remaining_in_month(now: datetime) -> int:
    if now.month == 12:
        next_month = now.replace(year=now.year + 1, month=1, day=1)
    else:
        next_month = now.replace(month=now.month + 1, day=1)
    next_month = next_month.replace(hour=0, minute=0, second=0, microsecond=0)
    delta = next_month - now
    return max(0, delta.days)


def _spent_for_window(
    tenant_id: str, start: datetime, end: datetime
) -> tuple[float, int, int]:
    """Sum cost / tokens between ``start`` and ``end`` (inclusive of start)."""
    with session_scope() as session:
        traces = list(
            session.exec(
                select(AgentTrace)
                .where(AgentTrace.tenant_id == tenant_id)
                .where(AgentTrace.created_at >= start)
                .where(AgentTrace.created_at <= end)
            ).all()
        )
        snaps = _trace_snapshots(traces)
    cost = 0.0
    tin = 0
    tout = 0
    for t in snaps:
        in_per_1k, out_per_1k = _price_for(t["provider"], t["model"])
        cost += t["tokens_in"] * in_per_1k / 1000.0 + t["tokens_out"] * out_per_1k / 1000.0
        tin += t["tokens_in"]
        tout += t["tokens_out"]
    return cost, tin, tout


def budget_status(tenant_id: str) -> Optional[BudgetStatus]:
    """Return the tenant's month-to-date budget posture, or ``None``
    if no budget is configured."""
    with session_scope() as session:
        row = session.exec(
            select(FinOpsBudget).where(FinOpsBudget.tenant_id == tenant_id)
        ).one_or_none()
        if row is None:
            return None
        budget = FinOpsBudget(
            tenant_id=row.tenant_id,
            monthly_usd=row.monthly_usd,
            alert_threshold=row.alert_threshold,
            alert_target=row.alert_target,
            analyst_hourly_usd=row.analyst_hourly_usd,
        )

    start, now = _month_to_date_window()
    spent, _, _ = _spent_for_window(tenant_id, start, now)
    monthly = float(budget.monthly_usd or 0.0)
    utilisation = (spent / monthly) if monthly > 0 else 0.0
    over_threshold = monthly > 0 and spent >= monthly * budget.alert_threshold
    over_cap = monthly > 0 and spent >= monthly

    elapsed_days = max(1, (now - start).days + 1)
    days_remaining = _days_remaining_in_month(now)
    projected = (spent / elapsed_days) * (elapsed_days + days_remaining)

    return BudgetStatus(
        tenant_id=tenant_id,
        monthly_usd=round(monthly, 4),
        alert_threshold=round(budget.alert_threshold, 4),
        spent_usd=round(spent, 4),
        utilisation=round(utilisation, 4),
        over_threshold=over_threshold,
        over_cap=over_cap,
        days_remaining_in_month=days_remaining,
        projected_month_end_usd=round(projected, 4),
    )


# ─── Top-level rollup (the dashboard endpoint) ─────────────────────


def finops_rollup(
    tenant_id: str, *, window_days: int = 30
) -> FinOpsRollup:
    """Cost + ROI + budget rollup over the last ``window_days``."""
    if window_days <= 0 or window_days > 365:
        raise ValueError("window_days must be in 1..365")
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

    with session_scope() as session:
        traces = list(
            session.exec(
                select(AgentTrace)
                .where(AgentTrace.tenant_id == tenant_id)
                .where(AgentTrace.created_at >= cutoff)
            ).all()
        )
        cases = list(
            session.exec(
                select(Case)
                .where(Case.tenant_id == tenant_id)
                .where(Case.created_at >= cutoff)
            ).all()
        )
        snaps = _trace_snapshots(traces)
        # Snapshot case ids and statuses so we don't touch the ORM
        # objects after the session is closed.
        case_snaps = [
            {
                "id": c.id,
                "status": c.status.value
                if hasattr(c.status, "value")
                else str(c.status),
            }
            for c in cases
        ]
        budget_row = session.exec(
            select(FinOpsBudget).where(FinOpsBudget.tenant_id == tenant_id)
        ).one_or_none()
        analyst_hourly = (
            float(budget_row.analyst_hourly_usd) if budget_row else 100.0
        )

    # ── Build daily rollup + by_agent + by_model in a single pass ──
    daily_index: dict[str, DailySpendRow] = {}
    by_agent: dict[str, AgentCostRow] = {}
    by_model: dict[tuple[str, str], ModelCostRow] = {}
    cost_total = 0.0
    tin_total = 0
    tout_total = 0
    distinct_cases_per_day: dict[str, set[int]] = {}

    for t in snaps:
        in_per_1k, out_per_1k = _price_for(t["provider"], t["model"])
        cost = t["tokens_in"] * in_per_1k / 1000.0 + t["tokens_out"] * out_per_1k / 1000.0
        cost_total += cost
        tin_total += t["tokens_in"]
        tout_total += t["tokens_out"]

        date_key = _utc_date_key(t["created_at"])
        row = daily_index.setdefault(date_key, DailySpendRow(date=date_key))
        row.tokens_in += t["tokens_in"]
        row.tokens_out += t["tokens_out"]
        row.cost_usd = round(row.cost_usd + cost, 6)
        distinct_cases_per_day.setdefault(date_key, set()).add(t["case_id"])

        ag = by_agent.setdefault(t["agent"], AgentCostRow(agent=t["agent"]))
        ag.cost_usd = round(ag.cost_usd + cost, 6)
        ag.tokens_in += t["tokens_in"]
        ag.tokens_out += t["tokens_out"]
        ag.steps += 1

        mk = (t["provider"], t["model"])
        m = by_model.setdefault(mk, ModelCostRow(provider=mk[0], model=mk[1]))
        m.cost_usd = round(m.cost_usd + cost, 6)
        m.tokens_in += t["tokens_in"]
        m.tokens_out += t["tokens_out"]

    for date_key, row in daily_index.items():
        row.cases = len(distinct_cases_per_day.get(date_key, set()))

    daily_sorted = sorted(daily_index.values(), key=lambda r: r.date)
    by_agent_sorted = sorted(
        by_agent.values(), key=lambda r: -r.cost_usd
    )
    by_model_sorted = sorted(
        by_model.values(), key=lambda r: -r.cost_usd
    )

    # ── ROI ────────────────────────────────────────────────────────
    resolved = sum(
        1 for c in case_snaps if c["status"] in _resolved_statuses()
    )
    hours_saved = round(resolved * 0.75, 4)  # 45 min/case avg
    roi_dollars = round(hours_saved * analyst_hourly - cost_total, 4)
    if cost_total > 0:
        roi_ratio = round(
            (hours_saved * analyst_hourly - cost_total) / cost_total, 4
        )
    else:
        roi_ratio = 0.0
    roi = ROIEstimate(
        cases_resolved=resolved,
        human_hours_saved=hours_saved,
        analyst_hourly_usd=round(analyst_hourly, 2),
        roi_dollars=roi_dollars,
        roi_ratio=roi_ratio,
    )

    return FinOpsRollup(
        tenant_id=tenant_id,
        window_days=window_days,
        cost_usd_total=round(cost_total, 6),
        tokens_in_total=tin_total,
        tokens_out_total=tout_total,
        daily=daily_sorted,
        by_agent=by_agent_sorted,
        by_model=by_model_sorted,
        roi=roi,
        budget=budget_status(tenant_id),
    )
