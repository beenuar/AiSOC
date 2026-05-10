"""Cost dashboard builder.

WS-H1 — buyer-value plan
========================
Produces a deterministic snapshot of LLM spend, automation activity and
BYOK savings for a tenant over a fixed window (default: last 30 days).

The output backs the admin cost dashboard at
``apps/web/src/app/(admin)/costs/`` and answers:

  * Where is my LLM money going? (daily time-series + per-model breakdown)
  * Which investigations are the most expensive? (top-cost cases)
  * How much SOC activity am I getting for that money? (action counts)
  * Am I saving money by running my own model? (BYOK imputed savings)

Following the WS-G2 pattern, the module splits into:

  1. ``build_dashboard_from_rows`` — a *pure* function that consumes
     pre-fetched rows and emits a ``CostDashboard``. Fully deterministic
     and tested without a database.

  2. ``build_cost_dashboard`` — a thin async orchestrator that runs the
     SQL queries and forwards rows into the pure builder.

BYOK savings are *imputed*: we re-price every recorded prompt+completion
token pair against the public list price for the model that handled it
(``cost_telemetry._PRICING``). When the runtime LLM is local
(``llm_status().is_local``), the difference between imputed cost and
recorded cost approximates what the operator would have paid a hosted
provider had they not brought their own key. We never claim this is a
billing-grade number — the response carries an ``is_byok_active`` flag so
the UI can label the panel accordingly.
"""

from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# ---------------------------------------------------------------------------
# Public list pricing for BYOK imputation.
#
# Mirrors ``services/agents/app/core/cost_telemetry._PRICING`` but lives
# here too so the API service doesn't need to import from the agents
# package (different deploy unit, no cross-import in production).
# Prices are USD per 1k tokens, (input, output).
# ---------------------------------------------------------------------------

_PUBLIC_PRICING: dict[str, tuple[float, float]] = {
    "gpt-4o": (0.005, 0.015),
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-4-turbo": (0.01, 0.03),
    "gpt-4": (0.03, 0.06),
    "gpt-3.5-turbo": (0.0005, 0.0015),
    "claude-3-5-sonnet-20241022": (0.003, 0.015),
    "claude-3-opus-20240229": (0.015, 0.075),
    "claude-3-haiku-20240307": (0.00025, 0.00125),
    "gemini-1.5-pro": (0.00125, 0.005),
    "gemini-1.5-flash": (0.000075, 0.0003),
}

# Conservative default for unknown models so we don't claim massive
# savings on a bespoke local model that has no public list price.
_DEFAULT_PUBLIC_PRICING: tuple[float, float] = (0.001, 0.002)


def _impute_public_cost(
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> float:
    """Return what ``model`` would cost on its public list price."""
    in_price, out_price = _PUBLIC_PRICING.get(
        (model or "").lower(),
        _DEFAULT_PUBLIC_PRICING,
    )
    return round(
        (max(prompt_tokens, 0) / 1000) * in_price + (max(completion_tokens, 0) / 1000) * out_price,
        6,
    )


# ---------------------------------------------------------------------------
# Output schemas (Pydantic) — what the endpoint returns.
# ---------------------------------------------------------------------------


class DashboardPeriod(BaseModel):
    start: datetime
    end: datetime
    window_days: int
    label: str


class CostBucket(BaseModel):
    """LLM spend bucketed by day."""

    day: date
    total_cost_usd: float
    total_tokens: int
    call_count: int


class ModelBreakdown(BaseModel):
    """Spend / volume rolled up per model over the window."""

    model: str
    runs: int
    calls: int
    total_prompt_tokens: int
    total_completion_tokens: int
    total_cost_usd: float
    imputed_public_cost_usd: float
    avg_latency_ms: float | None


class TopCostCase(BaseModel):
    """The most expensive cases over the window.

    Top-cost playbooks ≈ top-cost cases in the AiSOC data model: a
    case is the unit of work an analyst (or playbook) drives, and
    ``investigation_runs.case_id`` is the only stable join we can make
    between LLM cost and "what was this money spent on?".
    """

    case_id: str
    runs: int
    total_cost_usd: float
    total_tokens: int


class ActionCount(BaseModel):
    """How many of each kind of action SOC operators took."""

    action: str
    count: int


class ByokSavings(BaseModel):
    """Imputed savings vs hosted pricing.

    ``is_byok_active`` is True when the live LLM provider (per
    ``/llm/status``) is loopback or private — i.e. the operator is
    actually running their own model. When False, the savings are still
    computed (so the UI can show "if you switched to BYOK, you'd save
    ~X") but should be labelled "potential savings" in the UI.
    """

    is_byok_active: bool
    provider: str
    recorded_cost_usd: float
    imputed_public_cost_usd: float
    savings_usd: float


class CostHeadline(BaseModel):
    total_cost_usd: float
    total_tokens: int
    total_calls: int
    total_runs: int
    avg_cost_per_run_usd: float | None


class CostDashboard(BaseModel):
    """Top-level deterministic snapshot."""

    tenant_id: uuid.UUID
    period: DashboardPeriod
    headline: CostHeadline
    daily_costs: list[CostBucket] = Field(default_factory=list)
    by_model: list[ModelBreakdown] = Field(default_factory=list)
    top_cases: list[TopCostCase] = Field(default_factory=list)
    action_counts: list[ActionCount] = Field(default_factory=list)
    byok_savings: ByokSavings


# ---------------------------------------------------------------------------
# Pure-data input rows.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CostRow:
    """One ``aisoc_run_costs`` row joined with its investigation_run."""

    run_id: str
    case_id: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float
    latency_ms: float
    call_count: int
    started_at: datetime


@dataclass(frozen=True)
class AuditRow:
    """One ``audit_log`` row reduced to its action."""

    action: str


@dataclass(frozen=True)
class LlmContext:
    """Live LLM provider snapshot (subset of ``llm_status()``)."""

    provider: str
    is_local: bool


@dataclass
class DashboardInputs:
    """Bundle of pre-fetched rows for a tenant + period."""

    tenant_id: uuid.UUID
    period_start: datetime
    period_end: datetime
    cost_rows: list[CostRow] = field(default_factory=list)
    audit_rows: list[AuditRow] = field(default_factory=list)
    llm: LlmContext = field(default_factory=lambda: LlmContext(provider="none", is_local=False))


# ---------------------------------------------------------------------------
# Pure helpers (independently unit-tested).
# ---------------------------------------------------------------------------


def _format_period_label(start: datetime, end: datetime) -> str:
    """Render a human-friendly span like "Apr 9 – May 9, 2026"."""
    same_year = start.year == end.year
    same_month = same_year and start.month == end.month
    if same_month:
        return f"{start.strftime('%b %-d')} – {end.strftime('%-d, %Y')}"
    if same_year:
        return f"{start.strftime('%b %-d')} – {end.strftime('%b %-d, %Y')}"
    return f"{start.strftime('%b %-d, %Y')} – {end.strftime('%b %-d, %Y')}"


def _bucket_by_day(rows: list[CostRow]) -> list[CostBucket]:
    """Group cost rows by UTC calendar date, ascending."""
    buckets: dict[date, dict[str, float]] = defaultdict(lambda: {"cost": 0.0, "tokens": 0, "calls": 0})
    for r in rows:
        d = r.started_at.astimezone(UTC).date()
        b = buckets[d]
        b["cost"] += r.cost_usd
        b["tokens"] += r.prompt_tokens + r.completion_tokens
        b["calls"] += r.call_count
    return [
        CostBucket(
            day=d,
            total_cost_usd=round(buckets[d]["cost"], 4),
            total_tokens=int(buckets[d]["tokens"]),
            call_count=int(buckets[d]["calls"]),
        )
        for d in sorted(buckets)
    ]


def _model_breakdown(rows: list[CostRow]) -> list[ModelBreakdown]:
    """Aggregate rows per model, sorted by spend descending."""
    by_model: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "runs": set(),
            "calls": 0,
            "prompt": 0,
            "completion": 0,
            "cost": 0.0,
            "imputed": 0.0,
            "latency_ms": 0.0,
        }
    )
    for r in rows:
        m = (r.model or "unknown").lower()
        agg = by_model[m]
        agg["runs"].add(r.run_id)
        agg["calls"] += r.call_count
        agg["prompt"] += r.prompt_tokens
        agg["completion"] += r.completion_tokens
        agg["cost"] += r.cost_usd
        agg["imputed"] += _impute_public_cost(m, r.prompt_tokens, r.completion_tokens)
        agg["latency_ms"] += r.latency_ms

    breakdowns = [
        ModelBreakdown(
            model=m,
            runs=len(agg["runs"]),
            calls=int(agg["calls"]),
            total_prompt_tokens=int(agg["prompt"]),
            total_completion_tokens=int(agg["completion"]),
            total_cost_usd=round(agg["cost"], 4),
            imputed_public_cost_usd=round(agg["imputed"], 4),
            avg_latency_ms=(round(agg["latency_ms"] / agg["calls"], 2) if agg["calls"] else None),
        )
        for m, agg in by_model.items()
    ]
    breakdowns.sort(key=lambda b: (-b.total_cost_usd, b.model))
    return breakdowns


def _top_cases(rows: list[CostRow], *, limit: int = 10) -> list[TopCostCase]:
    """The most expensive cases in the window."""
    by_case: dict[str, dict[str, Any]] = defaultdict(lambda: {"runs": set(), "cost": 0.0, "tokens": 0})
    for r in rows:
        if not r.case_id:
            continue
        agg = by_case[r.case_id]
        agg["runs"].add(r.run_id)
        agg["cost"] += r.cost_usd
        agg["tokens"] += r.prompt_tokens + r.completion_tokens

    items = [
        TopCostCase(
            case_id=case_id,
            runs=len(agg["runs"]),
            total_cost_usd=round(agg["cost"], 4),
            total_tokens=int(agg["tokens"]),
        )
        for case_id, agg in by_case.items()
    ]
    items.sort(key=lambda c: (-c.total_cost_usd, c.case_id))
    return items[:limit]


def _action_counts(rows: list[AuditRow], *, limit: int = 20) -> list[ActionCount]:
    """How many of each action were recorded over the window."""
    counter: Counter[str] = Counter(r.action for r in rows if r.action)
    return [ActionCount(action=a, count=c) for a, c in counter.most_common(limit)]


def _byok_savings(rows: list[CostRow], llm: LlmContext) -> ByokSavings:
    """Imputed savings vs hosted public pricing.

    The ``recorded_cost_usd`` reflects what the cost tracker actually
    booked: on a hosted provider this is the public price, on a local
    BYOK provider this is the *imputed* price (the agents service uses
    the same pricing table when no upstream billing exists, so on
    BYOK the recorded cost typically already matches imputed and the
    delta is small or zero).

    Therefore on BYOK we report ``savings = imputed_public`` (i.e. the
    operator avoided paying the hosted provider entirely). On a hosted
    provider we report ``savings = max(imputed - recorded, 0)`` so the
    UI can still surface a "you'd save X if you self-hosted" hint.
    """
    recorded = sum(r.cost_usd for r in rows)
    imputed = sum(_impute_public_cost(r.model, r.prompt_tokens, r.completion_tokens) for r in rows)
    if llm.is_local:
        savings = imputed
    else:
        savings = max(imputed - recorded, 0.0)
    return ByokSavings(
        is_byok_active=bool(llm.is_local),
        provider=llm.provider or "unknown",
        recorded_cost_usd=round(recorded, 4),
        imputed_public_cost_usd=round(imputed, 4),
        savings_usd=round(savings, 4),
    )


def _headline(rows: list[CostRow]) -> CostHeadline:
    total_cost = sum(r.cost_usd for r in rows)
    total_tokens = sum(r.prompt_tokens + r.completion_tokens for r in rows)
    total_calls = sum(r.call_count for r in rows)
    total_runs = len({r.run_id for r in rows if r.run_id})
    return CostHeadline(
        total_cost_usd=round(total_cost, 4),
        total_tokens=int(total_tokens),
        total_calls=int(total_calls),
        total_runs=total_runs,
        avg_cost_per_run_usd=(round(total_cost / total_runs, 4) if total_runs else None),
    )


# ---------------------------------------------------------------------------
# Pure top-level builder.
# ---------------------------------------------------------------------------


def build_dashboard_from_rows(inputs: DashboardInputs) -> CostDashboard:
    """Pure function: rows in → CostDashboard out. Deterministic."""
    window_days = max(
        int(round((inputs.period_end - inputs.period_start).total_seconds() / 86400)),
        1,
    )
    period = DashboardPeriod(
        start=inputs.period_start,
        end=inputs.period_end,
        window_days=window_days,
        label=_format_period_label(inputs.period_start, inputs.period_end),
    )
    return CostDashboard(
        tenant_id=inputs.tenant_id,
        period=period,
        headline=_headline(inputs.cost_rows),
        daily_costs=_bucket_by_day(inputs.cost_rows),
        by_model=_model_breakdown(inputs.cost_rows),
        top_cases=_top_cases(inputs.cost_rows),
        action_counts=_action_counts(inputs.audit_rows),
        byok_savings=_byok_savings(inputs.cost_rows, inputs.llm),
    )


# ---------------------------------------------------------------------------
# DB orchestrator — the only place SQL lives.
# ---------------------------------------------------------------------------


_COST_QUERY = text(
    """
    SELECT c.run_id,
           r.case_id,
           c.model,
           c.total_prompt_tokens     AS prompt_tokens,
           c.total_completion_tokens AS completion_tokens,
           c.total_cost_usd          AS cost_usd,
           c.total_latency_ms        AS latency_ms,
           c.call_count              AS call_count,
           r.started_at              AS started_at
    FROM aisoc_run_costs c
    JOIN investigation_runs r ON r.id::text = c.run_id
    WHERE r.tenant_id = :tenant_id
      AND r.started_at >= :start_at
      AND r.started_at < :end_at
    """
)


_AUDIT_QUERY = text(
    """
    SELECT action
    FROM audit_log
    WHERE tenant_id = :tenant_id
      AND created_at >= :start_at
      AND created_at < :end_at
    """
)


async def _fetch_cost_rows(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> list[CostRow]:
    result = await db.execute(
        _COST_QUERY,
        {"tenant_id": str(tenant_id), "start_at": start, "end_at": end},
    )
    rows: list[CostRow] = []
    for r in result.mappings():
        started_at = r["started_at"]
        if started_at is not None and started_at.tzinfo is None:
            started_at = started_at.replace(tzinfo=UTC)
        rows.append(
            CostRow(
                run_id=str(r["run_id"]),
                case_id=str(r["case_id"] or ""),
                model=str(r["model"] or "unknown"),
                prompt_tokens=int(r["prompt_tokens"] or 0),
                completion_tokens=int(r["completion_tokens"] or 0),
                cost_usd=float(r["cost_usd"] or 0.0),
                latency_ms=float(r["latency_ms"] or 0.0),
                call_count=int(r["call_count"] or 0),
                started_at=started_at or end,
            )
        )
    return rows


async def _fetch_audit_rows(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    start: datetime,
    end: datetime,
) -> list[AuditRow]:
    result = await db.execute(
        _AUDIT_QUERY,
        {"tenant_id": str(tenant_id), "start_at": start, "end_at": end},
    )
    return [AuditRow(action=str(r["action"] or "")) for r in result.mappings()]


async def build_cost_dashboard(
    db: AsyncSession,
    tenant_id: uuid.UUID,
    *,
    window_days: int = 30,
    period_end: datetime | None = None,
    llm_provider: str | None = None,
    is_local: bool | None = None,
) -> CostDashboard:
    """Async orchestrator: query the tenant DB and build a ``CostDashboard``.

    ``window_days`` is clamped to ``[1, 365]`` so a malformed query
    parameter cannot cause an unbounded scan. ``llm_provider`` /
    ``is_local`` come from ``llm_status()`` and are threaded through so
    the BYOK panel reports against the real runtime config.
    """
    if window_days < 1:
        window_days = 1
    if window_days > 365:
        window_days = 365

    end = period_end or datetime.now(UTC)
    start = end - timedelta(days=window_days)

    cost_rows = await _fetch_cost_rows(db, tenant_id, start, end)
    audit_rows = await _fetch_audit_rows(db, tenant_id, start, end)

    inputs = DashboardInputs(
        tenant_id=tenant_id,
        period_start=start,
        period_end=end,
        cost_rows=cost_rows,
        audit_rows=audit_rows,
        llm=LlmContext(
            provider=llm_provider or "unknown",
            is_local=bool(is_local),
        ),
    )
    return build_dashboard_from_rows(inputs)


__all__ = [
    "ActionCount",
    "AuditRow",
    "ByokSavings",
    "CostBucket",
    "CostDashboard",
    "CostHeadline",
    "CostRow",
    "DashboardInputs",
    "DashboardPeriod",
    "LlmContext",
    "ModelBreakdown",
    "TopCostCase",
    "build_cost_dashboard",
    "build_dashboard_from_rows",
]


# Internal helpers exported for tests.
_internal_helpers: dict[str, Any] = {
    "_format_period_label": _format_period_label,
    "_bucket_by_day": _bucket_by_day,
    "_model_breakdown": _model_breakdown,
    "_top_cases": _top_cases,
    "_action_counts": _action_counts,
    "_byok_savings": _byok_savings,
    "_headline": _headline,
    "_impute_public_cost": _impute_public_cost,
}
