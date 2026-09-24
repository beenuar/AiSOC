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

Every dollar figure carries its provenance
------------------------------------------
Cost arrives here already classified by the agents service (migration 063):

``measured``
    The LiteLLM gateway reported what the call cost. Real money. A measured
    ``0.0`` — what a local model genuinely costs — is a fact, not a gap.

``estimated``
    Re-priced from a public list price for a **concrete** model id. An
    approximation, and labelled one on every surface, including this one.

``unpriced``
    Neither. Reported as *not measured*.

The counts travel with the sums, so a zero can be told from an absence. This
follows the MTTR precedent in ``api/v1/endpoints/metrics.py``, where a mean
over zero rows shipped as a confident ``0.0`` until its sample count came
with it. Without that, this dashboard could not distinguish "the agents spent
nothing" from "nobody told us what the agents spent", and it rendered the
first — a free AI-SOC, for a tenant nobody had priced.

There is deliberately no field summing measured and estimated together. One
number cannot be labelled two ways, and adding a guess to a measurement is
how the guess stops looking like one.

BYOK savings are *imputed*: we re-price recorded prompt+completion token
pairs against the public list price for the model that handled them. Only
models this table actually knows a price for are imputed at all — there is no
default rate, because a default rate is how the tracker came to invent
$0.000999 for a free local run in the first place. The response carries
``is_byok_active`` plus the number of tokens that could not be priced, so the
UI can say how much of the estimate is missing rather than implying none is.
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

# There is no default rate, on purpose. This table used to fall back to
# (0.001, 0.002) for anything it did not recognise, and what it did not
# recognise was *every* row: the agents service records the `aisoc-<role>`
# alias it requested, and an alias is not a model. So the "imputed list
# price" was a made-up rate applied to a made-up model, and the BYOK panel
# reported savings against it. A model with no known price now imputes
# nothing and is counted as unpriced instead.
_GATEWAY_ALIAS_PREFIX = "aisoc-"


def _price_key(model: str | None) -> str | None:
    """The pricing-table key for ``model``, or ``None`` if it has no known price.

    Gateway-resolved names carry a provider segment (``openai/gpt-4o-mini``),
    which is stripped; a logical alias carries no price at all and is refused
    outright rather than allowed to miss the table and take a default.
    """
    name = (model or "").strip().lower()
    if not name or name.startswith(_GATEWAY_ALIAS_PREFIX):
        return None
    if name in _PUBLIC_PRICING:
        return name
    bare = name.rsplit("/", 1)[-1]
    return bare if bare in _PUBLIC_PRICING else None


def _impute_public_cost(
    model: str | None,
    prompt_tokens: int,
    completion_tokens: int,
) -> float | None:
    """What ``model`` would cost at list price, or ``None`` if unknown.

    ``None`` is the point: "this model lists at $X" and "we had to guess"
    were previously the same return type and therefore the same number.
    """
    key = _price_key(model)
    if key is None:
        return None
    in_price, out_price = _PUBLIC_PRICING[key]
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
    """LLM spend bucketed by day.

    ``total_cost_usd`` is measured cost. ``measured_call_count`` says how much
    of the day's traffic that covers, so a bar of height zero can be read as
    "a free day" or "an unmeasured day" rather than silently as the first.
    """

    day: date
    total_cost_usd: float
    measured_call_count: int = 0
    estimated_cost_usd: float = 0.0
    estimated_call_count: int = 0
    unpriced_call_count: int = 0
    total_tokens: int
    call_count: int


class ModelBreakdown(BaseModel):
    """Spend / volume rolled up per model over the window."""

    model: str
    #: What the gateway resolved ``model`` to, when it said. An `aisoc-<role>`
    #: row is a request label; this is the thing that was actually billed.
    resolved_model: str | None = None
    runs: int
    calls: int
    total_prompt_tokens: int
    total_completion_tokens: int
    total_cost_usd: float
    measured_call_count: int = 0
    estimated_cost_usd: float = 0.0
    estimated_call_count: int = 0
    unpriced_call_count: int = 0
    #: List-price re-pricing of this model's tokens, or ``None`` when the model
    #: has no public list price. ``None`` is not zero: it means unknown.
    imputed_public_cost_usd: float | None
    #: Tokens excluded from the imputation because nothing prices them. Without
    #: this the imputed figure looks complete when it covers part of the window.
    unpriced_tokens: int = 0
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
    measured_call_count: int = 0
    estimated_cost_usd: float = 0.0
    estimated_call_count: int = 0
    total_tokens: int


class ActionCount(BaseModel):
    """How many of each kind of action SOC operators took."""

    action: str
    count: int


class ByokSavings(BaseModel):
    """Imputed savings vs hosted pricing — an estimate, labelled everywhere.

    ``is_byok_active`` is True when the live LLM provider (per
    ``/llm/status``) is loopback or private — i.e. the operator is
    actually running their own model. When False, the savings are still
    computed (so the UI can show "if you switched to BYOK, you'd save
    ~X") but should be labelled "potential savings" in the UI.

    ``imputed_public_cost_usd`` is ``None`` when no row in the window names a
    model with a public list price. It used to be a number in that case, built
    from a default rate applied to a gateway alias, and the BYOK panel
    announced savings against it — an invented saving on invented spend.
    ``unpriced_tokens`` says how much of the window the estimate omits.
    """

    is_byok_active: bool
    provider: str
    recorded_cost_usd: float
    recorded_is_measured: bool
    imputed_public_cost_usd: float | None
    unpriced_tokens: int = 0
    savings_usd: float | None


class CostHeadline(BaseModel):
    """Window totals, each with the count of calls it was computed over.

    ``total_cost_usd`` is **measured** spend. When ``measured_call_count`` is
    zero it is not a total of anything and the console must render "not
    measured" — the same contract the MTTR tiles use.
    """

    total_cost_usd: float
    measured_call_count: int = 0
    estimated_cost_usd: float = 0.0
    estimated_call_count: int = 0
    unpriced_call_count: int = 0
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
    #: Measured (gateway-reported) cost, already zeroed by the query when
    #: ``measured_call_count`` is 0 — see ``_COST_QUERY``. The guard lives at
    #: the boundary rather than on this row so every sum below is plain
    #: arithmetic and no aggregator can forget to apply it.
    measured_cost_usd: float
    latency_ms: float
    call_count: int
    started_at: datetime
    measured_call_count: int = 0
    estimated_cost_usd: float = 0.0
    estimated_call_count: int = 0
    unpriced_call_count: int = 0
    resolved_model: str | None = None


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
    buckets: dict[date, dict[str, float]] = defaultdict(
        lambda: {
            "cost": 0.0,
            "measured_calls": 0,
            "estimated": 0.0,
            "estimated_calls": 0,
            "unpriced_calls": 0,
            "tokens": 0,
            "calls": 0,
        }
    )
    for r in rows:
        d = r.started_at.astimezone(UTC).date()
        b = buckets[d]
        b["cost"] += r.measured_cost_usd
        b["measured_calls"] += r.measured_call_count
        b["estimated"] += r.estimated_cost_usd
        b["estimated_calls"] += r.estimated_call_count
        b["unpriced_calls"] += r.unpriced_call_count
        b["tokens"] += r.prompt_tokens + r.completion_tokens
        b["calls"] += r.call_count
    return [
        CostBucket(
            day=d,
            total_cost_usd=round(buckets[d]["cost"], 4),
            measured_call_count=int(buckets[d]["measured_calls"]),
            estimated_cost_usd=round(buckets[d]["estimated"], 4),
            estimated_call_count=int(buckets[d]["estimated_calls"]),
            unpriced_call_count=int(buckets[d]["unpriced_calls"]),
            total_tokens=int(buckets[d]["tokens"]),
            call_count=int(buckets[d]["calls"]),
        )
        for d in sorted(buckets)
    ]


def _imputed_for_row(r: CostRow) -> float | None:
    """List-price re-pricing of one row, preferring the model actually billed.

    The gateway-resolved name is tried first because that is the model a
    provider would have charged for; the requested name is usually an alias
    and carries no price. ``None`` when neither is priceable.
    """
    imputed = _impute_public_cost(r.resolved_model, r.prompt_tokens, r.completion_tokens)
    if imputed is None:
        imputed = _impute_public_cost(r.model, r.prompt_tokens, r.completion_tokens)
    return imputed


def _model_breakdown(rows: list[CostRow]) -> list[ModelBreakdown]:
    """Aggregate rows per model, sorted by spend descending."""
    by_model: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "runs": set(),
            "calls": 0,
            "prompt": 0,
            "completion": 0,
            "cost": 0.0,
            "measured_calls": 0,
            "estimated": 0.0,
            "estimated_calls": 0,
            "unpriced_calls": 0,
            "imputed": None,
            "unpriced_tokens": 0,
            "resolved": None,
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
        agg["cost"] += r.measured_cost_usd
        agg["measured_calls"] += r.measured_call_count
        agg["estimated"] += r.estimated_cost_usd
        agg["estimated_calls"] += r.estimated_call_count
        agg["unpriced_calls"] += r.unpriced_call_count
        imputed = _imputed_for_row(r)
        if imputed is None:
            # Counted, not silently dropped: an imputed total that quietly
            # skips half its rows reads as complete and is not.
            agg["unpriced_tokens"] += r.prompt_tokens + r.completion_tokens
        else:
            agg["imputed"] = (agg["imputed"] or 0.0) + imputed
        if r.resolved_model and not agg["resolved"]:
            agg["resolved"] = r.resolved_model
        agg["latency_ms"] += r.latency_ms

    breakdowns = [
        ModelBreakdown(
            model=m,
            resolved_model=agg["resolved"],
            runs=len(agg["runs"]),
            calls=int(agg["calls"]),
            total_prompt_tokens=int(agg["prompt"]),
            total_completion_tokens=int(agg["completion"]),
            total_cost_usd=round(agg["cost"], 4),
            measured_call_count=int(agg["measured_calls"]),
            estimated_cost_usd=round(agg["estimated"], 4),
            estimated_call_count=int(agg["estimated_calls"]),
            unpriced_call_count=int(agg["unpriced_calls"]),
            imputed_public_cost_usd=(round(agg["imputed"], 4) if agg["imputed"] is not None else None),
            unpriced_tokens=int(agg["unpriced_tokens"]),
            avg_latency_ms=(round(agg["latency_ms"] / agg["calls"], 2) if agg["calls"] else None),
        )
        for m, agg in by_model.items()
    ]
    breakdowns.sort(key=lambda b: (-b.total_cost_usd, b.model))
    return breakdowns


def _top_cases(rows: list[CostRow], *, limit: int = 10) -> list[TopCostCase]:
    """The most expensive cases in the window."""
    by_case: dict[str, dict[str, Any]] = defaultdict(
        lambda: {"runs": set(), "cost": 0.0, "measured_calls": 0, "estimated": 0.0, "estimated_calls": 0, "tokens": 0}
    )
    for r in rows:
        if not r.case_id:
            continue
        agg = by_case[r.case_id]
        agg["runs"].add(r.run_id)
        agg["cost"] += r.measured_cost_usd
        agg["measured_calls"] += r.measured_call_count
        agg["estimated"] += r.estimated_cost_usd
        agg["estimated_calls"] += r.estimated_call_count
        agg["tokens"] += r.prompt_tokens + r.completion_tokens

    items = [
        TopCostCase(
            case_id=case_id,
            runs=len(agg["runs"]),
            total_cost_usd=round(agg["cost"], 4),
            measured_call_count=int(agg["measured_calls"]),
            estimated_cost_usd=round(agg["estimated"], 4),
            estimated_call_count=int(agg["estimated_calls"]),
            total_tokens=int(agg["tokens"]),
        )
        for case_id, agg in by_case.items()
    ]
    # Ranked on measured spend first, then the estimate, so a window with
    # nothing measured still ranks by the best information available rather
    # than collapsing into an arbitrary alphabetical order.
    items.sort(key=lambda c: (-c.total_cost_usd, -c.estimated_cost_usd, c.case_id))
    return items[:limit]


def _action_counts(rows: list[AuditRow], *, limit: int = 20) -> list[ActionCount]:
    """How many of each action were recorded over the window."""
    counter: Counter[str] = Counter(r.action for r in rows if r.action)
    return [ActionCount(action=a, count=c) for a, c in counter.most_common(limit)]


def _byok_savings(rows: list[CostRow], llm: LlmContext) -> ByokSavings:
    """Imputed savings vs hosted public pricing — an estimate throughout.

    ``recorded_cost_usd`` is **measured** spend: what the gateway reported.
    It used to be whatever the tracker had booked, which on every deployment
    was a default list rate applied to a gateway alias — so on a local model
    the panel compared one invented number against another and called the
    difference a saving.

    On BYOK the saving is the whole imputed hosted cost (the operator avoided
    paying a provider at all). On a hosted provider it is
    ``max(imputed - measured, 0)``, a "you'd save X if you self-hosted" hint.
    Both are ``None`` when nothing in the window has a public list price,
    because a saving computed over no priceable rows is not a small saving —
    it is no answer.
    """
    measured_rows = [r for r in rows if r.measured_call_count > 0]
    recorded = sum(r.measured_cost_usd for r in rows)

    imputed: float | None = None
    unpriced_tokens = 0
    for r in rows:
        row_imputed = _imputed_for_row(r)
        if row_imputed is None:
            unpriced_tokens += r.prompt_tokens + r.completion_tokens
        else:
            imputed = (imputed or 0.0) + row_imputed

    if imputed is None:
        savings: float | None = None
    elif llm.is_local:
        savings = imputed
    else:
        savings = max(imputed - recorded, 0.0)

    return ByokSavings(
        is_byok_active=bool(llm.is_local),
        provider=llm.provider or "unknown",
        recorded_cost_usd=round(recorded, 4),
        recorded_is_measured=bool(measured_rows),
        imputed_public_cost_usd=(round(imputed, 4) if imputed is not None else None),
        unpriced_tokens=unpriced_tokens,
        savings_usd=(round(savings, 4) if savings is not None else None),
    )


def _headline(rows: list[CostRow]) -> CostHeadline:
    total_cost = sum(r.measured_cost_usd for r in rows)
    measured_calls = sum(r.measured_call_count for r in rows)
    estimated_cost = sum(r.estimated_cost_usd for r in rows)
    estimated_calls = sum(r.estimated_call_count for r in rows)
    unpriced_calls = sum(r.unpriced_call_count for r in rows)
    total_tokens = sum(r.prompt_tokens + r.completion_tokens for r in rows)
    total_calls = sum(r.call_count for r in rows)
    total_runs = len({r.run_id for r in rows if r.run_id})
    return CostHeadline(
        total_cost_usd=round(total_cost, 4),
        measured_call_count=int(measured_calls),
        estimated_cost_usd=round(estimated_cost, 4),
        estimated_call_count=int(estimated_calls),
        unpriced_call_count=int(unpriced_calls),
        total_tokens=int(total_tokens),
        total_calls=int(total_calls),
        total_runs=total_runs,
        # A mean of measured spend is only a mean when something was measured.
        # Dividing an unmeasured zero by the run count published "$0.0000 per
        # investigation", the most flattering number on the page, for a tenant
        # whose spend nobody knew.
        avg_cost_per_run_usd=(round(total_cost / total_runs, 4) if total_runs and measured_calls else None),
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
           c.resolved_model          AS resolved_model,
           c.total_prompt_tokens     AS prompt_tokens,
           c.total_completion_tokens AS completion_tokens,
           -- measured_cost_usd, not total_cost_usd: rows written before
           -- migration 063 hold a list-price guess in the latter, and
           -- measured_call_count = 0 is what marks them unmeasured.
           --
           -- The CASE is the guard, applied once here so no aggregator
           -- downstream has to remember it. A cost with no calls behind it is
           -- not a small cost, and must not enter a SUM as though it were.
           CASE WHEN c.measured_call_count > 0
                THEN c.measured_cost_usd ELSE 0 END AS measured_cost_usd,
           c.measured_call_count     AS measured_call_count,
           c.estimated_cost_usd      AS estimated_cost_usd,
           c.estimated_call_count    AS estimated_call_count,
           c.unpriced_call_count     AS unpriced_call_count,
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
                measured_cost_usd=float(r["measured_cost_usd"] or 0.0),
                latency_ms=float(r["latency_ms"] or 0.0),
                call_count=int(r["call_count"] or 0),
                started_at=started_at or end,
                measured_call_count=int(r["measured_call_count"] or 0),
                estimated_cost_usd=float(r["estimated_cost_usd"] or 0.0),
                estimated_call_count=int(r["estimated_call_count"] or 0),
                unpriced_call_count=int(r["unpriced_call_count"] or 0),
                resolved_model=(str(r["resolved_model"]) if r["resolved_model"] else None),
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
    "_internal_helpers",  # accessed by test suite for private helper coverage
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
    "_imputed_for_row": _imputed_for_row,
    "_price_key": _price_key,
}
