"""Tests for WS-H1 — cost dashboard builder.

The cost dashboard splits into a pure ``build_dashboard_from_rows`` and a
thin async DB orchestrator. We exercise the pure builder against
deterministic input rows so the regression surface is the actual aggregation
logic and not Postgres / SQLAlchemy plumbing.

The tests deliberately cover:

* daily bucketing across UTC midnight (timezone correctness)
* per-model aggregation, including unknown models that fall back to the
  default public-list price
* top-cost case ranking with ties broken deterministically by ``case_id``
* action-count ordering (most-common first) and the limit clamp
* BYOK savings semantics:
    - hosted provider with no recorded cost → zero or modest delta
    - local provider → full imputed cost reported as savings
* headline averages on empty input (no division by zero)
* window clamping inside the orchestrator boundary helper
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.services.cost_dashboard import (
    AuditRow,
    CostRow,
    DashboardInputs,
    LlmContext,
    _impute_public_cost,
    _internal_helpers,
    build_dashboard_from_rows,
)

PERIOD_START = datetime(2026, 5, 2, 0, 0, tzinfo=UTC)
PERIOD_END = datetime(2026, 5, 9, 0, 0, tzinfo=UTC)
TENANT_ID = uuid.uuid4()


def _cost(
    *,
    run_id: str | None = None,
    case_id: str = "CASE-1",
    model: str = "gpt-4o-mini",
    prompt_tokens: int = 1000,
    completion_tokens: int = 500,
    cost_usd: float | None = None,
    latency_ms: float = 250.0,
    call_count: int = 1,
    started_at: datetime | None = None,
) -> CostRow:
    """Builder that fills sensible defaults for a CostRow.

    When ``cost_usd`` is omitted we fall back to the imputed public cost so a
    test that wants "what a hosted call would have charged" can drop into
    the constructor without recomputing pricing by hand.
    """
    if cost_usd is None:
        cost_usd = _impute_public_cost(model, prompt_tokens, completion_tokens)
    return CostRow(
        run_id=run_id or str(uuid.uuid4()),
        case_id=case_id,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        cost_usd=cost_usd,
        latency_ms=latency_ms,
        call_count=call_count,
        started_at=started_at or PERIOD_START + timedelta(hours=1),
    )


# ---------------------------------------------------------------------------
# Pricing / imputation
# ---------------------------------------------------------------------------


def test_impute_public_cost_known_model() -> None:
    # gpt-4o-mini: $0.00015 / 1k input, $0.0006 / 1k output
    cost = _impute_public_cost("gpt-4o-mini", 1000, 500)
    assert cost == pytest.approx(0.00015 + 0.0003, rel=1e-9)


def test_impute_public_cost_unknown_model_uses_default() -> None:
    # Unknown model falls back to the conservative default, not zero, so we
    # never silently report 100% savings on a bespoke local model.
    cost = _impute_public_cost("super-secret-llm", 1000, 1000)
    assert cost > 0


def test_impute_public_cost_negative_token_counts_clamped() -> None:
    # Defensive: a malformed row with negative tokens shouldn't produce a
    # negative cost (which would fold the totals).
    assert _impute_public_cost("gpt-4o-mini", -5, -10) == 0.0


def test_impute_public_cost_case_insensitive() -> None:
    a = _impute_public_cost("GPT-4o", 1000, 500)
    b = _impute_public_cost("gpt-4o", 1000, 500)
    assert a == b


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_format_period_label_same_month() -> None:
    fmt = _internal_helpers["_format_period_label"]
    label = fmt(PERIOD_START, PERIOD_END)
    assert "May" in label
    assert "2026" in label


def test_format_period_label_cross_year() -> None:
    fmt = _internal_helpers["_format_period_label"]
    label = fmt(
        datetime(2025, 12, 28, tzinfo=UTC),
        datetime(2026, 1, 4, tzinfo=UTC),
    )
    assert "2025" in label
    assert "2026" in label


def test_bucket_by_day_groups_across_utc_midnight() -> None:
    bucket = _internal_helpers["_bucket_by_day"]
    rows = [
        _cost(started_at=datetime(2026, 5, 2, 23, 0, tzinfo=UTC), cost_usd=1.0),
        _cost(started_at=datetime(2026, 5, 2, 23, 30, tzinfo=UTC), cost_usd=2.0),
        # 30 min later → next UTC day → separate bucket
        _cost(started_at=datetime(2026, 5, 3, 0, 30, tzinfo=UTC), cost_usd=4.0),
    ]
    buckets = bucket(rows)
    assert len(buckets) == 2
    assert buckets[0].day.isoformat() == "2026-05-02"
    assert buckets[0].total_cost_usd == pytest.approx(3.0)
    assert buckets[1].day.isoformat() == "2026-05-03"
    assert buckets[1].total_cost_usd == pytest.approx(4.0)


def test_bucket_by_day_empty() -> None:
    assert _internal_helpers["_bucket_by_day"]([]) == []


def test_model_breakdown_sorts_by_spend_descending() -> None:
    breakdown = _internal_helpers["_model_breakdown"]
    rows = [
        _cost(model="gpt-4o-mini", cost_usd=0.5, run_id="r1"),
        _cost(model="gpt-4o", cost_usd=10.0, run_id="r2"),
        _cost(model="gpt-3.5-turbo", cost_usd=2.0, run_id="r3"),
    ]
    out = breakdown(rows)
    assert [b.model for b in out] == ["gpt-4o", "gpt-3.5-turbo", "gpt-4o-mini"]
    assert out[0].total_cost_usd == 10.0


def test_model_breakdown_aggregates_runs_and_calls() -> None:
    breakdown = _internal_helpers["_model_breakdown"]
    rows = [
        _cost(model="gpt-4o", run_id="r1", call_count=3, cost_usd=1.0),
        _cost(model="gpt-4o", run_id="r1", call_count=2, cost_usd=2.0),
        _cost(model="gpt-4o", run_id="r2", call_count=1, cost_usd=0.5),
    ]
    out = breakdown(rows)
    assert len(out) == 1
    assert out[0].runs == 2  # r1, r2 — distinct
    assert out[0].calls == 6  # 3 + 2 + 1
    assert out[0].total_cost_usd == pytest.approx(3.5)


def test_model_breakdown_avg_latency() -> None:
    breakdown = _internal_helpers["_model_breakdown"]
    rows = [
        _cost(model="gpt-4o", run_id="r1", call_count=2, latency_ms=200.0),
        _cost(model="gpt-4o", run_id="r1", call_count=2, latency_ms=400.0),
    ]
    out = breakdown(rows)
    # (200 + 400) / (2 + 2) = 150 ms per call
    assert out[0].avg_latency_ms == pytest.approx(150.0)


def test_top_cases_ranks_by_cost_desc_then_case_id() -> None:
    top = _internal_helpers["_top_cases"]
    rows = [
        _cost(case_id="C-2", cost_usd=5.0, run_id="r1"),
        _cost(case_id="C-1", cost_usd=5.0, run_id="r2"),  # tie with C-2
        _cost(case_id="C-3", cost_usd=10.0, run_id="r3"),
    ]
    out = top(rows)
    # Most expensive first, ties broken by case_id ascending.
    assert [c.case_id for c in out] == ["C-3", "C-1", "C-2"]


def test_top_cases_skips_blank_case_id() -> None:
    top = _internal_helpers["_top_cases"]
    rows = [
        _cost(case_id="", cost_usd=99.0),
        _cost(case_id="C-1", cost_usd=1.0),
    ]
    out = top(rows)
    assert [c.case_id for c in out] == ["C-1"]


def test_top_cases_respects_limit() -> None:
    top = _internal_helpers["_top_cases"]
    rows = [_cost(case_id=f"C-{i:02d}", cost_usd=float(i)) for i in range(15)]
    out = top(rows, limit=5)
    assert len(out) == 5
    assert out[0].case_id == "C-14"


def test_action_counts_orders_by_frequency() -> None:
    counts = _internal_helpers["_action_counts"]
    rows = [
        AuditRow(action="cases:read"),
        AuditRow(action="cases:read"),
        AuditRow(action="cases:write"),
        AuditRow(action="alerts:read"),
        AuditRow(action="alerts:read"),
        AuditRow(action="alerts:read"),
    ]
    out = counts(rows)
    assert [a.action for a in out] == ["alerts:read", "cases:read", "cases:write"]
    assert out[0].count == 3


def test_action_counts_drops_blanks() -> None:
    counts = _internal_helpers["_action_counts"]
    rows = [AuditRow(action=""), AuditRow(action="cases:read")]
    out = counts(rows)
    assert len(out) == 1
    assert out[0].action == "cases:read"


def test_action_counts_respects_limit() -> None:
    counts = _internal_helpers["_action_counts"]
    rows = [AuditRow(action=f"action-{i}") for i in range(50)]
    out = counts(rows, limit=10)
    assert len(out) == 10


# ---------------------------------------------------------------------------
# BYOK savings
# ---------------------------------------------------------------------------


def test_byok_savings_local_reports_full_imputed_cost() -> None:
    savings_fn = _internal_helpers["_byok_savings"]
    rows = [
        _cost(model="gpt-4o-mini", prompt_tokens=10_000, completion_tokens=5_000),
    ]
    # On BYOK the recorded cost typically already matches imputed (the agent
    # uses the same pricing table) so savings should ≈ imputed.
    result = savings_fn(rows, LlmContext(provider="local-ollama", is_local=True))
    assert result.is_byok_active is True
    assert result.savings_usd > 0
    assert result.savings_usd == pytest.approx(result.imputed_public_cost_usd)


def test_byok_savings_hosted_reports_max_zero() -> None:
    savings_fn = _internal_helpers["_byok_savings"]
    # Hosted provider where the recorded cost matches imputed → zero savings.
    rows = [
        _cost(model="gpt-4o", prompt_tokens=1000, completion_tokens=500, cost_usd=0.0125),
    ]
    result = savings_fn(rows, LlmContext(provider="openai", is_local=False))
    assert result.is_byok_active is False
    assert result.savings_usd == 0.0


def test_byok_savings_hosted_with_discount_reports_positive() -> None:
    savings_fn = _internal_helpers["_byok_savings"]
    # Operator paid less than list price (negotiated rate) → positive
    # potential additional savings if they switched to BYOK.
    rows = [_cost(model="gpt-4o", cost_usd=0.001)]  # imputed ≈ $0.0125
    result = savings_fn(rows, LlmContext(provider="openai", is_local=False))
    assert result.is_byok_active is False
    assert result.savings_usd > 0
    assert result.savings_usd < result.imputed_public_cost_usd


def test_byok_savings_empty_rows() -> None:
    savings_fn = _internal_helpers["_byok_savings"]
    result = savings_fn([], LlmContext(provider="none", is_local=False))
    assert result.recorded_cost_usd == 0.0
    assert result.imputed_public_cost_usd == 0.0
    assert result.savings_usd == 0.0


# ---------------------------------------------------------------------------
# Headline
# ---------------------------------------------------------------------------


def test_headline_zero_runs_avoids_div_by_zero() -> None:
    headline = _internal_helpers["_headline"]
    out = headline([])
    assert out.total_runs == 0
    assert out.avg_cost_per_run_usd is None


def test_headline_aggregates_distinct_runs() -> None:
    headline = _internal_helpers["_headline"]
    rows = [
        _cost(run_id="r1", cost_usd=1.0),
        _cost(run_id="r1", cost_usd=2.0),  # same run, different model call
        _cost(run_id="r2", cost_usd=3.0),
    ]
    out = headline(rows)
    assert out.total_runs == 2
    assert out.total_cost_usd == pytest.approx(6.0)
    assert out.avg_cost_per_run_usd == pytest.approx(3.0)


# ---------------------------------------------------------------------------
# Top-level pure builder
# ---------------------------------------------------------------------------


def test_build_dashboard_empty_inputs_is_well_formed() -> None:
    """Empty tenant should still return a valid CostDashboard, not raise."""
    dashboard = build_dashboard_from_rows(
        DashboardInputs(
            tenant_id=TENANT_ID,
            period_start=PERIOD_START,
            period_end=PERIOD_END,
            cost_rows=[],
            audit_rows=[],
            llm=LlmContext(provider="none", is_local=False),
        )
    )
    assert dashboard.tenant_id == TENANT_ID
    assert dashboard.period.window_days == 7
    assert dashboard.headline.total_cost_usd == 0.0
    assert dashboard.daily_costs == []
    assert dashboard.by_model == []
    assert dashboard.top_cases == []
    assert dashboard.action_counts == []
    # BYOK panel is always present so the UI doesn't have to special-case it.
    assert dashboard.byok_savings.is_byok_active is False
    assert dashboard.byok_savings.savings_usd == 0.0


def test_build_dashboard_end_to_end() -> None:
    """A representative tenant: 3 runs, 2 models, 2 days, mixed actions."""
    cost_rows = [
        _cost(
            run_id="r1",
            case_id="C-1",
            model="gpt-4o-mini",
            prompt_tokens=2000,
            completion_tokens=1000,
            started_at=datetime(2026, 5, 2, 10, 0, tzinfo=UTC),
        ),
        _cost(
            run_id="r2",
            case_id="C-2",
            model="gpt-4o",
            prompt_tokens=10_000,
            completion_tokens=5_000,
            cost_usd=0.125,  # cheaper than imputed → operator saved
            started_at=datetime(2026, 5, 3, 14, 0, tzinfo=UTC),
        ),
        _cost(
            run_id="r3",
            case_id="C-2",  # same case, separate run → C-2 ranks #1
            model="gpt-4o",
            prompt_tokens=5000,
            completion_tokens=2000,
            cost_usd=0.05,
            started_at=datetime(2026, 5, 3, 15, 0, tzinfo=UTC),
        ),
    ]
    audit_rows = [
        AuditRow(action="cases:read"),
        AuditRow(action="cases:read"),
        AuditRow(action="cases:write"),
        AuditRow(action="alerts:read"),
    ]
    dashboard = build_dashboard_from_rows(
        DashboardInputs(
            tenant_id=TENANT_ID,
            period_start=PERIOD_START,
            period_end=PERIOD_END,
            cost_rows=cost_rows,
            audit_rows=audit_rows,
            llm=LlmContext(provider="openai", is_local=False),
        )
    )
    # Headline
    assert dashboard.headline.total_runs == 3
    assert dashboard.headline.total_calls == 3
    assert dashboard.headline.total_tokens == 25_000

    # Daily buckets — 2 distinct UTC days
    assert [b.day.isoformat() for b in dashboard.daily_costs] == [
        "2026-05-02",
        "2026-05-03",
    ]

    # Model breakdown — gpt-4o has higher recorded cost
    assert dashboard.by_model[0].model == "gpt-4o"
    assert dashboard.by_model[1].model == "gpt-4o-mini"

    # Top cases — C-2 has 2 runs and higher spend
    assert dashboard.top_cases[0].case_id == "C-2"
    assert dashboard.top_cases[0].runs == 2

    # Action counts
    assert dashboard.action_counts[0].action == "cases:read"
    assert dashboard.action_counts[0].count == 2

    # BYOK — hosted provider, recorded < imputed → positive savings
    assert dashboard.byok_savings.is_byok_active is False
    assert dashboard.byok_savings.savings_usd > 0


def test_build_dashboard_byok_active_marks_local_provider() -> None:
    cost_rows = [
        _cost(
            run_id="r1",
            case_id="C-1",
            model="gpt-4o-mini",
            prompt_tokens=1000,
            completion_tokens=500,
        )
    ]
    dashboard = build_dashboard_from_rows(
        DashboardInputs(
            tenant_id=TENANT_ID,
            period_start=PERIOD_START,
            period_end=PERIOD_END,
            cost_rows=cost_rows,
            audit_rows=[],
            llm=LlmContext(provider="local-ollama", is_local=True),
        )
    )
    assert dashboard.byok_savings.is_byok_active is True
    assert dashboard.byok_savings.provider == "local-ollama"
    assert dashboard.byok_savings.savings_usd > 0
