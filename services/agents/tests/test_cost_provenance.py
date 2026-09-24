"""A cost figure must be measured, labelled an estimate, or absent.

The defect these cover
----------------------
``CostTracker`` priced a call by looking its **model name** up in a table of
hosted list prices, and the name it looked up was an ``aisoc-<role>`` alias —
a label the gateway resolves, not a model. No alias is in the table, so every
call took a ``(0.001, 0.002)`` default. A 903-token completion on an
operator's own hardware was reported as ``total_cost_usd=0.000999``, and that
number reached the cost dashboard, the funnel, the per-run ledger and the
budget circuit breaker.

The header fixtures below are not invented. They are the literal header sets
returned by ``ghcr.io/berriai/litellm:main-stable`` (1.102.1) driving a local
``ollama/qwen2:1.5b`` and a hosted ``openai/gpt-4o-mini`` from the same alias
config — including the fact that the local success response carries
``x-litellm-response-cost-original`` but *not* the plain
``x-litellm-response-cost``, which is why both spellings are read.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from app.core.cost_telemetry import (
    GATEWAY,
    LIST_PRICE_ESTIMATE,
    UNPRICED,
    CallRecord,
    CostSummary,
    CostTracker,
    _estimate_cost,
    _price_key,
)
from app.core.gateway_cost import extract_gateway_cost, extract_resolved_model

# Measured: `aisoc-triage` -> ollama/qwen2:1.5b, a free local model.
LOCAL_HEADERS = {
    "x-litellm-call-id": "716640f2-e268-47dd-b53e-d956fe9d6361",
    "x-litellm-model-name": "ollama/qwen2:1.5b",
    "x-litellm-model-api-base": "http://aisoc-probe-ollama:11434",
    "x-litellm-version": "1.102.1",
    "x-litellm-response-cost-original": "0.0",
    "x-litellm-response-cost-input": "0.0",
    "x-litellm-response-cost-output": "0",
    "x-litellm-response-cost-discount-amount": "0.0",
    "x-litellm-response-cost-margin-amount": "0.0",
    "x-litellm-response-cost-margin-percent": "0.0",
    "x-litellm-response-cost-tool-usage": "0.0",
    "x-litellm-model-group": "aisoc-triage",
}

# Measured: `aisoc-summary` -> openai/gpt-4o-mini, a hosted model with a price.
HOSTED_HEADERS = {
    "x-litellm-call-id": "7bd2c2f0-1f2a-4a44-9a66-8b7c9f5b1f21",
    "x-litellm-model-name": "openai/gpt-4o-mini",
    "x-litellm-response-cost": "1.35e-05",
    "x-litellm-response-cost-original": "1.35e-05",
    "x-litellm-response-cost-input": "1.5e-06",
    "x-litellm-response-cost-output": "1.2e-05",
    "x-litellm-response-cost-margin-percent": "0.0",
    "x-litellm-model-group": "aisoc-summary",
}


def _response(headers: dict[str, str] | None, *, prompt: int = 19, completion: int = 3):
    metadata: dict[str, object] = {"model_name": "aisoc-triage"}
    if headers is not None:
        metadata["headers"] = dict(headers)
    return SimpleNamespace(
        content="ok",
        usage_metadata={"input_tokens": prompt, "output_tokens": completion},
        response_metadata=metadata,
    )


# --------------------------------------------------------------------------
# Header extraction
# --------------------------------------------------------------------------


def test_local_model_reports_a_measured_zero():
    cost = extract_gateway_cost(_response(LOCAL_HEADERS))
    assert cost is not None, "the gateway reported a cost and it must be read"
    assert cost.cost_usd == 0.0
    assert cost.resolved_model == "ollama/qwen2:1.5b"
    assert cost.call_id == "716640f2-e268-47dd-b53e-d956fe9d6361"


def test_hosted_model_reports_its_real_price():
    cost = extract_gateway_cost(_response(HOSTED_HEADERS))
    assert cost is not None
    assert cost.cost_usd == pytest.approx(1.35e-05)
    assert cost.resolved_model == "openai/gpt-4o-mini"


def test_no_headers_means_not_measurable_not_free():
    """The distinction the whole change rests on."""
    assert extract_gateway_cost(_response(None)) is None
    assert extract_resolved_model(_response(None)) is None


def test_component_headers_alone_yield_no_cost():
    """A prefix match would accept ``-margin-percent`` as a dollar amount.

    Seven headers start ``x-litellm-response-cost`` and only two are totals.
    ``-margin-percent`` is not even denominated in money, and ``-input`` /
    ``-output`` are halves of one. Feeding any of them to the tracker would
    produce a plausible-looking wrong number rather than an obvious absence,
    which is the harder failure to notice.
    """
    partial = {k: v for k, v in HOSTED_HEADERS.items() if k not in ("x-litellm-response-cost", "x-litellm-response-cost-original")}
    assert any(k.startswith("x-litellm-response-cost") for k in partial), "fixture must still contain the decoys"
    assert extract_gateway_cost(_response(partial)) is None


def test_malformed_and_impossible_costs_are_refused():
    for bad in ("", "n/a", "NaN", "inf", "-0.5", "  "):
        headers = {**HOSTED_HEADERS, "x-litellm-response-cost": bad, "x-litellm-response-cost-original": bad}
        assert extract_gateway_cost(_response(headers)) is None, bad


# --------------------------------------------------------------------------
# Pricing: an alias is never a price key
# --------------------------------------------------------------------------


@pytest.mark.parametrize("alias", ["aisoc-triage", "aisoc-report", "AISOC-Summary"])
def test_an_alias_has_no_price(alias):
    assert _price_key(alias) is None
    assert _estimate_cost(alias, 10_000, 10_000) is None


def test_an_unknown_model_has_no_price():
    """No default rate. The default rate is what invented $0.000999."""
    assert _estimate_cost("some-bespoke-local-7b", 1_000_000, 1_000_000) is None
    assert _estimate_cost("ollama/qwen2:1.5b", 1_000_000, 1_000_000) is None


def test_a_known_model_prices_with_or_without_its_provider_prefix():
    bare = _estimate_cost("gpt-4o-mini", 1000, 1000)
    prefixed = _estimate_cost("openai/gpt-4o-mini", 1000, 1000)
    assert bare == prefixed == pytest.approx(0.00015 + 0.0006)


# --------------------------------------------------------------------------
# CallRecord provenance
# --------------------------------------------------------------------------


def test_gateway_cost_wins_over_any_estimate():
    """The gateway resolved the alias; nothing else is entitled to a view.

    A hosted model the table *does* know still books the gateway's figure,
    not the table's, because the gateway applies the operator's actual
    contract, discounts and margin.
    """
    rec = CallRecord(
        model="aisoc-summary",
        prompt_tokens=19,
        completion_tokens=3,
        latency_ms=88.0,
        gateway_cost=extract_gateway_cost(_response(HOSTED_HEADERS)),
    )
    assert rec.cost_source == GATEWAY
    assert rec.cost_usd == pytest.approx(1.35e-05)
    assert rec.resolved_model == "openai/gpt-4o-mini"


def test_local_run_books_a_measured_zero_not_an_estimate():
    rec = CallRecord(
        model="aisoc-triage",
        prompt_tokens=884,
        completion_tokens=19,
        latency_ms=5094.0,
        gateway_cost=extract_gateway_cost(_response(LOCAL_HEADERS)),
    )
    assert rec.cost_source == GATEWAY
    assert rec.cost_usd == 0.0
    assert rec.is_measured and not rec.is_estimated


def test_alias_with_no_gateway_is_unpriced_not_default_priced():
    """The exact shape of the reported defect, as a regression test.

    903 tokens of `aisoc-triage` against the old default rate produced
    $0.000999. It must now produce no figure at all.
    """
    rec = CallRecord(model="aisoc-triage", prompt_tokens=884, completion_tokens=19, latency_ms=5094.0)
    assert rec.cost_source == UNPRICED
    assert rec.cost_usd is None


def test_resolved_model_enables_an_estimate_the_alias_could_not():
    """A gateway that named the model but reported no cost is still estimable."""
    rec = CallRecord(
        model="aisoc-summary",
        prompt_tokens=1000,
        completion_tokens=1000,
        latency_ms=10.0,
        resolved_model="openai/gpt-4o-mini",
    )
    assert rec.cost_source == LIST_PRICE_ESTIMATE
    assert rec.cost_usd == pytest.approx(0.00075)


# --------------------------------------------------------------------------
# Tracker aggregation
# --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tracker_keeps_measured_and_estimated_apart():
    async with CostTracker(run_id="r1", tenant_id="t1") as tracker:
        tracker.record(
            model="aisoc-triage",
            prompt_tokens=884,
            completion_tokens=19,
            latency_ms=5094.0,
            gateway_cost=extract_gateway_cost(_response(LOCAL_HEADERS)),
        )
        tracker.record(model="gpt-4o-mini", prompt_tokens=1000, completion_tokens=1000, latency_ms=10.0)
        tracker.record(model="aisoc-report", prompt_tokens=100, completion_tokens=100, latency_ms=10.0)

        assert tracker.measured_cost_usd == 0.0, "a measured zero is a value, not an absence"
        assert tracker.measured_call_count == 1
        assert tracker.estimated_cost_usd == pytest.approx(0.00075)
        assert tracker.estimated_call_count == 1
        assert tracker.unpriced_call_count == 1

        summary = tracker.summary()
        assert summary["resolved_models"] == ["ollama/qwen2:1.5b"]
        # No key sums the two together: one number cannot be labelled both
        # "measured" and "estimated", and merging them un-labels the estimate.
        assert "total_cost_usd" not in summary


@pytest.mark.asyncio
async def test_a_run_with_no_measured_call_reports_none_not_zero():
    async with CostTracker(run_id="r2", tenant_id="t2") as tracker:
        tracker.record(model="aisoc-triage", prompt_tokens=10, completion_tokens=5, latency_ms=1.0)
        assert tracker.measured_cost_usd is None
        assert tracker.estimated_cost_usd is None
        assert CostSummary.from_tracker(tracker) == CostSummary(
            measured_usd=None,
            measured_calls=0,
            estimated_usd=None,
            estimated_calls=0,
            unpriced_calls=1,
        )


@pytest.mark.asyncio
async def test_cost_summary_default_carries_no_money():
    """The value a cached or deterministic verdict is recorded with.

    ``cost_usd: float = 0.0`` was the old default at every call site, so a
    verdict that placed no LLM call was persisted, traced and budgeted as one
    that cost nothing — which happens to be the same words but is not the
    same claim.
    """
    empty = CostSummary()
    assert empty.measured_usd is None and empty.measured_calls == 0
    assert empty.estimated_usd is None
