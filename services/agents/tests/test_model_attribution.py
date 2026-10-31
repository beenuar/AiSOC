"""Serving-model attribution: who answered the call, and how we know.

The defect these cover
----------------------
Every published verdict-eval row measured a model served directly by an
OpenAI-compatible endpoint, and every one of them shipped with
``resolved_models: []`` — "calls were placed, but no gateway named the model
that took them". The serving identity was in the response body's ``model``
field the whole time; nothing read it, because the only extractor was the
LiteLLM-header one.

The trap that makes the body field dangerous to read naively:
``langchain_openai`` builds ``response_metadata["model_name"]`` as
``response_dict.get("model", self.model_name)`` — the **requested** name is
the fallback when the body carried none. Copying the requested alias into
serving-model metadata is exactly what the attribution rules forbid, so the
extractor only credits the body when there is evidence the body was parsed:
either the reported name differs from the requested one, or the response
carries its own ``id`` (set by langchain only when the body had one).

Fixtures mirror ``test_cost_provenance.py``: the LiteLLM headers are the
measured set from ``ghcr.io/berriai/litellm:v1.102.1``; the body shapes are
what an Ollama 0.5-class server and OpenAI's API return for a chat
completion.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.core.cost_telemetry import CostSummary, CostTracker
from app.core.model_attribution import (
    ATTRIBUTION_GATEWAY_HEADER,
    ATTRIBUTION_RESPONSE_BODY,
    STATUS_MIXED_SERVING,
    STATUS_NO_CALLS,
    STATUS_SELF_REPORTED,
    STATUS_UNATTRIBUTED,
    STATUS_VERIFIED,
    extract_serving_attribution,
    models_match,
    run_provenance_status,
)

GATEWAY_HEADERS = {
    "x-litellm-call-id": "716640f2-e268-47dd-b53e-d956fe9d6361",
    "x-litellm-model-name": "ollama/qwen2:1.5b",
    "x-litellm-response-cost-original": "0.0",
}


def _response(
    *,
    headers: dict[str, str] | None = None,
    model_name: str | None = None,
    response_id: str | None = None,
    system_fingerprint: str | None = None,
):
    metadata: dict[str, object] = {}
    if model_name is not None:
        metadata["model_name"] = model_name
    if response_id is not None:
        metadata["id"] = response_id
    if system_fingerprint is not None:
        metadata["system_fingerprint"] = system_fingerprint
    if headers is not None:
        metadata["headers"] = dict(headers)
    return SimpleNamespace(
        content="ok",
        usage_metadata={"input_tokens": 19, "output_tokens": 3},
        response_metadata=metadata,
    )


# ---------------------------------------------------------------------------
# Extraction: which party named the serving model
# ---------------------------------------------------------------------------


def test_gateway_header_is_the_strongest_source():
    """The party that routed the call says what it called."""
    response = _response(headers=GATEWAY_HEADERS, model_name="aisoc-triage", response_id="chatcmpl-1")
    attribution = extract_serving_attribution(response, requested="aisoc-triage")
    assert attribution.serving_model == "ollama/qwen2:1.5b"
    assert attribution.source == ATTRIBUTION_GATEWAY_HEADER


def test_body_echo_with_id_witness_is_server_reported():
    """Ollama echoes the exact requested name — with an ``id``, that is the body speaking."""
    response = _response(model_name="llama3.1:8b-instruct-q4_K_M", response_id="chatcmpl-529")
    attribution = extract_serving_attribution(response, requested="llama3.1:8b-instruct-q4_K_M")
    assert attribution.serving_model == "llama3.1:8b-instruct-q4_K_M"
    assert attribution.source == ATTRIBUTION_RESPONSE_BODY


def test_body_name_differing_from_request_is_server_reported_without_witness():
    """OpenAI answers ``gpt-4o`` with ``gpt-4o-2024-08-06``: only the body knows that."""
    response = _response(model_name="gpt-4o-2024-08-06")
    attribution = extract_serving_attribution(response, requested="gpt-4o")
    assert attribution.serving_model == "gpt-4o-2024-08-06"
    assert attribution.source == ATTRIBUTION_RESPONSE_BODY


def test_equal_name_without_witness_is_not_attributed():
    """``model_name == requested`` with no ``id`` is indistinguishable from the
    langchain fallback that copies the requested name, so it must not be
    credited as a server claim. The requested alias is never copied into
    serving metadata."""
    response = _response(model_name="aisoc-triage")
    attribution = extract_serving_attribution(response, requested="aisoc-triage")
    assert attribution.serving_model is None
    assert attribution.source is None


def test_no_metadata_is_not_attributed():
    attribution = extract_serving_attribution(SimpleNamespace(content="ok"), requested="gpt-4o")
    assert attribution.serving_model is None
    assert attribution.source is None


def test_system_fingerprint_is_captured_when_present():
    response = _response(model_name="gpt-4o-2024-08-06", system_fingerprint="fp_abc123")
    attribution = extract_serving_attribution(response, requested="gpt-4o")
    assert attribution.system_fingerprint == "fp_abc123"


def test_empty_fingerprint_is_absent_not_empty_string():
    """langchain defaults ``system_fingerprint`` to ``""`` — absent, not a value."""
    response = _response(model_name="gpt-4o-2024-08-06", system_fingerprint="")
    attribution = extract_serving_attribution(response, requested="gpt-4o")
    assert attribution.system_fingerprint is None


# ---------------------------------------------------------------------------
# Matching: does the serving identity answer for the requested name
# ---------------------------------------------------------------------------


def test_provider_prefix_does_not_defeat_a_match():
    assert models_match(requested="qwen2:1.5b", serving="ollama/qwen2:1.5b")
    assert models_match(requested="gpt-4o-mini", serving="openai/gpt-4o-mini")


def test_a_version_suffix_still_matches_the_family():
    """OpenAI serves ``gpt-4o`` as ``gpt-4o-2024-08-06``; that is the same ask."""
    assert models_match(requested="gpt-4o", serving="gpt-4o-2024-08-06")


def test_a_different_model_does_not_match():
    assert not models_match(requested="llama3.1:8b-instruct-q4_K_M", serving="ollama/qwen2:1.5b")
    assert not models_match(requested="gpt-4o", serving="gpt-4o-mini")


def test_an_alias_matches_any_serving_model():
    """An ``aisoc-<role>`` alias is a label the gateway resolves — any concrete
    serving model is the correct answer for it, and must still be *named*."""
    assert models_match(requested="aisoc-triage", serving="ollama/qwen2:1.5b")


# ---------------------------------------------------------------------------
# Run-level provenance status
# ---------------------------------------------------------------------------


def test_zero_calls_is_its_own_status():
    assert run_provenance_status(llm_calls=0, attributed_by_source={}, serving_models=(), requested=()) == STATUS_NO_CALLS


def test_all_gateway_attributed_is_verified():
    status = run_provenance_status(
        llm_calls=72,
        attributed_by_source={ATTRIBUTION_GATEWAY_HEADER: 72},
        serving_models=("ollama/qwen2:1.5b",),
        requested=("aisoc-triage",),
    )
    assert status == STATUS_VERIFIED


def test_body_attribution_is_self_reported_not_verified():
    status = run_provenance_status(
        llm_calls=72,
        attributed_by_source={ATTRIBUTION_RESPONSE_BODY: 72},
        serving_models=("llama3.1:8b-instruct-q4_K_M",),
        requested=("llama3.1:8b-instruct-q4_K_M",),
    )
    assert status == STATUS_SELF_REPORTED


def test_calls_with_no_attribution_are_unattributed():
    status = run_provenance_status(llm_calls=72, attributed_by_source={}, serving_models=(), requested=("gpt-4o",))
    assert status == STATUS_UNATTRIBUTED


def test_partial_attribution_is_not_promoted():
    """60 attributed of 72 placed: the run cannot claim full attribution."""
    status = run_provenance_status(
        llm_calls=72,
        attributed_by_source={ATTRIBUTION_RESPONSE_BODY: 60},
        serving_models=("llama3.1:8b-instruct-q4_K_M",),
        requested=("llama3.1:8b-instruct-q4_K_M",),
    )
    assert status == STATUS_UNATTRIBUTED + ":partial"


def test_a_substituted_backend_is_named_not_averaged():
    """A concrete requested model answered by a different one is a substitution,
    whatever the attribution source — the run must not be advertised as the
    requested model's performance."""
    status = run_provenance_status(
        llm_calls=72,
        attributed_by_source={ATTRIBUTION_GATEWAY_HEADER: 72},
        serving_models=("ollama/qwen2:1.5b",),
        requested=("llama3.1:8b-instruct-q4_K_M",),
    )
    assert status == STATUS_MIXED_SERVING


# ---------------------------------------------------------------------------
# Tracker integration: attribution flows into the run summary
# ---------------------------------------------------------------------------


async def test_tracker_attribution_reaches_the_summary():
    async with CostTracker(run_id="r1", tenant_id="t1", persist=False) as tracker:
        tracker.record(
            model="llama3.1:8b-instruct-q4_K_M",
            prompt_tokens=10,
            completion_tokens=5,
            latency_ms=12.0,
            resolved_model="llama3.1:8b-instruct-q4_K_M",
            attribution_source=ATTRIBUTION_RESPONSE_BODY,
            system_fingerprint="fp_x",
        )
        summary = CostSummary.from_tracker(tracker)
    assert summary.resolved_models == ("llama3.1:8b-instruct-q4_K_M",)
    assert summary.attribution_sources == {ATTRIBUTION_RESPONSE_BODY: 1}
    assert tracker.summary()["attribution_sources"] == {ATTRIBUTION_RESPONSE_BODY: 1}


async def test_tracker_without_attribution_reports_none_not_requested_name():
    """A call whose serving identity is unknown must not inherit the alias."""
    async with CostTracker(run_id="r2", tenant_id="t1", persist=False) as tracker:
        tracker.record(model="aisoc-triage", prompt_tokens=10, completion_tokens=5, latency_ms=9.0)
        summary = CostSummary.from_tracker(tracker)
    assert summary.resolved_models == ()
    assert summary.attribution_sources == {}
