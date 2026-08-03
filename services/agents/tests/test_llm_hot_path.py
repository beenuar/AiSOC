"""Wave 1 — the LLM hot path now records cost, caches responses, honours BYOK,
and preflights the gateway config (previously all dormant/unwired)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from app.core.cost_telemetry import CostTracker
from app.llm.contract import safe_ainvoke
from app.llm.factory import llm_override, make_chat_model, preflight_llm
from langchain_core.messages import HumanMessage, SystemMessage


class _FakeLLM:
    model = "aisoc-triage"

    def __init__(self) -> None:
        self.calls = 0

    async def ainvoke(self, messages, **kwargs):
        self.calls += 1
        return SimpleNamespace(content="VERDICT", usage_metadata={"input_tokens": 10, "output_tokens": 5})


@pytest.mark.asyncio
async def test_safe_ainvoke_records_cost_into_bound_tracker():
    llm = _FakeLLM()
    msgs = [SystemMessage(content="You are a triage agent."), HumanMessage(content="Alert: benign login from office")]
    async with CostTracker(run_id="r-cost", tenant_id="t-cost") as tracker:
        await safe_ainvoke(llm, msgs)
        # record_llm_call fired via safe_ainvoke — was invisible ($0) before.
        assert tracker.total_tokens == 15
        assert tracker.total_cost_usd >= 0.0


@pytest.mark.asyncio
async def test_safe_ainvoke_serves_identical_call_from_cache():
    llm = _FakeLLM()
    # Unique content so no cross-test cache collision.
    msgs = [SystemMessage(content="sys wave1-cache-xyz"), HumanMessage(content="input wave1-cache-abc")]
    r1 = await safe_ainvoke(llm, msgs)
    r2 = await safe_ainvoke(llm, msgs)
    assert llm.calls == 1, "second identical call should be served from cache"
    assert r1.content == r2.content == "VERDICT"


def test_llm_override_routes_to_tenant_model(monkeypatch):
    # A tenant BYOK key/model overrides the alias + platform key.
    with llm_override(api_key="tenant-byok-key", base_url="https://byok.example/v1", model="gpt-4o-tenant"):
        m = make_chat_model("triage")
        assert getattr(m, "model_name", None) == "gpt-4o-tenant"
    # Outside the override, back to the alias (platform key from env, as in prod).
    monkeypatch.setenv("OPENAI_API_KEY", "sk-platform-test")
    m2 = make_chat_model("triage")
    assert getattr(m2, "model_name", None) == "aisoc-triage"


def test_preflight_warns_when_no_gateway_base_url(monkeypatch):
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("AISOC_MODEL_PIN_TRIAGE", raising=False)
    warnings = preflight_llm(("triage",))
    assert warnings and "aisoc-triage" in warnings[0]


def test_preflight_silent_with_gateway_base_url(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm:4000/v1")
    assert preflight_llm(("triage",)) == []
