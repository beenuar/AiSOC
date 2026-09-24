"""Tests for the LLM factory — alias + base-URL resolution (#478)."""

from __future__ import annotations

import pytest
from app.llm.factory import (
    UnroutableModelError,
    chat_completions_url,
    llm_override,
    make_chat_model,
    preflight_llm,
    resolve_api_key,
    resolve_base_url,
    resolve_model_alias,
)
from app.llm.model_pins import all_roles

# app.llm.contract.DEFAULT_OPENAI_CHAT_COMPLETIONS_URL
_DEFAULT_URL = "https://api.openai.com/v1/chat/completions"


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    """Start each test from a known-empty LLM env."""
    for var in (
        "OPENAI_BASE_URL",
        "LLM_BASE_URL",
        "LLM_GATEWAY_URL",
        "LITELLM_MASTER_KEY",
        "OPENAI_API_KEY",
        "LLM_API_KEY",
        "OPENAI_MODEL",
        "LLM_MODEL",
        "AISOC_LLM_MODEL",
        *(f"AISOC_MODEL_PIN_{role.upper()}" for role in all_roles()),
    ):
        monkeypatch.delenv(var, raising=False)


# ── resolve_model_alias ──────────────────────────────────────────────────────


def test_alias_defaults_to_aisoc_role():
    assert resolve_model_alias("triage") == "aisoc-triage"
    assert resolve_model_alias("investigation") == "aisoc-investigation"
    assert resolve_model_alias("nl") == "aisoc-nl"


def test_alias_env_override_escape_hatch(monkeypatch):
    monkeypatch.setenv("AISOC_MODEL_PIN_TRIAGE", "gpt-4o-mini")
    assert resolve_model_alias("triage") == "gpt-4o-mini"
    # Other roles are unaffected by a single-role override.
    assert resolve_model_alias("nl") == "aisoc-nl"


# ── resolve_base_url ─────────────────────────────────────────────────────────


def test_base_url_none_by_default():
    assert resolve_base_url() is None


def test_base_url_prefers_openai_then_llm(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://llm:9/v1")
    assert resolve_base_url() == "http://llm:9/v1"
    monkeypatch.setenv("OPENAI_BASE_URL", "http://gw:4000/v1")
    assert resolve_base_url() == "http://gw:4000/v1"


def test_base_url_adopts_gateway_url_for_an_alias(monkeypatch):
    # The compose-provided variable, which nothing read: an aisoc-<role> alias
    # resolves nowhere else, so the gateway is the only correct destination.
    # Sending it to the provider default is the 404 this whole module exists to
    # stop, and the fallback made it look like "no LLM available".
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    assert resolve_base_url("aisoc-triage") == "http://litellm:4000/v1"
    # No model named => every task role defaults to an alias, so same answer.
    assert resolve_base_url() == "http://litellm:4000/v1"


def test_base_url_leaves_a_concrete_pinned_model_at_its_provider(monkeypatch):
    # The documented direct-to-provider escape hatch. Rerouting it to a gateway
    # that does not define `gpt-4o-mini` would break a working deployment.
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    assert resolve_base_url("gpt-4o-mini") is None


def test_explicit_base_url_outranks_the_gateway(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://my-vllm:8000/v1")
    assert resolve_base_url("aisoc-triage") == "http://my-vllm:8000/v1"
    assert resolve_base_url("gpt-4o-mini") == "http://my-vllm:8000/v1"


# ── resolve_api_key ──────────────────────────────────────────────────────────


def test_api_key_is_the_master_key_when_we_pick_the_gateway(monkeypatch):
    # The route decides the bearer. A provider key sent to LiteLLM is rejected
    # as an invalid proxy token, so resolving the two independently is what
    # made "adopt the gateway URL" look ambiguous in the first place.
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sk-gateway")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider")
    assert resolve_api_key("aisoc-triage") == "sk-gateway"
    # …and the provider key for a model that goes straight to the provider.
    assert resolve_api_key("gpt-4o-mini") == "sk-provider"


def test_api_key_is_the_operators_when_they_set_the_base_url(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sk-gateway")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://my-vllm:8000/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider")
    assert resolve_api_key("aisoc-triage") == "sk-provider"


# ── chat_completions_url ─────────────────────────────────────────────────────


def test_chat_completions_url_default():
    assert chat_completions_url() == _DEFAULT_URL


def test_chat_completions_url_appends_path(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm:4000/v1/")
    assert chat_completions_url() == "http://litellm:4000/v1/chat/completions"


def test_chat_completions_url_refuses_an_alias_with_no_gateway():
    # The loud failure. Previously this returned api.openai.com and the caller
    # took the resulting 404 as evidence that no model was available.
    with pytest.raises(UnroutableModelError, match="aisoc-triage"):
        chat_completions_url("aisoc-triage")


def test_chat_completions_url_allows_a_concrete_model_with_no_gateway():
    assert chat_completions_url("gpt-4o-mini") == _DEFAULT_URL


# ── make_chat_model ──────────────────────────────────────────────────────────


def test_make_chat_model_uses_alias_and_base_url(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm:4000/v1")
    llm = make_chat_model("triage", temperature=0.0, max_tokens=256)
    # langchain_openai exposes the model id as ``model_name``.
    assert llm.model_name == "aisoc-triage"
    assert str(llm.openai_api_base).rstrip("/") == "http://litellm:4000/v1"


def test_make_chat_model_reaches_the_gateway_from_compose_alone(monkeypatch):
    # The default deployment: compose sets LLM_GATEWAY_URL + LITELLM_MASTER_KEY
    # and nothing else. This is the state that could not reach a model.
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sk-aisoc-local")
    llm = make_chat_model("triage")
    assert llm.model_name == "aisoc-triage"
    assert str(llm.openai_api_base).rstrip("/") == "http://litellm:4000/v1"
    assert llm.openai_api_key.get_secret_value() == "sk-aisoc-local"


def test_make_chat_model_refuses_an_alias_with_no_gateway(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    with pytest.raises(UnroutableModelError, match="aisoc-triage"):
        make_chat_model("triage")


def test_byok_model_override_only_when_the_tenant_set_one(monkeypatch):
    # The second defect: OPENAI_MODEL reached make_chat_model through the BYOK
    # override and replaced the role alias with a model the gateway 400s. The
    # override mechanism itself is fine — a real tenant model still wins.
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sk-aisoc-local")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4-turbo-preview")
    assert make_chat_model("triage").model_name == "aisoc-triage"
    with llm_override(model="tenant-model", base_url="http://tenant:1/v1", api_key="sk-tenant"):
        llm = make_chat_model("triage")
    assert llm.model_name == "tenant-model"
    assert str(llm.openai_api_base).rstrip("/") == "http://tenant:1/v1"


# ── preflight_llm ────────────────────────────────────────────────────────────


def test_preflight_clean_when_the_gateway_is_wired(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("OPENAI_MODEL", "aisoc-summary")
    assert preflight_llm() == []


def test_preflight_reports_an_alias_with_no_gateway():
    warnings = preflight_llm()
    assert len(warnings) == 1
    assert "aisoc-triage" in warnings[0]


def test_preflight_reports_a_concrete_pin_aimed_at_the_bundled_gateway(monkeypatch):
    # The reverse direction, which is the failure the commercial deployment hit:
    # every call 400'd with "Invalid model name" and degraded to stub output.
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("AISOC_MODEL_PIN_TRIAGE", "gpt-4-turbo-preview")
    warnings = preflight_llm()
    assert any("gpt-4-turbo-preview" in w and "does not define" in w for w in warnings)


def test_preflight_reports_a_byok_model_the_gateway_lacks(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4-turbo-preview")
    warnings = preflight_llm()
    assert any("OPENAI_MODEL" in w and "gpt-4-turbo-preview" in w for w in warnings)


def test_preflight_quiet_about_a_third_party_gateway(monkeypatch):
    # An operator pointing at their own vLLM with concrete model names is
    # correct; only the bundled gateway's contents are knowable from here.
    monkeypatch.setenv("OPENAI_BASE_URL", "http://my-vllm:8000/v1")
    monkeypatch.setenv("AISOC_MODEL_PIN_TRIAGE", "Qwen2.5-32B-Instruct")
    monkeypatch.setenv("OPENAI_MODEL", "Qwen2.5-32B-Instruct")
    assert preflight_llm() == []
