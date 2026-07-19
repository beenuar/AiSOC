"""Tests for the LLM factory — alias + base-URL resolution (#478)."""

from __future__ import annotations

import pytest
from app.llm.factory import (
    chat_completions_url,
    make_chat_model,
    resolve_base_url,
    resolve_model_alias,
)

# app.llm.contract.DEFAULT_OPENAI_CHAT_COMPLETIONS_URL
_DEFAULT_URL = "https://api.openai.com/v1/chat/completions"


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    """Start each test from a known-empty LLM env."""
    for var in (
        "OPENAI_BASE_URL",
        "LLM_BASE_URL",
        "LLM_GATEWAY_URL",
        "AISOC_MODEL_PIN_TRIAGE",
        "AISOC_MODEL_PIN_NL",
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


def test_base_url_ignores_gateway_url_env(monkeypatch):
    # Routing through the gateway must be explicit (OPENAI_BASE_URL), never
    # silently adopted from the compose-provided LLM_GATEWAY_URL.
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    assert resolve_base_url() is None


# ── chat_completions_url ─────────────────────────────────────────────────────


def test_chat_completions_url_default():
    assert chat_completions_url() == _DEFAULT_URL


def test_chat_completions_url_appends_path(monkeypatch):
    monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm:4000/v1/")
    assert chat_completions_url() == "http://litellm:4000/v1/chat/completions"


# ── make_chat_model ──────────────────────────────────────────────────────────


def test_make_chat_model_uses_alias_and_base_url(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://litellm:4000/v1")
    llm = make_chat_model("triage", temperature=0.0, max_tokens=256)
    # langchain_openai exposes the model id as ``model_name``.
    assert llm.model_name == "aisoc-triage"
    assert str(llm.openai_api_base).rstrip("/") == "http://litellm:4000/v1"
