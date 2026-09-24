"""The API service's half of the gateway routing rule.

``services/api`` is a separate package from ``services/agents`` and cannot
import its factory, so ``app.services.model_aliases`` mirrors
``app.llm.routing``. Two copies of a rule drift, and the drift is invisible
until a deployment behaves differently in one service than the other — so the
same behaviours are asserted on both sides, and
``scripts/check_llm_model_routing.py`` compares the two module surfaces.
"""

from __future__ import annotations

import pytest
from app.services.model_aliases import (
    ROLES,
    UnroutableModelError,
    chat_completions_url,
    is_gateway_alias,
    resolve_api_key,
    resolve_base_url,
    resolve_model_alias,
)

_DEFAULT_URL = "https://api.openai.com/v1/chat/completions"


@pytest.fixture(autouse=True)
def _clean_llm_env(monkeypatch):
    for var in (
        "OPENAI_BASE_URL",
        "LLM_BASE_URL",
        "LLM_GATEWAY_URL",
        "LITELLM_MASTER_KEY",
        "OPENAI_API_KEY",
        "LLM_API_KEY",
        *(f"AISOC_MODEL_PIN_{role.upper()}" for role in ROLES),
    ):
        monkeypatch.delenv(var, raising=False)


def test_alias_shape_matches_the_roles_the_gateway_defines():
    for role in ROLES:
        assert resolve_model_alias(role) == f"aisoc-{role}"
        assert is_gateway_alias(resolve_model_alias(role))


def test_base_url_adopts_the_compose_gateway_for_an_alias(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    assert resolve_base_url("aisoc-nl") == "http://litellm:4000/v1"


def test_base_url_leaves_a_concrete_model_at_its_provider(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    assert resolve_base_url("gpt-4o-mini") is None


def test_explicit_base_url_outranks_the_gateway(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LLM_BASE_URL", "http://my-vllm:8000/v1")
    assert resolve_base_url("aisoc-nl") == "http://my-vllm:8000/v1"


def test_api_key_pairs_with_the_route(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "sk-gateway")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-provider")
    assert resolve_api_key("aisoc-nl") == "sk-gateway"
    assert resolve_api_key("gpt-4o-mini") == "sk-provider"


def test_completions_url_refuses_an_alias_with_no_gateway():
    with pytest.raises(UnroutableModelError, match="aisoc-nl"):
        chat_completions_url("aisoc-nl")


def test_completions_url_allows_a_concrete_model_with_no_gateway():
    assert chat_completions_url("gpt-4o-mini") == _DEFAULT_URL


def test_completions_url_appends_the_path_once(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://litellm:4000/v1/")
    assert chat_completions_url("aisoc-nl") == "http://litellm:4000/v1/chat/completions"
