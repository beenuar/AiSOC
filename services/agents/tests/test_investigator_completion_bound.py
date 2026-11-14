"""Every investigator LLM call carries a completion bound.

The pipeline placed all four of its calls with no bound, and a small
quantised model that failed to stop generated 40,960 tokens over twenty
minutes on one of them. A test that only exercised `max_completion_tokens()`
would not have caught that, because the defect was at the call sites: the
helper is worth nothing if an agent forgets to pass it. So the call sites are
read off disk, which is the direction this drifts — a fifth agent added later
inherits the old default by simply not knowing about this module.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from app.investigator.limits import DEFAULT_MAX_COMPLETION_TOKENS, max_completion_tokens
from app.llm.factory import make_chat_model

INVESTIGATOR = Path(__file__).resolve().parents[1] / "app" / "investigator"

#: The largest legitimate completion measured across the pipeline on the eval
#: corpus — the report writer, which writes the longest output of the four.
LONGEST_LEGITIMATE_COMPLETION = 876


def _make_chat_model_calls() -> list[tuple[str, ast.Call]]:
    found: list[tuple[str, ast.Call]] = []
    for path in sorted(INVESTIGATOR.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "make_chat_model":
                found.append((path.name, node))
    return found


def test_the_call_sites_exist_so_this_test_is_not_vacuous():
    assert len(_make_chat_model_calls()) >= 4


@pytest.mark.parametrize("module_and_call", _make_chat_model_calls(), ids=lambda mc: f"{mc[0]}:{mc[1].lineno}")
def test_every_investigator_llm_call_bounds_its_completion(module_and_call):
    module, call = module_and_call
    passed = {kw.arg for kw in call.keywords}
    assert "max_tokens" in passed, (
        f"{module}:{call.lineno} places an LLM call with no completion bound — a model that fails to stop runs to the context window"
    )


def test_the_bound_clears_the_longest_reply_the_agents_actually_write():
    """A bound that truncates real output would be a quality regression."""
    assert DEFAULT_MAX_COMPLETION_TOKENS > LONGEST_LEGITIMATE_COMPLETION * 2


def test_the_default_applies_with_no_configuration(monkeypatch):
    monkeypatch.delenv("AISOC_INVESTIGATOR_MAX_COMPLETION_TOKENS", raising=False)
    assert max_completion_tokens() == DEFAULT_MAX_COMPLETION_TOKENS


def test_an_operator_can_raise_it(monkeypatch):
    monkeypatch.setenv("AISOC_INVESTIGATOR_MAX_COMPLETION_TOKENS", "8192")
    assert max_completion_tokens() == 8192


def test_removing_the_bound_stays_reachable_but_deliberate(monkeypatch):
    monkeypatch.setenv("AISOC_INVESTIGATOR_MAX_COMPLETION_TOKENS", "0")
    assert max_completion_tokens() is None


def test_the_bound_reaches_an_openai_compatible_server_under_its_old_name(monkeypatch):
    """langchain-openai renames the field on the wire; Ollama reads the old name.

    A bound the provider ignores is not a bound. Measured against Ollama with
    `qwen2.5:0.5b`, a 64-token limit returned 64 tokens under `max_tokens`
    and 72 under `max_completion_tokens`, which is what the typed field now
    becomes.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "probe")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("AISOC_MODEL_PIN_RECON", "qwen2.5:0.5b")
    llm = make_chat_model("recon", temperature=0, max_tokens=123)
    assert (getattr(llm, "extra_body", None) or {}).get("max_tokens") == 123


def test_openai_itself_is_not_sent_the_name_it_rejects(monkeypatch):
    """OpenAI refuses `max_tokens` for its newer models, so only the field goes."""
    monkeypatch.setenv("OPENAI_API_KEY", "probe")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.setenv("AISOC_MODEL_PIN_RECON", "gpt-4o-mini")
    llm = make_chat_model("recon", temperature=0, max_tokens=123)
    assert not (getattr(llm, "extra_body", None) or {})


def test_no_bound_means_no_compatibility_shim(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "probe")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://127.0.0.1:11434/v1")
    monkeypatch.setenv("AISOC_MODEL_PIN_RECON", "qwen2.5:0.5b")
    llm = make_chat_model("recon", temperature=0)
    assert not (getattr(llm, "extra_body", None) or {})


def test_a_typo_falls_back_to_the_bound_not_past_it(monkeypatch):
    """Unbounded must never be reachable by accident."""
    monkeypatch.setenv("AISOC_INVESTIGATOR_MAX_COMPLETION_TOKENS", "lots")
    assert max_completion_tokens() == DEFAULT_MAX_COMPLETION_TOKENS
    monkeypatch.setenv("AISOC_INVESTIGATOR_MAX_COMPLETION_TOKENS", "")
    assert max_completion_tokens() == DEFAULT_MAX_COMPLETION_TOKENS
