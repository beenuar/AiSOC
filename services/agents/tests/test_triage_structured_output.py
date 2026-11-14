"""Auto-triage must ask the provider for JSON, not hope for it.

Measured over 50 alerts through the gateway against the bundled
``llama3.2:3b-instruct-q4_K_M``, replies the triage parser could use went from
44/50 to 50/50 once ``response_format={"type": "json_object"}`` was requested.
Every one of the six failures carried a correct verdict and confidence and a
malformed ``rationale`` — an unquoted value, or an invalid ``\\'`` escape — and
none was truncated. Constraining the grammar removes that class at the source.

These tests read the request payload LangChain would actually send, rather than
asserting that a keyword argument was passed. The parameter has moved between
top-level and ``model_kwargs`` across langchain-openai versions, so checking the
call signature would pass while the provider received nothing.

Reproduce the measurement with::

    python3 scripts/measure_triage_reliability.py --attempts 50 --json-mode
"""

from __future__ import annotations

import ast
import warnings
from pathlib import Path

import pytest
from app.llm.factory import make_chat_model

AGENT_SOURCE = Path(__file__).resolve().parent.parent / "app" / "agents" / "auto_triage_agent.py"


def _payload(model) -> dict:
    return model._get_request_payload([("human", "hi")])


@pytest.fixture(autouse=True)
def _gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    """A routable gateway, so the factory does not refuse an alias."""
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://gateway.invalid:4000")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")


def test_json_output_reaches_the_request_payload() -> None:
    payload = _payload(make_chat_model("triage", temperature=0.0, max_tokens=512, json_output=True))
    assert payload.get("response_format") == {"type": "json_object"}


def test_json_output_is_opt_in() -> None:
    """A caller that parses prose must not silently get JSON mode."""
    assert "response_format" not in _payload(make_chat_model("triage", temperature=0.0))


def test_json_output_preserves_the_other_parameters() -> None:
    """The fix must not cost the sampling settings triage depends on."""
    payload = _payload(make_chat_model("triage", temperature=0.0, max_tokens=512, json_output=True))
    assert payload["temperature"] == 0.0
    # langchain-openai renamed this; accept whichever key this version emits,
    # but require the value to have survived.
    assert payload.get("max_completion_tokens", payload.get("max_tokens")) == 512


def test_json_output_does_not_discard_caller_model_kwargs() -> None:
    """Setting response_format must merge, not replace."""
    model = make_chat_model("triage", json_output=True, model_kwargs={"seed": 7})
    payload = _payload(model)
    assert payload.get("seed") == 7
    assert payload.get("response_format") == {"type": "json_object"}


def test_json_output_emits_no_warning() -> None:
    """Constructed on a hot path; a per-call UserWarning is log noise.

    langchain warns when an undeclared field is passed top-level, which is why
    the factory routes it through ``model_kwargs``.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("error", UserWarning)
        make_chat_model("triage", temperature=0.0, max_tokens=512, json_output=True)


def test_auto_triage_requests_structured_output() -> None:
    """The call site, read from source — this is what fails on the pre-fix tree.

    Parsed rather than grepped: a string match would be satisfied by the word
    appearing in a comment explaining why it is absent.
    """
    tree = ast.parse(AGENT_SOURCE.read_text())
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "make_chat_model"
    ]
    assert calls, "auto_triage_agent no longer calls make_chat_model — update this test"
    for call in calls:
        flag = next((kw for kw in call.keywords if kw.arg == "json_output"), None)
        assert flag is not None, "auto-triage parses the reply as JSON but does not ask for JSON"
        assert isinstance(flag.value, ast.Constant) and flag.value.value is True
