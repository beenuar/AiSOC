"""The API service must have an LLM input contract, and run it before the POST.

`services/agents` has had a fail-closed contract since T2.3 landed there. The
API service had none: seven endpoints POSTed untrusted input straight to a
chat-completions provider, and the module the repo's own notes described as
living here — ``app/services/llm_safety.py`` — was simply absent from the tree.

The most direct case is ``phishing.py``, which forwards a submitted email body,
attacker-authored by definition.
"""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest
from app.services.llm_safety import (
    LLMContractViolation,
    classify_message,
    safe_chat_completions_request,
)

RAW_OCSF = '{"class_uid": 2001, "activity_id": 1, "metadata": {"product": {"name": "x"}, "version": "1.0"}}'

API_APP = Path(__file__).resolve().parents[1] / "app"


class _Recorder:
    """Records whether a request was ever issued."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"url": url, "headers": headers, "json": json})
        # `raise_for_status` needs a bound request, so build one rather than
        # returning a bare Response.
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}]},
            request=httpx.Request("POST", url),
        )


# ── the contract itself ────────────────────────────────────────────────────


def test_the_api_runs_the_same_classifier_as_the_agents_service() -> None:
    """Two heuristics that disagreed about what counts as a raw log would be
    worse than one: a prompt refused in one service and accepted in the other
    reads as a bug in the refusal."""
    assert classify_message(RAW_OCSF) is not None
    assert classify_message("A user signed in from an unfamiliar ASN.") is None


@pytest.mark.asyncio
async def test_a_breaching_prompt_never_reaches_the_provider() -> None:
    """Ordering is the whole point. A check that runs after the request is a
    log line, not a control."""
    recorder = _Recorder()
    with pytest.raises(LLMContractViolation):
        await safe_chat_completions_request(
            api_key="k",
            model="m",
            messages=[{"role": "user", "content": RAW_OCSF}],
            client=recorder,
        )
    assert recorder.calls == [], "the request was issued despite the violation"


@pytest.mark.asyncio
async def test_a_clean_prompt_is_forwarded_with_the_normalised_messages() -> None:
    recorder = _Recorder()
    body = await safe_chat_completions_request(
        api_key="k",
        model="gpt-x",
        messages=[{"role": "user", "content": "Explain this alert."}],
        url="https://provider.test/v1/chat/completions",
        client=recorder,
        temperature=0.1,
    )
    assert body["choices"][0]["message"]["content"] == "ok"
    assert len(recorder.calls) == 1
    sent = recorder.calls[0]
    assert sent["url"] == "https://provider.test/v1/chat/completions"
    assert sent["json"]["model"] == "gpt-x"
    assert sent["json"]["temperature"] == 0.1
    assert sent["json"]["messages"] == [{"role": "user", "content": "Explain this alert."}]
    assert sent["headers"]["Authorization"] == "Bearer k"


@pytest.mark.asyncio
async def test_a_secret_shaped_value_is_refused() -> None:
    """The contract matches an assignment shape (`token: "..."`), not a bare
    high-entropy string — a bare one is indistinguishable from a hostname or
    a hash, both of which are legitimate prompt content."""
    recorder = _Recorder()
    with pytest.raises(LLMContractViolation):
        await safe_chat_completions_request(
            api_key="k",
            model="m",
            messages=[{"role": "user", "content": 'the config had api_key: "AKIAIOSFODNN7EXAMPLE1"'}],
            client=recorder,
        )
    assert recorder.calls == []


# ── every call site actually uses it ───────────────────────────────────────

#: The endpoints the audit found POSTing untrusted input with no contract.
GUARDED_CALL_SITES = (
    "api/v1/endpoints/phishing.py",
    "api/v1/endpoints/translation.py",
    "api/v1/endpoints/knowledge_base.py",
    "api/v1/endpoints/hunts.py",
    "api/v1/endpoints/nl_detection.py",
    "api/v1/endpoints/detection_loop.py",
    "services/alert_explain.py",
)


@pytest.mark.parametrize("relpath", GUARDED_CALL_SITES)
def test_the_call_site_routes_through_the_contract(relpath: str) -> None:
    """A module-by-module assertion rather than one aggregate, so a
    regression names the endpoint that lost its guard."""
    source = (API_APP / relpath).read_text(encoding="utf-8")
    assert "safe_chat_completions_request" in source, f"{relpath} does not route through the contract"


@pytest.mark.parametrize("relpath", GUARDED_CALL_SITES)
def test_the_call_site_no_longer_posts_to_a_completions_endpoint(relpath: str) -> None:
    """The guard is only real if the raw POST is gone.

    Importing the wrapper while leaving the old call in place would pass a
    string-search gate and change nothing.

    Only POSTs aimed at a completions endpoint count. ``hunts.py`` also POSTs
    an ES|QL query to Elasticsearch, which is a different thing entirely and
    must not be flagged.
    """
    path = API_APP / relpath
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    offenders: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr != "post":
            continue
        if isinstance(node.func.value, ast.Name) and node.func.value.id in {"router", "app"}:
            continue
        target = node.args[0] if node.args else next((kw.value for kw in node.keywords if kw.arg == "url"), None)
        if target is None:
            continue
        rendered = ast.get_source_segment(source, target) or ""
        # The URL is usually a variable (`completions_url`) rather than a
        # literal, so match the name as well as the string.
        if "completions" in rendered:
            offenders.append(node.lineno)

    assert not offenders, f"{relpath} still POSTs to a completions endpoint at line(s) {offenders}"


def test_the_nl_query_llm_path_can_resolve_its_imports() -> None:
    """It could not, and the failure was silent.

    The vendored translator imported ``app.llm.contract`` and
    ``app.llm.factory``, neither of which exists in the API process. The
    resulting ImportError was swallowed by a broad ``except``, so
    ``/nl-query`` always returned the deterministic translation and never
    reached a model — safe by accident, and invisible.
    """
    from app.services.llm_safety import safe_chat_completions_request as api_wrapper
    from app.services.model_aliases import chat_completions_url, resolve_model_alias

    assert callable(api_wrapper)
    assert chat_completions_url().endswith("/chat/completions")
    assert resolve_model_alias("nl")
