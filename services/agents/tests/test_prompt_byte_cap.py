"""Prompt byte cap at the safe_ainvoke/safe_astream choke point.

A prompt over the inference backend's limit is rejected wholesale and
deterministically; the cap truncates the largest non-system contributor
instead, honestly marked, so the request is answered rather than retried
into a retry storm (the Oct 2026 prefill-guard incident).
"""

from __future__ import annotations

from app.llm import contract
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage


def _total_bytes(msgs) -> int:
    return sum(len(str(getattr(m, "content", "")).encode("utf-8")) for m in msgs)


def test_under_cap_is_untouched(monkeypatch):
    monkeypatch.setattr(contract, "_MAX_PROMPT_BYTES", 10_000)
    msgs = [
        SystemMessage(content="sys"),
        HumanMessage(content="hello"),
        ToolMessage(content="result", tool_call_id="t1"),
    ]
    out = contract._cap_prompt_bytes(msgs)
    assert [m.content for m in out] == ["sys", "hello", "result"]


def test_over_cap_truncates_largest_and_keeps_system(monkeypatch):
    monkeypatch.setattr(contract, "_MAX_PROMPT_BYTES", 5_000)
    big = "X" * 60_000
    msgs = [
        SystemMessage(content="system prompt stays verbatim"),
        HumanMessage(content="small question"),
        ToolMessage(content=big, tool_call_id="t1"),
    ]
    out = contract._cap_prompt_bytes(msgs)
    assert _total_bytes(out) <= 5_000
    assert out[0].content == "system prompt stays verbatim"
    assert out[1].content == "small question"
    assert out[2].content.endswith("[... truncated: AiSOC prompt byte cap ...]")
    assert len(out[2].content) < len(big)
    # original objects are not mutated
    assert msgs[2].content == big


def test_cap_spreads_across_multiple_senders(monkeypatch):
    monkeypatch.setattr(contract, "_MAX_PROMPT_BYTES", 3_000)
    msgs = [
        SystemMessage(content="sys"),
        ToolMessage(content="A" * 4_000, tool_call_id="t1"),
        ToolMessage(content="B" * 4_000, tool_call_id="t2"),
    ]
    out = contract._cap_prompt_bytes(msgs)
    assert _total_bytes(out) <= 3_000
    # both contributors were reduced, order preserved
    assert out[1].content.startswith("A")
    assert out[2].content.startswith("B")


def test_cap_disabled_when_zero(monkeypatch):
    monkeypatch.setattr(contract, "_MAX_PROMPT_BYTES", 0)
    big = "X" * 500_000
    msgs = [HumanMessage(content=big)]
    out = contract._cap_prompt_bytes(msgs)
    assert out[0].content == big
