"""Extra T2.3 coverage: streaming, model wrapper, secrets, enforcement toggle.

These tests complement ``test_llm_contract.py``. The base file covers the
validator on dict messages; here we exercise the parts of the safety surface
that ship to production but had no direct assertions:

* :func:`safe_astream` — the streaming counterpart of ``safe_ainvoke``,
* :func:`make_safe_chat_model` — the wrapper used when a caller already
  holds a chat-model reference,
* :func:`classify_message` secret-pattern branch,
* :func:`set_contract_enforcement` — the soft-mode escape hatch.

If any of these regress we lose either a defence layer or the ability to
debug locally with the gate disabled.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.llm.contract import (
    LLMContractViolation,
    classify_message,
    is_contract_enforced,
    make_safe_chat_model,
    safe_astream,
    set_contract_enforcement,
    validate_messages,
)


@pytest.fixture
def contract_enforced():
    prev = set_contract_enforcement(True)
    try:
        yield
    finally:
        set_contract_enforcement(prev)


# ---------------------------------------------------------------------------
# safe_astream — validates once, then yields underlying chunks
# ---------------------------------------------------------------------------


class _FakeStreamingLLM:
    """Minimal stand-in for a LangChain chat model with .astream."""

    def __init__(self, chunks: list[str]) -> None:
        self._chunks = chunks
        self.calls: list[list[dict[str, Any]]] = []

    async def astream(self, messages: list[Any], **_: Any):
        self.calls.append(list(messages))
        for chunk in self._chunks:
            yield chunk

    async def ainvoke(self, messages: list[Any], **_: Any) -> str:
        self.calls.append(list(messages))
        return "".join(self._chunks)


async def test_safe_astream_yields_chunks_when_messages_clean(contract_enforced) -> None:
    llm = _FakeStreamingLLM(["alpha", "beta", "gamma"])
    safe_msgs = [
        {"role": "system", "content": "You are a security analyst."},
        {"role": "user", "content": "Summarise the incident in two sentences."},
    ]

    collected: list[str] = []
    async for chunk in safe_astream(llm, safe_msgs):
        collected.append(chunk)

    assert collected == ["alpha", "beta", "gamma"]
    assert llm.calls == [safe_msgs], "underlying llm must receive the exact message list"


async def test_safe_astream_rejects_violating_messages_before_yield(
    contract_enforced,
) -> None:
    llm = _FakeStreamingLLM(["should-never-emit"])
    bad_msgs = [
        {"role": "user", "content": json.dumps({"class_uid": 7003, "activity_id": 1})},
    ]

    collected: list[str] = []
    with pytest.raises(LLMContractViolation):
        async for chunk in safe_astream(llm, bad_msgs):
            collected.append(chunk)

    assert collected == [], "no chunks must escape when the contract is violated"
    assert llm.calls == [], "the underlying llm must never be invoked"


# ---------------------------------------------------------------------------
# make_safe_chat_model — wrapper routes ainvoke/astream through the contract
# ---------------------------------------------------------------------------


class _FakeChatModel:
    """Records calls and exposes a non-LLM attribute we expect to passthrough."""

    model_name = "fake-gpt"

    def __init__(self) -> None:
        self.invocations: list[list[Any]] = []

    async def ainvoke(self, messages: list[Any], **_: Any) -> str:
        self.invocations.append(list(messages))
        return "ok"

    async def astream(self, messages: list[Any], **_: Any):
        self.invocations.append(list(messages))
        for token in ("o", "k"):
            yield token


async def test_make_safe_chat_model_allows_safe_messages(contract_enforced) -> None:
    inner = _FakeChatModel()
    guarded = make_safe_chat_model(inner)

    result = await guarded.ainvoke([{"role": "user", "content": "How risky is this alert?"}])

    assert result == "ok"
    assert len(inner.invocations) == 1


async def test_make_safe_chat_model_blocks_raw_ocsf(contract_enforced) -> None:
    inner = _FakeChatModel()
    guarded = make_safe_chat_model(inner)

    raw = json.dumps({"class_uid": 1001, "activity_id": 2, "metadata": {"product": "Sentinel"}})

    with pytest.raises(LLMContractViolation):
        await guarded.ainvoke([{"role": "user", "content": raw}])

    assert inner.invocations == [], "blocked prompt must never reach the chat model"


def test_make_safe_chat_model_passes_through_non_llm_attributes() -> None:
    """Wrapper must remain a drop-in proxy for everything except ainvoke/astream."""
    inner = _FakeChatModel()
    guarded = make_safe_chat_model(inner)

    assert guarded.model_name == "fake-gpt"


# ---------------------------------------------------------------------------
# classify_message — the secret-pattern branch is the last-resort guard
# ---------------------------------------------------------------------------


def test_classify_message_flags_api_key_assignment() -> None:
    """`api_key = '...long...'` style assignments must be classified as leaking."""
    leak = "Found in code: api_key = 'sk-AbCdEf0123456789xyz'"
    reason = classify_message(leak)
    assert reason is not None
    assert "secret" in reason.lower()


def test_classify_message_flags_pem_private_key_header() -> None:
    pem_header = "Pasted from server: -----BEGIN RSA PRIVATE KEY-----\\nMIIE…"
    reason = classify_message(pem_header)
    assert reason is not None
    assert "secret" in reason.lower()


# ---------------------------------------------------------------------------
# Enforcement toggle — operators MUST be able to soft-disable for debugging
# ---------------------------------------------------------------------------


def test_set_contract_enforcement_soft_mode_lets_raw_ocsf_through() -> None:
    raw = json.dumps({"class_uid": 1, "activity_id": 2, "metadata": {"product": "x"}})
    prev = set_contract_enforcement(False)
    try:
        assert is_contract_enforced() is False
        # When soft, validator must not raise. The return value is the
        # normalised view; we just need this to not blow up.
        normalised = validate_messages([{"role": "user", "content": raw}])
        assert normalised == [{"role": "user", "content": raw}]
    finally:
        set_contract_enforcement(prev)


def test_set_contract_enforcement_returns_previous_value() -> None:
    prev = set_contract_enforcement(True)
    try:
        was = set_contract_enforcement(False)
        assert was is True
        was_again = set_contract_enforcement(True)
        assert was_again is False
    finally:
        set_contract_enforcement(prev)


def test_enforcement_toggle_restores_blocking_after_soft_window() -> None:
    """Soft mode must not 'stick' — restoring True must re-arm rejection."""
    raw = json.dumps({"class_uid": 42, "metadata": {"product": "x", "version": "1"}})
    prev = set_contract_enforcement(False)
    try:
        validate_messages([{"role": "user", "content": raw}])  # passes
    finally:
        set_contract_enforcement(prev)
    set_contract_enforcement(True)
    try:
        with pytest.raises(LLMContractViolation):
            validate_messages([{"role": "user", "content": raw}])
    finally:
        set_contract_enforcement(prev)
