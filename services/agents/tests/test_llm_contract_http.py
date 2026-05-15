"""Tests for ``safe_chat_completions_request`` — the raw-HTTP LLM wrapper.

These tests ensure the helper:

* validates messages against the LLM input contract *before* hitting the
  network (so a violation never leaks on the wire),
* forwards body / headers / extra kwargs correctly,
* surfaces httpx transport errors so callers can decide whether to
  fall back to deterministic behaviour,
* refuses to run without an API key.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.llm.contract import (
    DEFAULT_OPENAI_CHAT_COMPLETIONS_URL,
    LLMContractViolation,
    safe_chat_completions_request,
    set_contract_enforcement,
)


@pytest.fixture
def contract_enforced():
    prev = set_contract_enforcement(True)
    try:
        yield
    finally:
        set_contract_enforcement(prev)


def _mock_async_client(response_json: dict[str, Any], status: int = 200):
    """Return a patched ``httpx.AsyncClient`` whose ``.post`` yields ``response_json``."""
    response = MagicMock(spec=httpx.Response)
    response.status_code = status
    response.json = MagicMock(return_value=response_json)
    if status >= 400:
        response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                f"status {status}", request=MagicMock(), response=response
            )
        )
    else:
        response.raise_for_status = MagicMock(return_value=None)

    client = MagicMock()
    client.post = AsyncMock(return_value=response)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return client, response


@pytest.mark.asyncio
async def test_safe_chat_completions_request_success(contract_enforced) -> None:
    """Happy-path: contract passes, body forwarded, parsed JSON returned."""
    expected_response = {"choices": [{"message": {"content": "hello"}}]}
    client, _ = _mock_async_client(expected_response)

    with patch("httpx.AsyncClient", return_value=client):
        result = await safe_chat_completions_request(
            api_key="sk-test",
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an analyst."},
                {"role": "user", "content": "Summarise this alert title: Suspicious login"},
            ],
            max_tokens=128,
        )

    assert result == expected_response
    # body forwarded with all expected fields
    call_kwargs = client.post.call_args
    assert call_kwargs.args[0] == DEFAULT_OPENAI_CHAT_COMPLETIONS_URL
    body = call_kwargs.kwargs["json"]
    assert body["model"] == "gpt-4o-mini"
    assert body["max_tokens"] == 128
    assert body["messages"][0]["role"] == "system"
    headers = call_kwargs.kwargs["headers"]
    assert headers["Authorization"] == "Bearer sk-test"
    assert headers["Content-Type"] == "application/json"


@pytest.mark.asyncio
async def test_safe_chat_completions_request_rejects_raw_ocsf(contract_enforced) -> None:
    """Contract must reject OCSF-shaped payloads before any network call happens."""
    raw_log = json.dumps({"class_uid": 1, "activity_id": 2, "metadata": {"product": "X"}})

    client, _ = _mock_async_client({"choices": []})
    with patch("httpx.AsyncClient", return_value=client):
        with pytest.raises(LLMContractViolation):
            await safe_chat_completions_request(
                api_key="sk-test",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": raw_log}],
            )

    # critical: no network call was attempted
    client.post.assert_not_called()


@pytest.mark.asyncio
async def test_safe_chat_completions_request_requires_api_key() -> None:
    """Empty API key must raise before any contract / network work."""
    with pytest.raises(ValueError, match="api_key is required"):
        await safe_chat_completions_request(
            api_key="",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "hi"}],
        )


@pytest.mark.asyncio
async def test_safe_chat_completions_request_propagates_http_errors(
    contract_enforced,
) -> None:
    """Non-2xx responses surface as ``httpx.HTTPStatusError`` for caller fallback."""
    client, _ = _mock_async_client({"error": "rate limited"}, status=429)
    with patch("httpx.AsyncClient", return_value=client):
        with pytest.raises(httpx.HTTPStatusError):
            await safe_chat_completions_request(
                api_key="sk-test",
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "summarise"}],
            )


@pytest.mark.asyncio
async def test_safe_chat_completions_request_forwards_extra_body(
    contract_enforced,
) -> None:
    """Extra kwargs (response_format, temperature, etc.) make it into the body."""
    client, _ = _mock_async_client({"choices": []})
    with patch("httpx.AsyncClient", return_value=client):
        await safe_chat_completions_request(
            api_key="sk-test",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "translate to ES|QL"}],
            response_format={"type": "json_object"},
            temperature=0,
        )

    body = client.post.call_args.kwargs["json"]
    assert body["response_format"] == {"type": "json_object"}
    assert body["temperature"] == 0


@pytest.mark.asyncio
async def test_safe_chat_completions_request_merges_extra_headers(
    contract_enforced,
) -> None:
    """``extra_headers`` should be merged on top of the defaults."""
    client, _ = _mock_async_client({"choices": []})
    with patch("httpx.AsyncClient", return_value=client):
        await safe_chat_completions_request(
            api_key="sk-test",
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "hi"}],
            extra_headers={"OpenAI-Beta": "assistants=v2"},
        )

    headers = client.post.call_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer sk-test"
    assert headers["OpenAI-Beta"] == "assistants=v2"


@pytest.mark.asyncio
async def test_safe_chat_completions_request_honours_custom_url(
    contract_enforced,
) -> None:
    """Caller-provided URL overrides the default (for compatible endpoints)."""
    client, _ = _mock_async_client({"choices": []})
    custom_url = "https://api.example.test/v1/chat/completions"
    with patch("httpx.AsyncClient", return_value=client):
        await safe_chat_completions_request(
            api_key="sk-test",
            model="local-model",
            messages=[{"role": "user", "content": "hello"}],
            url=custom_url,
        )

    assert client.post.call_args.args[0] == custom_url
