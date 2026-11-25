"""A rejected prompt is reported separately from a provider failure.

Exercise both HTTP routes through the real model/tool loop and input contract.
Only the external HTTP responses and conversation persistence are fixtures.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from app.api import conversation_store, copilot
from app.llm import contract_rules, factory
from fastapi import FastAPI
from structlog.testing import capture_logs

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000111")
ALERT = "00000000-0000-0000-0000-000000000222"
SECRET = "copilot-contract-test-signing-key-with-32-characters"
CANARY = "contract-evidence-must-not-be-echoed"


def _token():
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")

    signing = (
        encode({"alg": "HS256", "typ": "JWT"})
        + b"."
        + encode({"sub": "analyst", "tenant_id": str(TENANT), "type": "access", "role": "analyst", "exp": time.time() + 600})
    )
    return (signing + b"." + base64.urlsafe_b64encode(hmac.digest(SECRET.encode(), signing, hashlib.sha256)).rstrip(b"=")).decode()


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("read_status", [200, 503])
async def test_contract_rejection_is_safe_and_preserves_completed_reads(monkeypatch, stream, read_status):
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://gateway.test/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "test-gateway-key")
    monkeypatch.setenv("AISOC_API_URL", "http://api.test")
    monkeypatch.setattr(contract_rules, "_ENFORCED", True)
    model_calls, api_calls, saved = [], [], []
    real_client = httpx.AsyncClient

    async def handle(request):
        if request.url.host == "api.test":
            api_calls.append(request)
            assert request.url.path == f"/api/v1/alerts/{ALERT}"
            return httpx.Response(read_status, json={"id": ALERT, "title": "WAF blocked requests", "severity": "high"})
        assert request.url.host == "gateway.test"
        model_calls.append(json.loads(request.content))
        # A provider may return a raw snippet alongside its tool call. The
        # next invocation must reject it, including after the read succeeds.
        message = {
            "role": "assistant",
            "content": json.dumps({"class_uid": 2001, "title": CANARY}),
            "tool_calls": [
                {
                    "id": "call-1",
                    "type": "function",
                    "function": {"name": "copilot_record", "arguments": json.dumps({"kind": "alert", "record_id": ALERT})},
                }
            ],
        }
        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "created": 1,
                "model": "aisoc-copilot",
                "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls"}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
            },
        )

    class Client(real_client):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("transport", httpx.MockTransport(handle))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    make_model = factory.make_chat_model
    monkeypatch.setattr(factory, "make_chat_model", lambda *a, **kw: make_model(*a, http_async_client=Client(), **kw))

    async def append(**kwargs):
        assert kwargs["tenant_id"] == TENANT
        saved.extend(kwargs["new_messages"])
        return conversation_store.Conversation("conversation-1", "test", saved, datetime.now(UTC).isoformat())

    monkeypatch.setattr(conversation_store, "append_messages", append)
    app = FastAPI()
    app.include_router(copilot.router)
    with capture_logs() as logs:
        async with real_client(transport=httpx.ASGITransport(app), base_url="http://console.test") as browser:
            response = await browser.post(
                "/api/v1/copilot/chat" + ("/stream" if stream else ""),
                headers={"Authorization": "Bearer " + _token()},
                json={"message": "Investigate this alert."},
            )

    assert response.status_code == 200, response.text
    assert len(model_calls) == 1, "rejected input must not be sent or retried"
    assert len(api_calls) == 1
    payload = json.loads(response.text.splitlines()[0]) if stream else response.json()
    assert payload["source"] == "template"
    assert payload["template_reason"] == "input_contract_rejected"
    assert "input contract" in payload["notice"].lower()
    assert payload["grounding"] is None
    assert payload["data_access"][0]["status"] == ("ok" if read_status == 200 else "could_not_check")
    assert saved[-1]["data_access"] == payload["data_access"]
    assert saved[-1]["notice"] == payload["notice"]
    assert "unanswered question rather than a finding" in saved[-1]["content"]
    for unsupported in ("model or gateway problem", "CPU-only", "auto-triage", "Retrying usually works", CANARY, "class_uid"):
        assert unsupported not in response.text
        assert unsupported not in saved[-1]["content"]
    assert CANARY not in json.dumps(logs)
    assert any(event["event"] == "copilot.input_contract_rejected" for event in logs)


@pytest.mark.asyncio
async def test_old_failure_text_does_not_poison_the_next_question(monkeypatch):
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://gateway.test/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "test-gateway-key")
    monkeypatch.setattr(contract_rules, "_ENFORCED", True)
    sent = []

    async def handle(request):
        sent.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "created": 1,
                "model": "aisoc-copilot",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "A new reply."}, "finish_reason": "stop"}],
            },
        )

    make_model = factory.make_chat_model
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        monkeypatch.setattr(factory, "make_chat_model", lambda *a, **kw: make_model(*a, http_async_client=client, **kw))
        text, source, reason = await copilot._get_openai_reply(
            {
                "messages": [
                    {"role": "user", "content": "Investigate this alert."},
                    {
                        "role": "assistant",
                        "source": "template",
                        "content": f'Previous call failed: {{"class_uid": 2001, "title": "{CANARY}"}}',
                    },
                    {"role": "assistant", "source": "llm", "content": "A prior model answer."},
                ]
            },
            "What can I ask next?",
        )

    assert (text, source, reason) == ("A new reply.", "llm", None)
    assert len(sent) == 1
    contents = [message["content"] for message in sent[0]["messages"]]
    assert "Investigate this alert." in contents
    assert "A prior model answer." in contents
    assert "What can I ask next?" in contents
    assert CANARY not in json.dumps(sent)


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize("legacy", [False, True])
async def test_rejected_question_is_not_replayed_but_stays_in_transcript(monkeypatch, stream, legacy):
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://gateway.test/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "test-gateway-key")
    monkeypatch.setattr(contract_rules, "_ENFORCED", True)
    monkeypatch.setattr(contract_rules, "_MAX_MESSAGE_CHARS", 2500)
    rejected = "too long " * 300
    saved = [
        {"role": "user", "content": "A valid prior question."},
        {"role": "assistant", "content": "A valid prior answer.", "source": "llm"},
    ]
    calls = []

    async def handle(request):
        calls.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "created": 1,
                "model": "aisoc-copilot",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "A fresh answer."}, "finish_reason": "stop"}],
            },
        )

    async def append(**kwargs):
        saved.extend(kwargs["new_messages"])
        return conversation_store.Conversation("conversation-1", "test", saved, datetime.now(UTC).isoformat())

    async def get(**kwargs):
        return conversation_store.Conversation("conversation-1", "test", list(saved), datetime.now(UTC).isoformat())

    monkeypatch.setattr(conversation_store, "get_conversation", get)
    monkeypatch.setattr(conversation_store, "append_messages", append)
    make_model = factory.make_chat_model
    app = FastAPI()
    app.include_router(copilot.router)
    route = "/api/v1/copilot/chat" + ("/stream" if stream else "")
    headers = {"Authorization": "Bearer " + _token()}
    async with (
        httpx.AsyncClient(transport=httpx.MockTransport(handle)) as provider,
        httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://console.test") as browser,
    ):
        monkeypatch.setattr(factory, "make_chat_model", lambda *a, **kw: make_model(*a, http_async_client=provider, **kw))
        if legacy:
            # Pre-#2061 versions stored the generic fallback without a reason
            # field, even if the contract rejected a user question.
            error = contract_rules.LLMContractViolation("message exceeds size cap", role="user")
            saved.extend(
                [
                    {"role": "user", "content": rejected},
                    {
                        "role": "assistant",
                        "source": "template",
                        "content": copilot._fallback_reply(copilot.CALL_FAILED, model="aisoc-copilot", detail=str(error)),
                    },
                ]
            )
        else:
            first = await browser.post(route, headers=headers, json={"conversationId": "conversation-1", "message": rejected})
            first_payload = json.loads(first.text.splitlines()[0])
            assert first.status_code == 200
            assert first_payload["template_reason"] == "input_contract_rejected"
            assert not calls
            assert saved[-2]["content"] == rejected

        second = await browser.post(route, headers=headers, json={"conversationId": "conversation-1", "message": "A valid follow-up."})
    assert second.status_code == 200
    assert json.loads(second.text.splitlines()[0])["source"] == "llm"
    assert len(calls) == 1
    assert saved[-4]["content"] == rejected
    assert saved[-3].get("template_reason") == (None if legacy else "input_contract_rejected")
    assert [m["content"] for m in calls[0]["messages"] if m["role"] != "system"] == [
        "A valid prior question.",
        "A valid prior answer.",
        "A valid follow-up.",
    ]


@pytest.mark.parametrize("legacy", [False, True])
def test_history_preserves_other_failures_and_excludes_only_rejected_turns(legacy):
    rejected_reply = {
        "role": "assistant",
        "source": "template",
        "content": copilot._fallback_reply(copilot.INPUT_REJECTED),
    }
    if not legacy:
        rejected_reply["template_reason"] = copilot.INPUT_REJECTED
    messages = [
        {"role": "user", "content": "A normal question that timed out."},
        {"role": "assistant", "source": "template", "template_reason": copilot.CALL_FAILED, "content": "Timed out."},
        {"role": "user", "content": "A rejected question."},
        rejected_reply,
        {"role": "user", "content": "A valid new question."},
        {"role": "assistant", "source": "llm", "content": "An accepted answer."},
    ]

    assert copilot._model_history({"messages": messages}) == [messages[0], messages[4], messages[5]]


def test_generic_legacy_rejection_of_other_history_does_not_drop_valid_user_turn(monkeypatch):
    monkeypatch.setattr(contract_rules, "_ENFORCED", True)
    error = contract_rules.LLMContractViolation("prior evidence failed contract", role="tool")
    question = {"role": "user", "content": "A valid question."}
    reply = {
        "role": "assistant",
        "source": "template",
        "content": copilot._fallback_reply(copilot.CALL_FAILED, model="aisoc-copilot", detail=str(error)),
    }

    assert copilot._model_history({"messages": [question, reply]}) == [question]
