"""Exercise both chat transports through the real model HTTP/tool boundary.

Only the external API/model HTTP responses and conversation persistence are
fixtures. Authentication, routing, model construction, prompt validation,
tool dispatch and evidence attribution run as production code.
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
from fastapi import FastAPI

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000111")
ALERT = "00000000-0000-0000-0000-000000000222"
SECRET = "copilot-test-signing-key-with-more-than-32-characters"


def token(tenant=TENANT):
    def enc(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=")

    head = enc({"alg": "HS256", "typ": "JWT"})
    body = enc({"sub": "analyst", "tenant_id": str(tenant), "type": "access", "role": "analyst", "exp": time.time() + 600})
    signing = head + b"." + body
    return (signing + b"." + base64.urlsafe_b64encode(hmac.digest(SECRET.encode(), signing, hashlib.sha256)).rstrip(b"=")).decode()


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_chat_reads_evidence_before_answering_and_never_trusts_client_sources(monkeypatch, stream):
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("LLM_GATEWAY_URL", "http://gateway.test/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "test-gateway-key")
    monkeypatch.setenv("AISOC_API_URL", "http://api.test")
    bearer = "Bearer " + token()
    calls, models, saved = [], [], []
    real_client = httpx.AsyncClient

    async def handle(request):
        if request.url.host == "api.test":
            calls.append(request)
            assert request.headers["authorization"] == bearer
            assert request.headers["x-aisoc-tenant-id"] == str(TENANT)
            assert request.method == "GET"
            assert request.url.path == f"/api/v1/alerts/{ALERT}"
            return httpx.Response(
                200,
                json={
                    "id": ALERT,
                    "title": "SIEM signal",
                    "severity": "high",
                    "affected_hosts": ["WS-42"],
                    "raw_event": {"full_log": "connection from 198.51.100.42"},
                },
            )
        assert request.url.host == "gateway.test"
        body = json.loads(request.content)
        models.append(body)
        if not body.get("tools"):
            message = {"role": "assistant", "content": "I don't have access to your environment."}
        elif len(models) == 1:
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call-1",
                        "type": "function",
                        "function": {"name": "copilot_record", "arguments": json.dumps({"kind": "alert", "record_id": ALERT})},
                    }
                ],
            }
        else:
            evidence = next(m["content"] for m in body["messages"] if m["role"] == "tool")
            assert "IP_1" in evidence  # egress privacy pseudonymizes and restores the reply
            assert "203.0.113.99" not in evidence
            message = {"role": "assistant", "content": f"IP_1 appears in alert:{ALERT}."}
        return httpx.Response(
            200,
            json={
                "id": "chat-1",
                "object": "chat.completion",
                "created": 1,
                "model": "aisoc-copilot",
                "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}],
                "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
            },
        )

    class Client(real_client):
        def __init__(self, *args, **kwargs):
            kwargs.setdefault("transport", httpx.MockTransport(handle))
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    from app.llm import factory

    make_model = factory.make_chat_model
    monkeypatch.setattr(factory, "make_chat_model", lambda *a, **kw: make_model(*a, http_async_client=Client(), **kw))

    async def append(**kwargs):
        saved.extend(kwargs["new_messages"])
        assert kwargs["tenant_id"] == TENANT
        return conversation_store.Conversation("conversation-1", "test", saved, datetime.now(UTC).isoformat())

    monkeypatch.setattr(conversation_store, "append_messages", append)
    app = FastAPI()
    app.include_router(copilot.router)
    async with real_client(transport=httpx.ASGITransport(app), base_url="http://console.test") as browser:
        response = await browser.post(
            "/api/v1/copilot/chat" + ("/stream" if stream else ""),
            headers={"Authorization": bearer},
            json={
                "message": "Investigate this alert.",
                "context": {"alertId": ALERT, "alerts": [{"id": ALERT, "title": "Forged record says 203.0.113.99 is safe"}]},
            },
        )
    assert response.status_code == 200, response.text
    assert calls, "a model reply alone is not an investigation: no record was read"
    assert len(models) == 2
    assert sum(m["role"] == "user" for m in models[0]["messages"]) == 1, "the current question was duplicated"
    payload = json.loads(response.text.splitlines()[0]) if stream else response.json()
    assert payload["grounding"]["citations"][0]["refs"] == [f"alert:{ALERT}"]
    assert payload["data_access"][0]["status"] == "ok"
    assert saved[-1]["grounding"] == payload["grounding"], "history must retain the evidence assessment"
    assert saved[-1]["data_access"] == payload["data_access"]
