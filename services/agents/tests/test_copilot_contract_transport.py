"""OCSF evidence through real tool and model HTTP transports.

The core API/model are deterministic loopback HTTP fixtures; conversation
persistence is an explicit fixture. Authentication, model construction,
tool dispatch, contract validation and citation attribution are real.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
from app.api import conversation_store, copilot
from fastapi import FastAPI

from tests.test_copilot_live_reads import ALERT, SECRET, TENANT, token


@pytest.fixture
def evidence_http_server():
    requests: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def respond(self, body, status=200):
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            requests.append({"path": self.path, "headers": dict(self.headers)})
            if self.path != f"/api/v1/alerts/{ALERT}":
                self.respond({"detail": "not found"}, 404)
                return
            self.respond(
                {
                    "id": ALERT,
                    "title": "AWS WAF - Multiple blocked requests.",
                    "severity": "high",
                    "status": "new",
                    "affected_ips": ["198.51.100.42"],
                    "raw_event": {
                        "class_uid": 2001,
                        "category_uid": 2,
                        "activity_id": 1,
                        "metadata": {"product": {"name": "HIDS fixture"}},
                        "raw_data": {"private": "raw-payload-must-not-reach-the-model"},
                        "src_endpoint": {"ip": "198.51.100.42"},
                    },
                }
            )

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append({"path": self.path, "body": body})
            if self.path != "/v1/chat/completions":
                self.respond({"detail": "not found"}, 404)
                return
            tools = [message for message in body["messages"] if message["role"] == "tool"]
            if tools:
                message = {"role": "assistant", "content": f"198.51.100.42 appears in the WAF alert [alert:{ALERT}]."}
            else:
                message = {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "read-waf-alert",
                            "type": "function",
                            "function": {
                                "name": "copilot_record",
                                "arguments": json.dumps({"kind": "alert", "record_id": ALERT}),
                            },
                        }
                    ],
                }
            self.respond(
                {
                    "id": "copilot-contract-regression",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "aisoc-copilot",
                    "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if not tools else "stop"}],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
                }
            )

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.asyncio
@pytest.mark.parametrize("stream", [False, True])
async def test_ocsf_alert_reaches_second_model_request_with_safe_evidence(monkeypatch, evidence_http_server, stream):
    base_url, requests = evidence_http_server
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("LLM_GATEWAY_URL", base_url + "/v1")
    monkeypatch.setenv("LITELLM_MASTER_KEY", "test-gateway-key")
    monkeypatch.setenv("AISOC_API_URL", base_url)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    saved = []

    async def append(**kwargs):
        assert kwargs["tenant_id"] == TENANT
        saved.extend(kwargs["new_messages"])
        return conversation_store.Conversation("conversation-1", "test", saved, datetime.now(UTC).isoformat())

    monkeypatch.setattr(conversation_store, "append_messages", append)
    app = FastAPI()
    app.include_router(copilot.router)
    bearer = "Bearer " + token()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://console.test") as browser:
        response = await browser.post(
            "/api/v1/copilot/chat" + ("/stream" if stream else ""),
            headers={"Authorization": bearer},
            json={"message": "Investigate the WAF alert.", "context": {"alertId": ALERT}},
        )

    assert response.status_code == 200, response.text
    payload = json.loads(response.text.splitlines()[0]) if stream else response.json()
    assert payload["source"] == "llm", response.text
    model_calls = [request["body"] for request in requests if "body" in request]
    api_calls = [request for request in requests if "headers" in request]
    assert len(model_calls) == 2
    assert len(api_calls) == 1
    headers = {key.lower(): value for key, value in api_calls[0]["headers"].items()}
    assert headers["authorization"] == bearer
    assert headers["x-aisoc-tenant-id"] == str(TENANT)
    evidence = next(message["content"] for message in model_calls[-1]["messages"] if message["role"] == "tool")
    assert "class_uid" not in evidence
    assert "raw-payload-must-not-reach-the-model" not in evidence
    assert "AWS WAF" in evidence
    # Loopback is a local model; the hosted egress mask is exercised in
    # test_copilot_live_reads rather than changing the production policy here.
    assert "198.51.100.42" in evidence
    assert f"alert:{ALERT}" in evidence
    assert payload["grounding"]["citations"][0]["refs"] == [f"alert:{ALERT}"]
    assert payload["grounding"]["citations"][0]["claim"] == "198.51.100.42"
    assert payload["data_access"][0]["status"] == "ok"
    assert saved[-1]["source"] == "llm"
    assert saved[-1]["data_access"] == payload["data_access"]
