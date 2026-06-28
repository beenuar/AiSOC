"""
Phase 3.3 — wire-shape tests for the alert ack + suppress methods
added to :class:`SplunkClient`, :class:`ElasticClient`, and
:class:`DefenderClient`.

We use respx to capture the request bodies and assert that each
client hits the right endpoint with the right payload. The
status-code integers, classification strings, and signal_ids list
shape are all vendor-side contracts — if any of them change
silently, this test catches it.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.clients.defender_client import DefenderClient
from app.clients.elastic_client import ElasticClient
from app.clients.splunk_client import SplunkClient

# ────────────────────────────────────────────────────────────────────
# Splunk ES
# ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_splunk_acknowledge_notable_event_posts_status_1() -> None:
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"status": "success"})

    respx.post("https://splunk.example.com:8089/services/notable_update").mock(side_effect=respond)

    client = SplunkClient(host="https://splunk.example.com:8089", token="T", verify_ssl=False)
    result = await client.acknowledge_notable_event(event_id="rule-abc", owner="alice", comment="On it")

    assert result["success"] is True
    assert result["event_id"] == "rule-abc"
    # Splunk ES uses integer status codes: 1 = "in progress", 5 = "closed".
    assert "status=1" in captured["body"]
    assert "ruleUIDs=rule-abc" in captured["body"]


@pytest.mark.asyncio
@respx.mock
async def test_splunk_suppress_notable_event_posts_status_5() -> None:
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"status": "success"})

    respx.post("https://splunk.example.com:8089/services/notable_update").mock(side_effect=respond)

    client = SplunkClient(host="https://splunk.example.com:8089", token="T", verify_ssl=False)
    result = await client.suppress_notable_event(event_id="rule-abc", comment="Closed")

    assert result["success"] is True
    assert "status=5" in captured["body"]


# ────────────────────────────────────────────────────────────────────
# Elastic Security
# ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_elastic_acknowledge_alert_posts_signal_ids() -> None:
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        captured["xsrf"] = request.headers.get("kbn-xsrf", "")
        return httpx.Response(200, json={"updated": 1})

    respx.post("https://kib.example.com:9243/api/detection_engine/signals/status").mock(side_effect=respond)

    client = ElasticClient(
        es_url="https://es.example.com:9243",
        api_key="ak",
        kibana_url="https://kib.example.com:9243",
    )
    result = await client.acknowledge_alert(signal_id="sig-1")
    assert result["signal_id"] == "sig-1"
    assert '"signal_ids":["sig-1"]' in captured["body"].replace(" ", "")
    assert '"status":"acknowledged"' in captured["body"].replace(" ", "")
    # Kibana requires kbn-xsrf on detection-engine writes.
    assert captured["xsrf"] == "true"


@pytest.mark.asyncio
@respx.mock
async def test_elastic_close_alert_posts_closed_status() -> None:
    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"updated": 1})

    respx.post("https://kib.example.com:9243/api/detection_engine/signals/status").mock(side_effect=respond)

    client = ElasticClient(es_url="https://es.example.com:9243", api_key="ak", kibana_url="https://kib.example.com:9243")
    result = await client.close_alert(signal_id="sig-2")
    assert result["signal_id"] == "sig-2"
    assert '"status":"closed"' in captured["body"].replace(" ", "")


# ────────────────────────────────────────────────────────────────────
# Microsoft Defender
# ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_defender_acknowledge_alert_patches_inprogress() -> None:
    respx.post("https://login.microsoftonline.com/tn/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok"})
    )

    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        captured["auth"] = request.headers.get("Authorization", "")
        return httpx.Response(200, json={"id": "A1", "status": "InProgress"})

    respx.patch("https://api.securitycenter.microsoft.com/api/alerts/A1").mock(side_effect=respond)

    client = DefenderClient(tenant_id="tn", client_id="cl", client_secret="cs")
    result = await client.acknowledge_alert(alert_id="A1", assigned_to="alice@example.com")

    assert result["alert_id"] == "A1"
    assert captured["auth"] == "Bearer tok"
    assert '"status":"InProgress"' in captured["body"].replace(" ", "")
    assert "alice@example.com" in captured["body"]


@pytest.mark.asyncio
@respx.mock
async def test_defender_suppress_alert_requires_classification() -> None:
    respx.post("https://login.microsoftonline.com/tn/oauth2/v2.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "tok"})
    )

    captured: dict[str, str] = {}

    def respond(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.read().decode()
        return httpx.Response(200, json={"id": "A1", "status": "Resolved"})

    respx.patch("https://api.securitycenter.microsoft.com/api/alerts/A1").mock(side_effect=respond)

    client = DefenderClient(tenant_id="tn", client_id="cl", client_secret="cs")
    result = await client.suppress_alert(alert_id="A1")

    assert result["classification"] == "FalsePositive"
    body = captured["body"].replace(" ", "")
    assert '"status":"Resolved"' in body
    # Classification is required by MDE when moving to Resolved.
    assert '"classification":"FalsePositive"' in body
    assert '"determination":"NotAvailable"' in body
