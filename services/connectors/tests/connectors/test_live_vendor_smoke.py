"""Phase D3 — live-vendor mock-server smoke conformance.

The contract test (`test_conformance.py`) proves each connector *declares* the
async runtime methods. This smoke goes further: it stands up a mock HTTP server
(respx) returning realistic vendor payloads and drives each connector's real
`test_connection()` + `fetch_alerts()` HTTP path end-to-end, asserting a
successful probe and that pulled events normalize to a valid five-tier severity.
It exercises the httpx client, pagination, and normalize together — the failure
mode a bare contract test misses (e.g. a wrong endpoint path or a normalize that
KeyErrors on the real response shape).

Focus is the Phase D1/D2 connectors (the newest, least battle-tested); the
matrix ensures each is registered + conformant.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.connectors.devo import DevoConnector
from app.connectors.exabeam import ExabeamConnector
from app.connectors.llm_usage import LlmUsageConnector
from app.connectors.netskope import NetskopeConnector
from app.connectors.qradar import QRadarConnector
from app.connectors.securonix import SecuronixConnector
from app.connectors.syslog_cef import SyslogCefConnector
from app.connectors.windows_event import WindowsEventConnector
from app.connectors.zeek_suricata import ZeekSuricataConnector

pytestmark = pytest.mark.asyncio

_LADDER = {"info", "low", "medium", "high", "critical"}


def _assert_events(events: list[dict], connector_id: str) -> None:
    assert events, f"{connector_id}: fetch_alerts returned no events from mock server"
    for e in events:
        assert e.get("source") == connector_id
        assert e.get("severity") in _LADDER, f"{connector_id}: bad severity {e.get('severity')!r}"


@respx.mock
async def test_qradar_smoke():
    respx.get(url__regex=r"https://q/api/siem/offenses.*").mock(
        return_value=httpx.Response(200, json=[{"id": 7, "magnitude": 9, "description": "Suspicious login", "status": "OPEN"}])
    )
    c = QRadarConnector(console_url="https://q", sec_token="t")
    assert (await c.test_connection())["success"] is True
    _assert_events(await c.fetch_alerts(300), "qradar")


@respx.mock
async def test_exabeam_smoke():
    respx.get("https://e/uba/api/ping").respond(200, json={"ok": True})
    respx.get(url__regex=r"https://e/uba/api/users/sequences/notable.*").respond(
        200, json={"sessions": [{"username": "alice", "riskScore": 120, "sessionId": "s1", "numOfReasons": 4}]}
    )
    c = ExabeamConnector(base_url="https://e", api_key="k", api_secret="s")
    assert (await c.test_connection())["success"] is True
    _assert_events(await c.fetch_alerts(300), "exabeam")


@respx.mock
async def test_securonix_smoke():
    payload = {"result": {"data": {"incidentItems": [{"incidentId": "1", "priority": "High", "entity": "bob", "entityType": "Users"}]}}}
    respx.get(url__regex=r"https://s/ws/incident/get.*").respond(200, json=payload)
    c = SecuronixConnector(tenant_url="https://s", api_token="t")
    assert (await c.test_connection())["success"] is True
    _assert_events(await c.fetch_alerts(300), "securonix")


@respx.mock
async def test_devo_smoke():
    respx.get(url__regex=r"https://d/alerts/v1/alerts.*").respond(
        200, json={"object": [{"alertId": "a1", "severity": 4, "summary": "brute force", "context": {"srcIp": "1.2.3.4"}}]}
    )
    c = DevoConnector(api_url="https://d/alerts", api_token="t")
    assert (await c.test_connection())["success"] is True
    _assert_events(await c.fetch_alerts(300), "devo")


@respx.mock
async def test_netskope_smoke():
    respx.get(url__regex=r"https://n/api/v2/events/data/alert.*").respond(
        200, json={"result": [{"alert_type": "malware", "severity": "low", "user": "alice", "srcip": "10.0.0.1", "_id": "x"}]}
    )
    c = NetskopeConnector(tenant_url="https://n", api_token="t")
    assert (await c.test_connection())["success"] is True
    events = await c.fetch_alerts(300)
    _assert_events(events, "netskope")
    assert events[0]["severity"] == "high"  # malware floored


@respx.mock
async def test_windows_event_smoke():
    respx.get(url__regex=r"https://w/spool.*").respond(
        200, json={"events": [{"EventID": 1102, "Channel": "Security", "Computer": "DC01", "EventData": {}}]}
    )
    c = WindowsEventConnector(collector_url="https://w/spool", api_token="t")
    assert (await c.test_connection())["success"] is True
    _assert_events(await c.fetch_alerts(300), "windows_event")


@respx.mock
async def test_zeek_suricata_smoke():
    respx.get(url__regex=r"https://x/spool.*").respond(
        200, json={"events": [{"flow_id": 1, "src_ip": "1.1.1.1", "dest_ip": "2.2.2.2", "alert": {"severity": 1, "signature": "ET"}}]}
    )
    c = ZeekSuricataConnector(engine="suricata", spool_url="https://x/spool", api_token="t")
    assert (await c.test_connection())["success"] is True
    _assert_events(await c.fetch_alerts(300), "zeek_suricata")


@respx.mock
async def test_syslog_cef_smoke():
    respx.get(url__regex=r"https://y/spool.*").respond(
        200, json={"messages": ["CEF:0|Fortinet|FortiGate|7.0|13|IPS|8|src=10.0.0.5 dst=8.8.8.8"]}
    )
    c = SyslogCefConnector(spool_url="https://y/spool", api_token="t")
    assert (await c.test_connection())["success"] is True
    _assert_events(await c.fetch_alerts(300), "syslog_cef")


@respx.mock
async def test_llm_usage_smoke():
    respx.get(url__regex=r"https://api.openai.com/v1/organization/audit_logs.*").respond(
        200, json={"data": [{"id": "l1", "type": "api_key.created", "actor": {"email": "a@corp.com"}}]}
    )
    c = LlmUsageConnector(provider="openai", api_key="k")
    assert (await c.test_connection())["success"] is True
    events = await c.fetch_alerts(300)
    _assert_events(events, "llm_usage")
    assert events[0]["event_type"] == "openai.api_key.created"
