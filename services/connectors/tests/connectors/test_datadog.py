"""Tests for the Datadog (Logs + APM) connector (T4.13).

Brings the wave-2 ``datadog`` connector to wave-1 test parity: schema +
registry wiring, site/mode validation, both normalizer branches (log
status->severity and event alert_type/priority->severity), the logs
cursor pagination and the single-shot events fetch, and
``test_connection``. Network mocked with respx.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.datadog import DatadogConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "datadog" / "sample_event.json"
_BASE = "https://api.datadoghq.com"


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


def _logs_connector() -> DatadogConnector:
    return DatadogConnector(site="us1", mode="logs", api_key="k", application_key="a")


def test_schema_valid():
    schema = DatadogConnector.schema()
    assert schema.connector_id == "datadog"
    assert schema.category == "siem"
    names = {f.name for f in schema.fields}
    assert {"site", "mode", "query", "api_key", "application_key"} <= names
    assert Capability.PULL_LOGS in DatadogConnector.capabilities()


def test_registry_contains_datadog():
    assert "datadog" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["datadog"] is DatadogConnector


def test_invalid_site_rejected():
    with pytest.raises(ValueError):
        DatadogConnector(site="mars1", mode="logs", api_key="k", application_key="a")


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        DatadogConnector(site="us1", mode="bogus", api_key="k", application_key="a")


def test_normalize_log_critical_to_high(fixture):
    out = _logs_connector().normalize(fixture["logs"][0])
    assert out["severity"] == "high"
    assert out["stream"] == "logs"
    assert out["host"] == "web-1"
    assert out["service"] == "api"


def test_normalize_log_error_to_medium(fixture):
    assert _logs_connector().normalize(fixture["logs"][1])["severity"] == "medium"


def test_normalize_log_warn_via_level_alias_to_low(fixture):
    assert _logs_connector().normalize(fixture["logs"][2])["severity"] == "low"


def test_normalize_log_info_to_info(fixture):
    assert _logs_connector().normalize(fixture["logs"][3])["severity"] == "info"


def test_normalize_event_error_to_high(fixture):
    out = _logs_connector().normalize({"_kind": "event", **fixture["events"][0]})
    assert out["severity"] == "high"
    assert out["stream"] == "events"
    assert out["external_id"] == "111"


def test_normalize_event_warning_to_medium(fixture):
    out = _logs_connector().normalize({"_kind": "event", **fixture["events"][1]})
    assert out["severity"] == "medium"


def test_normalize_event_info_priority_low_to_low(fixture):
    out = _logs_connector().normalize({"_kind": "event", **fixture["events"][2]})
    assert out["severity"] == "low"


def test_normalize_event_info_to_info(fixture):
    out = _logs_connector().normalize({"_kind": "event", **fixture["events"][3]})
    assert out["severity"] == "info"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_logs_uses_cursor_pagination(fixture, monkeypatch):
    monkeypatch.setattr("app.connectors.datadog._LOGS_PER_PAGE", 2)
    c = _logs_connector()
    page1 = {"data": fixture["logs"][:2], "meta": {"page": {"after": "cur1"}}}
    page2 = {"data": fixture["logs"][2:3]}  # short → stop
    route = respx.post(f"{_BASE}/api/v2/logs/events/search")
    route.side_effect = [
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ]
    out = await c.fetch_alerts(since_seconds=300)
    assert len(out) == 3
    assert all(e["stream"] == "logs" for e in out)


@pytest.mark.asyncio
@respx.mock
async def test_fetch_events_single_shot(fixture):
    c = DatadogConnector(site="us1", mode="events", api_key="k", application_key="a")
    respx.get(f"{_BASE}/api/v1/events").respond(200, json={"events": fixture["events"][:2]})
    out = await c.fetch_alerts(since_seconds=300)
    assert len(out) == 2
    assert all(e["stream"] == "events" for e in out)


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    c = _logs_connector()
    respx.get(f"{_BASE}/api/v1/validate").respond(200, json={"valid": True})
    res = await c.test_connection()
    assert res["success"] is True
    assert res["site"] == "us1"
    assert res["mode"] == "logs"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_failure():
    c = _logs_connector()
    respx.get(f"{_BASE}/api/v1/validate").respond(403, json={"errors": ["forbidden"]})
    res = await c.test_connection()
    assert res["success"] is False
    assert "403" in res["error"]
