"""Tests for the PagerDuty connector (T4.2)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.pagerduty import PagerDutyConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "pagerduty" / "sample_event.json"
_BASE = "https://api.pagerduty.com"
_KEY = "pd_api_key_fakefakefakefakefakefakefa"  # noqa: S105 — fake


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = PagerDutyConnector.schema()
    assert schema.connector_id == "pagerduty"
    assert schema.category == "saas"
    names = {f.name for f in schema.fields}
    assert "api_key" in names
    secret = next(f for f in schema.fields if f.name == "api_key")
    assert secret.type == "secret"
    assert Capability.PULL_ALERTS in PagerDutyConnector.capabilities()
    assert Capability.PULL_AUDIT in PagerDutyConnector.capabilities()


def test_registry_contains_pagerduty():
    assert "pagerduty" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["pagerduty"] is PagerDutyConnector


def test_normalize_incident_p1_triggered_high(fixture):
    ev = dict(fixture["incidents"][0], _aisoc_stream="incident")
    out = PagerDutyConnector(_KEY, subdomain="acme").normalize(ev)
    # P1 priority maps to high via the wave-1 priority table.
    assert out["severity"] == "high"
    assert out["source"] == "pagerduty"
    assert out["external_id"] == "pagerduty-incident-PT4KHLK"
    assert out["event_type"] == "pagerduty.incident.triggered"


def test_normalize_incident_low_urgency_low(fixture):
    ev = dict(fixture["incidents"][1], _aisoc_stream="incident")
    out = PagerDutyConnector(_KEY).normalize(ev)
    # P4 priority → low.
    assert out["severity"] == "low"


def test_normalize_incident_resolved_collapses_info(fixture):
    ev = dict(fixture["incidents"][2], _aisoc_stream="incident")
    out = PagerDutyConnector(_KEY).normalize(ev)
    # Resolved incidents collapse to info regardless of urgency/priority.
    assert out["severity"] == "info"
    assert out["event_type"] == "pagerduty.incident.resolved"


def test_normalize_audit_api_key_create_high(fixture):
    ev = dict(fixture["records"][0], _aisoc_stream="audit_record")
    out = PagerDutyConnector(_KEY).normalize(ev)
    assert out["severity"] == "high"
    assert out["src_ip"] == "10.0.0.10"
    assert out["event_type"] == "pagerduty.api_key.create"


def test_normalize_audit_role_changed_high(fixture):
    ev = dict(fixture["records"][1], _aisoc_stream="audit_record")
    out = PagerDutyConnector(_KEY).normalize(ev)
    assert out["severity"] == "high"


def test_normalize_audit_routine_info(fixture):
    ev = dict(fixture["records"][2], _aisoc_stream="audit_record")
    out = PagerDutyConnector(_KEY).normalize(ev)
    assert out["severity"] == "info"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_pagination(fixture):
    inc_calls = 0

    def inc_handler(request: httpx.Request) -> httpx.Response:
        nonlocal inc_calls
        inc_calls += 1
        if inc_calls == 1:
            return httpx.Response(200, json={"incidents": fixture["incidents"], "more": True})
        return httpx.Response(200, json={"incidents": [], "more": False})

    respx.get(f"{_BASE}/incidents").mock(side_effect=inc_handler)

    audit_calls = 0

    def audit_handler(request: httpx.Request) -> httpx.Response:
        nonlocal audit_calls
        audit_calls += 1
        if audit_calls == 1:
            return httpx.Response(200, json={"records": fixture["records"], "next_cursor": "cur2"})
        return httpx.Response(200, json={"records": [], "next_cursor": None})

    respx.get(f"{_BASE}/audit/records").mock(side_effect=audit_handler)

    connector = PagerDutyConnector(_KEY)
    events = await connector.fetch_alerts(since_seconds=10**9)

    # Both pagination styles ran.
    assert inc_calls == 2  # offset+more terminated after empty page
    assert audit_calls == 2  # cursor terminated after empty page
    assert len(events) == len(fixture["incidents"]) + len(fixture["records"])


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_user_key():
    respx.get(f"{_BASE}/users/me").mock(
        return_value=httpx.Response(200, json={"user": {"email": "owner@example.com"}}),
    )
    out = await PagerDutyConnector(_KEY).test_connection()
    assert out["success"] is True
    assert out["auth_type"] == "user_key"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_general_access_key_fallback():
    respx.get(f"{_BASE}/users/me").mock(return_value=httpx.Response(401, text="not a user key"))
    respx.get(f"{_BASE}/incidents").mock(return_value=httpx.Response(200, json={"incidents": []}))
    out = await PagerDutyConnector(_KEY).test_connection()
    assert out["success"] is True
    assert out["auth_type"] == "general_access_key"
