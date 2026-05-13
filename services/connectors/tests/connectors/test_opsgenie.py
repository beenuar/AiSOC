"""Tests for the Opsgenie connector (T4.2)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.opsgenie import OpsgenieConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "opsgenie" / "sample_event.json"
_BASE = "https://api.opsgenie.com"
_EU_BASE = "https://api.eu.opsgenie.com"
_KEY = "00000000-0000-0000-0000-000000000000"


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = OpsgenieConnector.schema()
    assert schema.connector_id == "opsgenie"
    assert schema.category == "saas"
    names = {f.name for f in schema.fields}
    assert {"api_key", "region"} <= names
    secret = next(f for f in schema.fields if f.name == "api_key")
    assert secret.type == "secret"
    assert Capability.PULL_ALERTS in OpsgenieConnector.capabilities()


def test_registry_contains_opsgenie():
    assert "opsgenie" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["opsgenie"] is OpsgenieConnector


def test_eu_region_selects_eu_base():
    c = OpsgenieConnector(_KEY, region="eu")
    assert c._base == _EU_BASE  # noqa: SLF001 — intentional internal check


def test_normalize_alert_p1_to_high(fixture):
    ev = dict(fixture["data"][0], _aisoc_stream="alert")
    out = OpsgenieConnector(_KEY).normalize(ev)
    # P1 priority → high.
    assert out["severity"] == "high"
    assert out["source"] == "opsgenie"
    assert out["external_id"] == "opsgenie-alert-alert-001"
    assert out["event_type"] == "opsgenie.alert.open"


def test_normalize_alert_closed_collapses_info(fixture):
    ev = dict(fixture["data"][1], _aisoc_stream="alert")
    out = OpsgenieConnector(_KEY).normalize(ev)
    assert out["severity"] == "info"  # status=closed forces info


def test_normalize_alert_p5_to_info(fixture):
    ev = dict(fixture["data"][2], _aisoc_stream="alert")
    out = OpsgenieConnector(_KEY).normalize(ev)
    assert out["severity"] == "info"


def test_normalize_audit_api_key_created_high(fixture):
    ev = dict(fixture["audit_records"][0], _aisoc_stream="audit_log")
    out = OpsgenieConnector(_KEY).normalize(ev)
    assert out["severity"] == "high"
    assert out["src_ip"] == "10.0.0.1"
    assert out["actor_email"] == "owner@example.com"


def test_normalize_audit_policy_deleted_high(fixture):
    ev = dict(fixture["audit_records"][1], _aisoc_stream="audit_log")
    out = OpsgenieConnector(_KEY).normalize(ev)
    assert out["severity"] == "high"


def test_normalize_audit_routine_info(fixture):
    ev = dict(fixture["audit_records"][2], _aisoc_stream="audit_log")
    out = OpsgenieConnector(_KEY).normalize(ev)
    assert out["severity"] == "info"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_pagination(fixture):
    alerts_calls = 0

    def alert_handler(request: httpx.Request) -> httpx.Response:
        nonlocal alerts_calls
        alerts_calls += 1
        if alerts_calls == 1:
            return httpx.Response(
                200,
                json={"data": fixture["data"], "paging": {"next": f"{_BASE}/v2/alerts?offset=100"}},
            )
        return httpx.Response(200, json={"data": [], "paging": {}})

    # respx matches the bare path. Use a base-and-query route.
    respx.get(f"{_BASE}/v2/alerts").mock(side_effect=alert_handler)

    audit_calls = 0

    def audit_handler(request: httpx.Request) -> httpx.Response:
        nonlocal audit_calls
        audit_calls += 1
        return httpx.Response(200, json={"data": fixture["audit_records"], "paging": {}})

    respx.get(f"{_BASE}/v2/audit-logs").mock(side_effect=audit_handler)

    out = await OpsgenieConnector(_KEY).fetch_alerts(since_seconds=10**9)

    assert alerts_calls == 2  # one full + one empty
    assert audit_calls == 1
    assert all(e["source"] == "opsgenie" for e in out)
    alerts_out = [e for e in out if e["external_id"].startswith("opsgenie-alert-")]
    audits_out = [e for e in out if e["external_id"].startswith("opsgenie-audit-")]
    assert len(alerts_out) == len(fixture["data"])
    assert len(audits_out) == len(fixture["audit_records"])


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    respx.get(f"{_BASE}/v2/account").mock(
        return_value=httpx.Response(200, json={"data": {"name": "AcmeOrg", "plan": {"name": "Enterprise"}}}),
    )
    out = await OpsgenieConnector(_KEY).test_connection()
    assert out["success"] is True
    assert out["account"] == "AcmeOrg"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_unauthorised():
    respx.get(f"{_BASE}/v2/account").mock(return_value=httpx.Response(401, text="bad key"))
    out = await OpsgenieConnector(_KEY).test_connection()
    assert out["success"] is False
