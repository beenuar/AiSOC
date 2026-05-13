"""Tests for the Tines connector (T4.2)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.tines import TinesConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "tines" / "sample_event.json"
_BASE = "https://acme.tines.com"
_TOKEN = "tines_pat_fakeFakeFakeFakeFakeFakeFakeFake"


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_schema_valid():
    schema = TinesConnector.schema()
    assert schema.connector_id == "tines"
    assert schema.category == "saas"
    field_names = {f.name for f in schema.fields}
    assert {"base_url", "api_token"} <= field_names
    secret = next(f for f in schema.fields if f.name == "api_token")
    assert secret.type == "secret"
    # Capabilities must include at least PULL_AUDIT for an audit-source.
    assert Capability.PULL_AUDIT in TinesConnector.capabilities()


def test_registry_contains_tines():
    assert "tines" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["tines"] is TinesConnector


# ---------------------------------------------------------------------------
# normalize() roundtrip
# ---------------------------------------------------------------------------


def test_normalize_roundtrip_audit_high_risk(fixture):
    audit = fixture["audit_logs"][0]  # credential.created
    audit["_aisoc_stream"] = "audit_log"
    connector = TinesConnector(_BASE, _TOKEN)
    out = connector.normalize(audit)
    assert out["source"] == "tines"
    assert out["severity"] == "high"
    assert out["actor"] == "alice@example.com"
    assert out["actor_email"] == "alice@example.com"
    assert out["src_ip"] == "10.0.0.1"
    assert out["event_type"] == "tines.credential.created"
    assert out["external_id"] == "tines-audit-1001"


def test_normalize_roundtrip_audit_routine(fixture):
    audit = fixture["audit_logs"][1]  # story.updated → info
    audit["_aisoc_stream"] = "audit_log"
    connector = TinesConnector(_BASE, _TOKEN)
    out = connector.normalize(audit)
    assert out["severity"] == "info"


def test_normalize_roundtrip_audit_delete_medium(fixture):
    audit = fixture["audit_logs"][2]  # story.deleted is in HIGH_RISK list
    audit["_aisoc_stream"] = "audit_log"
    connector = TinesConnector(_BASE, _TOKEN)
    out = connector.normalize(audit)
    # story.deleted is explicitly high-risk in the connector
    assert out["severity"] == "high"


def test_normalize_roundtrip_case_open_critical(fixture):
    case = fixture["cases"][0]  # critical, open → high (per wave-1 mapping)
    case["_aisoc_stream"] = "case"
    connector = TinesConnector(_BASE, _TOKEN)
    out = connector.normalize(case)
    assert out["severity"] == "high"
    assert out["source"] == "tines"
    assert out["external_id"] == "tines-case-5001"
    assert out["actor_email"] == "soc-on-call@example.com"
    assert out["event_type"] == "tines.case.open"


def test_normalize_roundtrip_case_closed_resolved_is_info(fixture):
    case = fixture["cases"][1]  # high, closed+resolved → collapses to info
    case["_aisoc_stream"] = "case"
    connector = TinesConnector(_BASE, _TOKEN)
    out = connector.normalize(case)
    assert out["severity"] == "info"


def test_normalize_severity_collapse_warn_to_low():
    connector = TinesConnector(_BASE, _TOKEN)
    case = {"_aisoc_stream": "case", "id": 1, "status": "open", "record_severity": "warn"}
    assert connector.normalize(case)["severity"] == "low"


def test_normalize_severity_collapse_error_to_high():
    connector = TinesConnector(_BASE, _TOKEN)
    case = {"_aisoc_stream": "case", "id": 1, "status": "open", "record_severity": "error"}
    assert connector.normalize(case)["severity"] == "high"


# ---------------------------------------------------------------------------
# fetch_alerts() pagination
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_pagination(fixture):
    # Audit-log endpoint returns one page of events with a next_page cursor,
    # then an empty page; cases endpoint returns one page. Together this
    # exercises:
    #   (a) the pagination loop following next_page until None
    #   (b) the empty-page termination branch
    #   (c) the case-vs-audit stream dispatch in normalize()
    page1_calls = 0
    page2_calls = 0

    def audit_handler(request: httpx.Request) -> httpx.Response:
        nonlocal page1_calls, page2_calls
        page = int(request.url.params.get("page") or 1)
        if page == 1:
            page1_calls += 1
            return httpx.Response(
                200,
                json={
                    "audit_logs": fixture["audit_logs"],
                    "meta": {"current_page": 1, "next_page": 2},
                },
            )
        page2_calls += 1
        return httpx.Response(200, json={"audit_logs": [], "meta": {"current_page": 2, "next_page": None}})

    respx.get(f"{_BASE}/api/v1/audit_logs").mock(side_effect=audit_handler)

    case_calls = 0

    def case_handler(request: httpx.Request) -> httpx.Response:
        nonlocal case_calls
        case_calls += 1
        return httpx.Response(200, json={"cases": fixture["cases"], "meta": {"next_page": None}})

    respx.get(f"{_BASE}/api/v1/cases").mock(side_effect=case_handler)

    connector = TinesConnector(_BASE, _TOKEN)
    # Fetch with a huge window so timestamps in the fixture (year 2099) pass.
    events = await connector.fetch_alerts(since_seconds=10**9)

    # Pagination actually ran: page 1 returned items, page 2 returned [] and
    # terminated.
    assert page1_calls == 1
    assert page2_calls == 1
    # Cases endpoint was hit exactly once (one page, no next).
    assert case_calls == 1
    # All events flow through normalize() — first three are audit, last two
    # are cases.
    assert all(e["source"] == "tines" for e in events)
    audit_events = [e for e in events if e["external_id"].startswith("tines-audit-")]
    case_events = [e for e in events if e["external_id"].startswith("tines-case-")]
    assert len(audit_events) == 3
    assert len(case_events) == 2


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    respx.get(f"{_BASE}/api/v1/users/info").mock(return_value=httpx.Response(200, json={"email": "alice@example.com"}))
    connector = TinesConnector(_BASE, _TOKEN)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["user_email"] == "alice@example.com"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_unauthorised():
    respx.get(f"{_BASE}/api/v1/users/info").mock(return_value=httpx.Response(401, text="bad token"))
    connector = TinesConnector(_BASE, _TOKEN)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "401" in result["error"]
