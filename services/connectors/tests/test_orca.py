"""Tests for the Orca Security connector."""

from __future__ import annotations

import httpx
import pytest
import respx
from app.connectors.orca import OrcaConnector


def test_schema():
    schema = OrcaConnector.schema()
    assert schema.connector_id == "orca"
    assert schema.connector_name == "Orca Security"
    assert schema.category == "cloud"
    field_names = {f.name for f in schema.fields}
    assert {"api_token", "api_url"}.issubset(field_names)
    api_token_field = next(f for f in schema.fields if f.name == "api_token")
    assert api_token_field.type == "secret"
    api_url_field = next(f for f in schema.fields if f.name == "api_url")
    assert api_url_field.required is False
    assert api_url_field.default == "https://api.orcasecurity.io"


def test_capabilities():
    from app.connectors.base import Capability

    caps = OrcaConnector.capabilities()
    assert Capability.PULL_ALERTS in caps


def test_normalize_severity_hazardous_is_critical():
    """Orca's ``hazardous`` tier (also known as ``imminent_compromise``)
    represents active exploitation and maps to AiSOC's P1 ``critical`` tier
    so it lands in the 15-minute MTTD lane."""
    conn = OrcaConnector(api_token="t")
    raw = {
        "alert_id": "alert-1",
        "description": "Public S3 bucket exposed",
        "state": {"severity": "hazardous"},
        "asset": {
            "name": "my-bucket",
            "vendor": "aws",
            "region": "us-east-1",
            "vendor_id": "arn:aws:s3:::my-bucket",
        },
        "rule_name": "Bucket public",
    }
    norm = conn.normalize(raw)
    assert norm["source"] == "orca"
    assert norm["category"] == "cloud"
    assert norm["external_id"] == "alert-1"
    assert norm["severity"] == "critical"
    assert norm["hostname"] == "my-bucket"
    assert norm["cloud_platform"] == "aws"
    assert norm["cloud_region"] == "us-east-1"
    assert norm["raw_event"] is raw


def test_normalize_severity_critical_preserves_critical():
    # Orca's ``critical`` tier mirrors directly into AiSOC's ``critical`` —
    # never silently downgrade a P1 finding.
    conn = OrcaConnector(api_token="t")
    raw = {"alert_id": "c1", "state": {"severity": "critical"}}
    assert conn.normalize(raw)["severity"] == "critical"


def test_normalize_severity_informational():
    conn = OrcaConnector(api_token="t")
    raw = {"alert_id": "i1", "state": {"severity": "informational"}}
    assert conn.normalize(raw)["severity"] == "info"


def test_normalize_severity_unknown_defaults_medium():
    conn = OrcaConnector(api_token="t")
    raw = {"alert_id": "u1", "state": {"severity": "weird"}}
    assert conn.normalize(raw)["severity"] == "medium"


def test_normalize_severity_from_top_level():
    """If state.severity is missing, fall back to top-level severity."""
    conn = OrcaConnector(api_token="t")
    raw = {"alert_id": "t1", "severity": "low"}
    assert conn.normalize(raw)["severity"] == "low"


def test_normalize_handles_missing_asset():
    conn = OrcaConnector(api_token="t")
    raw = {"alert_id": "n1", "state": {"severity": "medium"}}
    norm = conn.normalize(raw)
    assert norm["hostname"] is None
    assert norm["cloud_platform"] is None
    assert norm["severity"] == "medium"


def test_normalize_uses_recommendation_for_description():
    conn = OrcaConnector(api_token="t")
    raw = {
        "alert_id": "d1",
        "description": "title",
        "recommendation": "remediation steps",
    }
    norm = conn.normalize(raw)
    assert norm["title"] == "title"
    assert norm["description"] == "remediation steps"


def test_normalize_falls_back_to_id():
    """Some Orca payloads use ``id`` rather than ``alert_id``."""
    conn = OrcaConnector(api_token="t")
    raw = {"id": "fallback-id", "state": {"severity": "high"}}
    assert conn.normalize(raw)["external_id"] == "fallback-id"


@respx.mock
@pytest.mark.asyncio
async def test_test_connection_success():
    respx.get("https://api.orcasecurity.io/api/user/session").mock(return_value=httpx.Response(200, json={"user": "ok"}))
    conn = OrcaConnector(api_token="t")
    result = await conn.test_connection()
    assert result["success"] is True
    assert result["connector"] == "orca"


@respx.mock
@pytest.mark.asyncio
async def test_test_connection_unauthorized():
    respx.get("https://api.orcasecurity.io/api/user/session").mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))
    conn = OrcaConnector(api_token="bad")
    result = await conn.test_connection()
    assert result["success"] is False
    assert "401" in result["error"]


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_data_envelope():
    """Orca tenants on the standard envelope return ``{"data": [...]}.``"""
    respx.get("https://api.orcasecurity.io/api/alerts").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "alert_id": "a1",
                        "description": "Misconfig",
                        "state": {"severity": "critical"},
                        "asset": {"name": "host-1", "vendor": "aws"},
                    },
                    {
                        "alert_id": "a2",
                        "description": "Vuln",
                        "state": {"severity": "medium"},
                    },
                ]
            },
        )
    )
    conn = OrcaConnector(api_token="t")
    alerts = await conn.fetch_alerts(since_seconds=300)
    assert len(alerts) == 2
    assert alerts[0]["external_id"] == "a1"
    # Orca's ``critical`` flows straight through to AiSOC's ``critical`` —
    # no collapse to ``high``.
    assert alerts[0]["severity"] == "critical"
    assert alerts[1]["severity"] == "medium"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_results_envelope():
    """Some Orca versions ship results in ``{"results": [...]}``."""
    respx.get("https://api.orcasecurity.io/api/alerts").mock(
        return_value=httpx.Response(
            200,
            json={
                "results": [
                    {
                        "alert_id": "r1",
                        "state": {"severity": "high"},
                    }
                ]
            },
        )
    )
    conn = OrcaConnector(api_token="t")
    alerts = await conn.fetch_alerts()
    assert len(alerts) == 1
    assert alerts[0]["external_id"] == "r1"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_bare_list():
    """Bare-list fallback for older endpoints."""
    respx.get("https://api.orcasecurity.io/api/alerts").mock(
        return_value=httpx.Response(
            200,
            json=[{"alert_id": "b1", "state": {"severity": "low"}}],
        )
    )
    conn = OrcaConnector(api_token="t")
    alerts = await conn.fetch_alerts()
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "low"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_handles_error():
    respx.get("https://api.orcasecurity.io/api/alerts").mock(return_value=httpx.Response(500, text="boom"))
    conn = OrcaConnector(api_token="t")
    alerts = await conn.fetch_alerts()
    assert alerts == []


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_passes_status_open():
    """We only ever pull open alerts to keep volume sane."""
    route = respx.get("https://api.orcasecurity.io/api/alerts").mock(return_value=httpx.Response(200, json={"data": []}))
    conn = OrcaConnector(api_token="t")
    await conn.fetch_alerts()
    assert route.called
    call_url = str(route.calls[0].request.url)
    assert "status=open" in call_url
    assert "start_at_gte=" in call_url


def test_custom_api_url_strips_trailing_slash():
    conn = OrcaConnector(api_token="t", api_url="https://api.eu.orcasecurity.io/")
    assert conn._api_url == "https://api.eu.orcasecurity.io"
