"""Tests for the Abnormal Security email-security connector (T4.5).

Brings the wave-2 ``abnormal_security`` connector to wave-1 test parity:
schema + registry wiring, the threatType->severity collapse (high attack
families, low graymail/spam, medium default), the case-severity override,
the two-endpoint (threats + cases) paginated fetch, and the
``test_connection`` paths. Network is mocked with :mod:`respx`.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.abnormal_security import AbnormalSecurityConnector
from app.connectors.base import Capability

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "abnormal_security" / "sample_event.json"
_BASE = "https://api.abnormalplatform.com"


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = AbnormalSecurityConnector.schema()
    assert schema.connector_id == "abnormal_security"
    assert schema.category == "saas"
    names = {f.name for f in schema.fields}
    assert {"base_url", "api_token"} <= names
    assert Capability.PULL_ALERTS in AbnormalSecurityConnector.capabilities()


def test_registry_contains_abnormal_security():
    assert "abnormal_security" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["abnormal_security"] is AbnormalSecurityConnector


def test_normalize_bec_to_high(fixture):
    c = AbnormalSecurityConnector(api_token="t")
    out = c.normalize(fixture["threats"][0])
    assert out["severity"] == "high"
    assert out["stream"] == "threat"
    assert out["external_id"] == "t-bec"
    assert out["actor_email"] == "ceo-spoof@evil.test"


def test_normalize_credential_phishing_via_attacktype_to_high(fixture):
    """``attackType`` is an accepted alias for ``threatType``; sender can
    arrive nested under ``sender.email``."""
    c = AbnormalSecurityConnector(api_token="t")
    out = c.normalize(fixture["threats"][1])
    assert out["severity"] == "high"
    assert out["actor_email"] == "phish@lookalike.test"


def test_normalize_spam_to_low(fixture):
    c = AbnormalSecurityConnector(api_token="t")
    assert c.normalize(fixture["threats"][2])["severity"] == "low"


def test_normalize_unknown_type_to_medium(fixture):
    """Abnormal only reports things it considers abnormal — unknown types
    floor at medium, never info."""
    c = AbnormalSecurityConnector(api_token="t")
    assert c.normalize(fixture["threats"][3])["severity"] == "medium"


def test_normalize_case_high_severity(fixture):
    c = AbnormalSecurityConnector(api_token="t")
    out = c.normalize(fixture["cases"][0])
    assert out["severity"] == "high"
    assert out["stream"] == "case"
    assert out["external_id"] == "c-ato"


def test_normalize_case_severity_overrides_low_type(fixture):
    """A low threatType (spam) still reports high when the case severity is
    high — the case rollup is the max of its constituents."""
    c = AbnormalSecurityConnector(api_token="t")
    assert c.normalize(fixture["cases"][1])["severity"] == "high"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_merges_threats_and_cases(fixture, monkeypatch):
    monkeypatch.setattr("app.connectors.abnormal_security._PER_PAGE", 2)
    c = AbnormalSecurityConnector(api_token="t")

    threats_p1 = {"threats": fixture["threats"][:2], "nextPageNumber": 2}
    threats_p2 = {"threats": fixture["threats"][2:3]}  # short → stop
    respx.get(f"{_BASE}/v1/threats").side_effect = [
        httpx.Response(200, json=threats_p1),
        httpx.Response(200, json=threats_p2),
    ]
    respx.get(f"{_BASE}/v1/cases").respond(200, json={"cases": fixture["cases"][:1]})

    out = await c.fetch_alerts(since_seconds=300)

    assert len(out) == 4  # 3 threats (2 + 1) + 1 case
    streams = {e["stream"] for e in out}
    assert streams == {"threat", "case"}
    assert all(e["source"] == "abnormal_security" for e in out)


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    c = AbnormalSecurityConnector(api_token="t")
    respx.get(f"{_BASE}/v1/threats").respond(200, json={"threats": []})
    res = await c.test_connection()
    assert res["success"] is True


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_failure():
    c = AbnormalSecurityConnector(api_token="t")
    respx.get(f"{_BASE}/v1/threats").respond(500, json={"error": "boom"})
    res = await c.test_connection()
    assert res["success"] is False
    assert "500" in res["error"]
