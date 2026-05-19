"""Tests for the Cloudflare WAF + Zero Trust connector (T4.1)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.cloudflare_zt import CloudflareZTConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "cloudflare_zt" / "sample_event.json"


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = CloudflareZTConnector.schema()
    assert schema.connector_id == "cloudflare_zt"
    assert schema.category == "network"
    names = {f.name for f in schema.fields}
    assert {"mode", "account_id", "zone_id", "api_token"} <= names
    assert Capability.PULL_ALERTS in CloudflareZTConnector.capabilities()


def test_registry_contains_cloudflare_zt():
    assert "cloudflare_zt" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["cloudflare_zt"] is CloudflareZTConnector


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        CloudflareZTConnector(mode="bogus", account_id="a", api_token="t")


def test_waf_mode_requires_zone_id():
    with pytest.raises(ValueError):
        CloudflareZTConnector(mode="waf", account_id="a", api_token="t")


def test_normalize_waf_block_owasp_to_high(fixture):
    c = CloudflareZTConnector(mode="waf", account_id="a", api_token="t", zone_id="z")
    out = c.normalize(fixture["waf"][0])
    assert out["severity"] == "high"
    assert out["src_ip"] == "203.0.113.42"
    assert out["event_type"] == "cloudflare_zt.waf.block"


def test_normalize_waf_challenge_to_medium(fixture):
    c = CloudflareZTConnector(mode="waf", account_id="a", api_token="t", zone_id="z")
    out = c.normalize(fixture["waf"][1])
    assert out["severity"] == "medium"


def test_normalize_waf_log_to_info(fixture):
    c = CloudflareZTConnector(mode="waf", account_id="a", api_token="t", zone_id="z")
    out = c.normalize(fixture["waf"][2])
    assert out["severity"] == "info"


def test_normalize_access_blocked_to_high(fixture):
    c = CloudflareZTConnector(mode="access", account_id="a", api_token="t")
    out = c.normalize(fixture["access"][1])
    assert out["severity"] == "high"
    assert out["actor_email"] == "mallory@example.com"


def test_normalize_access_allow_to_info(fixture):
    c = CloudflareZTConnector(mode="access", account_id="a", api_token="t")
    out = c.normalize(fixture["access"][0])
    assert out["severity"] == "info"


def test_normalize_access_non_identity_to_medium(fixture):
    c = CloudflareZTConnector(mode="access", account_id="a", api_token="t")
    out = c.normalize(fixture["access"][2])
    assert out["severity"] == "medium"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_pagination(fixture):
    c = CloudflareZTConnector(mode="waf", account_id="a", api_token="t", zone_id="z")
    page1 = {
        "result": fixture["waf"],
        "result_info": {"cursor": "abc"},
    }
    page2 = {"result": [fixture["waf"][0]], "result_info": {}}
    route = respx.get("https://api.cloudflare.com/client/v4/zones/z/security/events")
    route.side_effect = [
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ]
    out = await c.fetch_alerts(since_seconds=300)
    # 3 from page 1, 1 from page 2 = 4 total. Page 2 has no cursor → stops.
    assert len(out) == 4
    assert all(e["source"] == "cloudflare_zt" for e in out)
    assert all(e["stream"] == "waf" for e in out)


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    c = CloudflareZTConnector(mode="access", account_id="a", api_token="t")
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").respond(200, json={"result": {"status": "active"}})
    respx.get("https://api.cloudflare.com/client/v4/accounts/a/access/logs/access_requests").respond(200, json={"result": []})
    res = await c.test_connection()
    assert res["success"] is True
    assert res["mode"] == "access"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_token_inactive():
    c = CloudflareZTConnector(mode="access", account_id="a", api_token="t")
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").respond(200, json={"result": {"status": "disabled"}})
    res = await c.test_connection()
    assert res["success"] is False
    assert "disabled" in res["error"]
