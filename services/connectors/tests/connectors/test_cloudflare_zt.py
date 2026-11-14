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


def _graphql_body(rows: list[dict]) -> dict:
    return {"data": {"viewer": {"zones": [{"firewallEventsAdaptive": rows}]}}}


def test_normalize_waf_reads_the_columns_graphql_actually_returns(fixture):
    """`firewallEventsAdaptive` names its columns in camelCase.

    The older fixture in this file is REST-shaped (`client_ip`, `rule_id`,
    `occurred_at`) — a shape no Cloudflare endpoint emits, because the REST
    route it was written for does not exist. These rows carry the names the
    GraphQL dataset returns.
    """
    c = CloudflareZTConnector(mode="waf", account_id="a", api_token="t", zone_id="z")
    out = c.normalize(fixture["waf_graphql"][0])
    assert out["severity"] == "high"
    assert out["src_ip"] == "203.0.113.42"
    assert out["external_id"] == "8a1b2c3d4e5f6789"
    assert out["created_at"] == "2026-05-13T18:30:00Z"
    assert "host=www.example.com" in out["description"]
    assert "country=RU" in out["description"]
    assert "None" not in out["description"], "a GraphQL column was read under a name it is not returned by"


def test_zero_trust_is_accepted_as_a_spelling_of_access():
    """Three surfaces published `zero_trust` while the code took `access`."""
    c = CloudflareZTConnector(mode="zero_trust", account_id="a", api_token="t")
    assert c._mode == "access"


@pytest.mark.asyncio
@respx.mock
async def test_waf_fetch_posts_graphql_and_pages_by_datetime(fixture):
    """The request shape is the property under test.

    A mock that answers whatever it is handed cannot tell a query against the
    firewall dataset from a GET at a route that 404s — which is what this
    connector did before, under a test that passed.
    """
    c = CloudflareZTConnector(mode="waf", account_id="a", api_token="t", zone_id="z")
    rows = fixture["waf_graphql"]
    page1 = rows * 34  # 102 rows, over the 100 page size, so a second page is asked for
    sent: list[dict] = []

    def _respond(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json=_graphql_body(page1 if len(sent) == 1 else [rows[0]]))

    respx.post("https://api.cloudflare.com/client/v4/graphql").mock(side_effect=_respond)
    out = await c.fetch_alerts(since_seconds=300)

    assert len(sent) == 2, "a full page must be followed by another request"
    first = sent[0]
    assert "firewallEventsAdaptive" in first["query"]
    assert first["variables"]["zoneTag"] == "z"
    assert first["variables"]["limit"] == 100
    assert first["variables"]["since"] < first["variables"]["until"]
    # Page 2 resumes at the last row's timestamp, which is the only paging
    # control this dataset has.
    assert sent[1]["variables"]["since"] == rows[-1]["datetime"]
    # 3 distinct rayNames on page 1; page 2 repeats one of them and it is
    # dropped rather than emitted twice.
    assert len(out) == 3, f"rayName de-duplication did not hold: {len(out)}"
    assert all(e["source"] == "cloudflare_zt" for e in out)
    assert all(e["stream"] == "waf" for e in out)


@pytest.mark.asyncio
@respx.mock
async def test_a_graphql_scope_error_is_not_read_as_an_empty_zone():
    """A missing scope is a 200 carrying `errors` and a null `data`.

    Returning `[]` would report a token that cannot see the dataset as a zone
    under no attack.
    """
    c = CloudflareZTConnector(mode="waf", account_id="a", api_token="t", zone_id="z")
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").respond(200, json={"result": {"status": "active"}})
    respx.post("https://api.cloudflare.com/client/v4/graphql").respond(
        200, json={"data": None, "errors": [{"message": "forbidden: insufficient permissions"}]}
    )
    res = await c.test_connection()
    assert res["success"] is False
    assert "insufficient permissions" in res["error"]


@pytest.mark.asyncio
@respx.mock
async def test_an_unmatched_zone_is_not_read_as_an_empty_zone():
    c = CloudflareZTConnector(mode="waf", account_id="a", api_token="t", zone_id="z")
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").respond(200, json={"result": {"status": "active"}})
    respx.post("https://api.cloudflare.com/client/v4/graphql").respond(200, json=_graphql_body([]) | {"data": {"viewer": {"zones": []}}})
    res = await c.test_connection()
    assert res["success"] is False
    assert "no zone with that id" in res["error"]


@pytest.mark.asyncio
@respx.mock
async def test_waf_test_connection_succeeds_on_a_quiet_zone(fixture):
    """Positive control: zero rows is a pass, only errors are not.

    Without this, a gate stuck on "refuse everything" would satisfy both
    cases above and no WAF instance could ever be saved.
    """
    c = CloudflareZTConnector(mode="waf", account_id="a", api_token="t", zone_id="z")
    respx.get("https://api.cloudflare.com/client/v4/user/tokens/verify").respond(200, json={"result": {"status": "active"}})
    respx.post("https://api.cloudflare.com/client/v4/graphql").respond(200, json=_graphql_body([]))
    res = await c.test_connection()
    assert res["success"] is True
    assert res["mode"] == "waf"


@pytest.mark.asyncio
@respx.mock
async def test_access_fetch_still_uses_the_rest_endpoint(fixture):
    """Access mode is the half that was never broken, and must stay REST."""
    c = CloudflareZTConnector(mode="access", account_id="a", api_token="t")
    route = respx.get("https://api.cloudflare.com/client/v4/accounts/a/access/logs/access_requests")
    route.side_effect = [
        httpx.Response(200, json={"result": fixture["access"], "result_info": {"cursor": "abc"}}),
        httpx.Response(200, json={"result": [fixture["access"][0]], "result_info": {}}),
    ]
    out = await c.fetch_alerts(since_seconds=300)
    assert len(out) == len(fixture["access"]) + 1
    assert all(e["stream"] == "access" for e in out)


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
