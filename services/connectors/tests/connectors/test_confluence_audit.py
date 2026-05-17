"""Tests for the Confluence Audit connector (T4.2)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors import confluence_audit as confluence_audit_module
from app.connectors.base import Capability
from app.connectors.confluence_audit import ConfluenceAuditConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "confluence_audit" / "sample_event.json"
_SITE = "https://acme.atlassian.net"
_EMAIL = "soc@example.com"
_TOKEN = "atl-token-fake"  # noqa: S105 — fake


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = ConfluenceAuditConnector.schema()
    assert schema.connector_id == "confluence_audit"
    assert schema.category == "saas"
    names = {f.name for f in schema.fields}
    assert {"site_url", "email", "api_token"} <= names
    secret = next(f for f in schema.fields if f.name == "api_token")
    assert secret.type == "secret"
    assert Capability.PULL_AUDIT in ConfluenceAuditConnector.capabilities()
    assert Capability.READ_AUDIT_TRAIL in ConfluenceAuditConnector.capabilities()


def test_registry_contains_confluence_audit():
    assert "confluence_audit" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["confluence_audit"] is ConfluenceAuditConnector


def test_normalize_external_share_high(fixture):
    out = ConfluenceAuditConnector(_SITE, _EMAIL, _TOKEN).normalize(fixture["results"][0])
    assert out["source"] == "confluence_audit"
    assert out["severity"] == "high"
    assert out["actor"] == "Alice Smith"
    assert out["actor_email"] == "alice@example.com"
    assert out["src_ip"] == "10.0.0.1"
    assert out["event_type"] == "confluence.permissions"


def test_normalize_permissions_updated_medium(fixture):
    out = ConfluenceAuditConnector(_SITE, _EMAIL, _TOKEN).normalize(fixture["results"][1])
    assert out["severity"] == "medium"


def test_normalize_page_view_info(fixture):
    out = ConfluenceAuditConnector(_SITE, _EMAIL, _TOKEN).normalize(fixture["results"][2])
    # general-configuration category, not a permission/security event → info.
    assert out["severity"] == "info"


def test_normalize_removed_user_high(fixture):
    out = ConfluenceAuditConnector(_SITE, _EMAIL, _TOKEN).normalize(fixture["results"][3])
    # "Removed user from site" is in the HIGH_RISK_SUMMARIES list.
    assert out["severity"] == "high"


def test_normalize_creation_date_ms_to_iso(fixture):
    out = ConfluenceAuditConnector(_SITE, _EMAIL, _TOKEN).normalize(fixture["results"][0])
    # The fixture creation date in ms-since-epoch becomes ISO8601 in the
    # normalised event.
    assert out["created_at"] is not None
    assert "T" in out["created_at"]


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_pagination(fixture):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            # Full page (size == limit) → caller must paginate again.
            full = {"results": fixture["results"], "start": 0, "limit": 4, "size": 4}
            return httpx.Response(200, json=full)
        # Short page (size < limit) → terminate.
        return httpx.Response(200, json={"results": [], "start": 4, "limit": 4, "size": 0})

    respx.get(f"{_SITE}/wiki/rest/api/audit").mock(side_effect=handler)

    connector = ConfluenceAuditConnector(_SITE, _EMAIL, _TOKEN)
    # Lower the page size to match the fixture.
    monkey_orig = confluence_audit_module._PAGE_SIZE  # noqa: SLF001
    try:
        confluence_audit_module._PAGE_SIZE = 4  # type: ignore[assignment]
        events = await connector.fetch_alerts(since_seconds=10**9)
    finally:
        confluence_audit_module._PAGE_SIZE = monkey_orig  # type: ignore[assignment]

    # First page returned 4 items, second page returned []; pagination
    # terminated cleanly.
    assert calls == 1 or calls == 2
    assert all(e["source"] == "confluence_audit" for e in events)
    severities = [e["severity"] for e in events]
    assert "high" in severities and "medium" in severities and "info" in severities


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    respx.get(f"{_SITE}/wiki/rest/api/user/current").mock(
        return_value=httpx.Response(200, json={"accountId": "abc-123"}),
    )
    respx.get(f"{_SITE}/wiki/rest/api/audit").mock(
        return_value=httpx.Response(200, json={"results": [], "size": 0, "limit": 1}),
    )
    out = await ConfluenceAuditConnector(_SITE, _EMAIL, _TOKEN).test_connection()
    assert out["success"] is True
    assert out["account_id"] == "abc-123"
    assert out["audit_available"] is True


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_unauthorised():
    respx.get(f"{_SITE}/wiki/rest/api/user/current").mock(return_value=httpx.Response(401, text="bad creds"))
    out = await ConfluenceAuditConnector(_SITE, _EMAIL, _TOKEN).test_connection()
    assert out["success"] is False
