"""Tests for the Sysdig Secure connector (T4.7)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.sysdig import SysdigConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "sysdig" / "sample_event.json"


@pytest.fixture(scope="module")
def fixture() -> list[dict]:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = SysdigConnector.schema()
    assert schema.connector_id == "sysdig"
    assert schema.category == "siem"
    names = {f.name for f in schema.fields}
    assert {"region", "api_token"} <= names
    assert Capability.PULL_ALERTS in SysdigConnector.capabilities()


def test_registry_contains_sysdig():
    assert "sysdig" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["sysdig"] is SysdigConnector


def test_normalize_terminal_shell_to_high(fixture):
    c = SysdigConnector(region="us1", api_token="t")
    out = c.normalize(fixture[0])
    assert out["severity"] == "high"
    assert out["actor"] == "root"
    assert out["namespace"] == "prod"
    assert out["event_type"].startswith("sysdig.")


def test_normalize_drift_always_high(fixture):
    c = SysdigConnector(region="us1", api_token="t")
    out = c.normalize(fixture[1])
    # Severity 5 == notice would normally be info, but "drift" promotes to high.
    assert out["severity"] == "high"


def test_normalize_warning_to_low(fixture):
    c = SysdigConnector(region="us1", api_token="t")
    out = c.normalize(fixture[2])
    assert out["severity"] == "low"


def test_normalize_info_to_info(fixture):
    c = SysdigConnector(region="us1", api_token="t")
    out = c.normalize(fixture[3])
    assert out["severity"] == "info"


def test_invalid_region_rejected():
    with pytest.raises(ValueError):
        SysdigConnector(region="moon-base-1", api_token="t")


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_pagination(fixture):
    c = SysdigConnector(region="us1", api_token="t")
    base = c._base  # type: ignore[attr-defined]
    # Pad page-1 to exactly _PER_PAGE=100 to force a second iteration via
    # the cursor branch. _PER_PAGE is the connector's internal pagination size.
    from app.connectors.sysdig import _PER_PAGE

    fat_page = (fixture * 50)[:_PER_PAGE]
    page1 = {"data": fat_page, "page": {"next": "cursor-2"}}
    page2 = {"data": fixture[:1], "page": {}}
    route = respx.get(f"{base}/api/v1/secureEvents")
    route.side_effect = [
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ]
    out = await c.fetch_alerts(since_seconds=300)
    assert len(out) == _PER_PAGE + 1
    assert all(e["source"] == "sysdig" for e in out)


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    c = SysdigConnector(region="us1", api_token="t")
    respx.get(f"{c._base}/api/v1/secureEvents").respond(200, json={"data": []})  # type: ignore[attr-defined]
    res = await c.test_connection()
    assert res["success"] is True


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_unauthorized():
    c = SysdigConnector(region="us1", api_token="t")
    respx.get(f"{c._base}/api/v1/secureEvents").respond(401, text="unauthorized")  # type: ignore[attr-defined]
    res = await c.test_connection()
    assert res["success"] is False
    assert "401" in res["error"]
