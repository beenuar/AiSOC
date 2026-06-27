"""Tests for the Box content-cloud audit-events connector (T4.12).

Brings the wave-2 ``box`` connector to wave-1 test parity: schema +
registry wiring, the event_type->severity collapse (Shield + admin/role
events high, collaboration + failed-login medium, info floor), the
external-collaborator download escalation, the ``next_stream_position``
cursor pagination, and ``test_connection``. Network mocked with respx.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.box import BoxConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "box" / "sample_event.json"
_BASE = "https://api.box.com"


@pytest.fixture(scope="module")
def fixture() -> list[dict]:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = BoxConnector.schema()
    assert schema.connector_id == "box"
    assert schema.category == "saas"
    names = {f.name for f in schema.fields}
    assert {"access_token"} <= names
    assert Capability.PULL_AUDIT in BoxConnector.capabilities()


def test_registry_contains_box():
    assert "box" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["box"] is BoxConnector


def test_normalize_shield_alert_to_high(fixture):
    out = BoxConnector(access_token="t").normalize(fixture[0])
    assert out["severity"] == "high"
    assert out["external_id"] == "box-shield"
    assert out["actor_email"] == "sec@corp.test"
    assert out["src_ip"] == "203.0.113.9"
    assert out["target"] == "confidential.docx"


def test_normalize_collaboration_invite_to_medium(fixture):
    assert BoxConnector(access_token="t").normalize(fixture[1])["severity"] == "medium"


def test_normalize_failed_login_to_medium(fixture):
    assert BoxConnector(access_token="t").normalize(fixture[2])["severity"] == "medium"


def test_normalize_preview_to_info(fixture):
    assert BoxConnector(access_token="t").normalize(fixture[3])["severity"] == "info"


def test_normalize_external_download_escalates_to_high(fixture):
    """An ITEM_DOWNLOAD whose action_by is a consumer (external) mailbox is
    promoted to high even though the bare event type is otherwise info."""
    out = BoxConnector(access_token="t").normalize(fixture[4])
    assert out["severity"] == "high"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_stream_position(fixture, monkeypatch):
    monkeypatch.setattr("app.connectors.box._PER_PAGE", 2)
    c = BoxConnector(access_token="t")
    page1 = {"entries": fixture[:2], "next_stream_position": "pos2"}
    page2 = {"entries": fixture[2:3]}  # short → stop
    route = respx.get(f"{_BASE}/2.0/events")
    route.side_effect = [
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ]
    out = await c.fetch_alerts(since_seconds=300)
    assert len(out) == 3
    assert all(e["source"] == "box" for e in out)


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_stops_on_non_200():
    c = BoxConnector(access_token="t")
    respx.get(f"{_BASE}/2.0/events").respond(401, json={"code": "unauthorized"})
    out = await c.fetch_alerts(since_seconds=300)
    assert out == []


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    c = BoxConnector(access_token="t")
    respx.get(f"{_BASE}/2.0/users/me").respond(200, json={"login": "admin@corp.test", "name": "Admin", "enterprise": {"name": "Acme"}})
    res = await c.test_connection()
    assert res["success"] is True
    assert res["user"] == "admin@corp.test"
    assert res["enterprise"] == "Acme"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_failure():
    c = BoxConnector(access_token="t")
    respx.get(f"{_BASE}/2.0/users/me").respond(401, json={"code": "unauthorized"})
    res = await c.test_connection()
    assert res["success"] is False
    assert "401" in res["error"]
