"""Tests for the Dropbox Business audit-log connector (T4.12).

Brings the wave-2 ``dropbox`` connector to wave-1 test parity: schema +
registry wiring, the tagged-union ``event_type`` -> severity collapse
(high-risk admin/app/sharing events, medium sharing + login_fail, info
floor), actor/src_ip extraction, the ``get_events`` -> ``continue``
cursor pagination, and ``test_connection``. Network mocked with respx.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.dropbox import DropboxConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "dropbox" / "sample_event.json"
_BASE = "https://api.dropboxapi.com"


@pytest.fixture(scope="module")
def fixture() -> list[dict]:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = DropboxConnector.schema()
    assert schema.connector_id == "dropbox"
    assert schema.category == "saas"
    names = {f.name for f in schema.fields}
    assert {"team_admin_token"} <= names
    assert Capability.PULL_AUDIT in DropboxConnector.capabilities()


def test_registry_contains_dropbox():
    assert "dropbox" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["dropbox"] is DropboxConnector


def test_normalize_app_link_to_high(fixture):
    c = DropboxConnector(team_admin_token="t")
    out = c.normalize(fixture[0])
    assert out["severity"] == "high"
    assert out["external_id"] == "d-app-link"
    assert out["actor_email"] == "admin@corp.test"
    assert out["event_type"] == "dropbox.app_link_team"


def test_normalize_admin_role_change_to_high(fixture):
    c = DropboxConnector(team_admin_token="t")
    assert c.normalize(fixture[1])["severity"] == "high"


def test_normalize_shared_link_to_medium(fixture):
    c = DropboxConnector(team_admin_token="t")
    assert c.normalize(fixture[2])["severity"] == "medium"


def test_normalize_login_fail_to_medium_with_src_ip(fixture):
    c = DropboxConnector(team_admin_token="t")
    out = c.normalize(fixture[3])
    assert out["severity"] == "medium"
    assert out["src_ip"] == "203.0.113.5"


def test_normalize_benign_event_to_info(fixture):
    c = DropboxConnector(team_admin_token="t")
    assert c.normalize(fixture[4])["severity"] == "info"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_cursor_continue(fixture):
    c = DropboxConnector(team_admin_token="t")
    page1 = {"events": fixture[:2], "has_more": True, "cursor": "cur1"}
    page2 = {"events": fixture[2:3], "has_more": False}
    respx.post(f"{_BASE}/2/team_log/get_events").respond(200, json=page1)
    respx.post(f"{_BASE}/2/team_log/get_events/continue").respond(200, json=page2)

    out = await c.fetch_alerts(since_seconds=300)

    assert len(out) == 3  # 2 from first page + 1 from continue
    assert all(e["source"] == "dropbox" for e in out)


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_stops_on_non_200():
    c = DropboxConnector(team_admin_token="t")
    respx.post(f"{_BASE}/2/team_log/get_events").respond(401, json={"error": "expired_access_token"})
    out = await c.fetch_alerts(since_seconds=300)
    assert out == []


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    c = DropboxConnector(team_admin_token="t")
    respx.post(f"{_BASE}/2/team/get_info").respond(200, json={"name": "Acme Team", "num_provisioned_users": 42})
    res = await c.test_connection()
    assert res["success"] is True
    assert res["team"] == "Acme Team"
    assert res["members"] == 42


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_failure():
    c = DropboxConnector(team_admin_token="t")
    respx.post(f"{_BASE}/2/team/get_info").respond(401, json={"error": "invalid"})
    res = await c.test_connection()
    assert res["success"] is False
    assert "401" in res["error"]
