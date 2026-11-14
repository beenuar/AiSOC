"""Tests for POST /api/v1/osquery/config."""

from __future__ import annotations

import pytest


async def _enroll(client, host: str = "cfg-host") -> str:
    r = await client.post(
        "/api/v1/osquery/enroll",
        json={"enroll_secret": "test-enroll-secret", "host_identifier": host},
    )
    return r.json()["node_key"]


@pytest.mark.asyncio
async def test_config_valid_node(client):
    node_key = await _enroll(client, "cfg-host-1")
    resp = await client.post(
        "/api/v1/osquery/config",
        json={"node_key": node_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "schedule" in data
    assert "options" in data


@pytest.mark.asyncio
async def test_config_invalid_node(client):
    resp = await client.post(
        "/api/v1/osquery/config",
        json={"node_key": "totally-fake"},
    )
    assert resp.status_code == 401
