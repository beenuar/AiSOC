"""Tests for POST /api/v1/osquery/enroll."""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_enroll_success(client):
    resp = await client.post(
        "/api/v1/osquery/enroll",
        json={
            "enroll_secret": "test-enroll-secret",
            "host_identifier": "host-001",
            "host_details": {"platform": "linux"},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "node_key" in data
    assert data["node_invalid"] is False


@pytest.mark.asyncio
async def test_enroll_wrong_secret(client):
    resp = await client.post(
        "/api/v1/osquery/enroll",
        json={
            "enroll_secret": "wrong-secret",
            "host_identifier": "host-002",
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_reenroll_rotates_key(client):
    payload = {
        "enroll_secret": "test-enroll-secret",
        "host_identifier": "host-003",
    }
    r1 = await client.post("/api/v1/osquery/enroll", json=payload)
    r2 = await client.post("/api/v1/osquery/enroll", json=payload)
    assert r1.status_code == 200
    assert r2.status_code == 200
    # Node key must rotate on re-enroll
    assert r1.json()["node_key"] != r2.json()["node_key"]
