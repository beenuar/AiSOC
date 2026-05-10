"""Tests for distributed query read/write and internal enqueue/status endpoints."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


async def _enroll(client, host: str = "dist-host") -> tuple[str, str]:
    r = await client.post(
        "/api/v1/osquery/enroll",
        json={"enroll_secret": "test-enroll-secret", "host_identifier": host},
    )
    return host, r.json()["node_key"]


@pytest.mark.asyncio
async def test_distributed_read_empty(client):
    _host, node_key = await _enroll(client, "dist-read-1")
    resp = await client.post(
        "/api/v1/osquery/distributed/read",
        json={"node_key": node_key},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["queries"] == {}
    assert data["node_invalid"] is False


@pytest.mark.asyncio
async def test_distributed_enqueue_and_read(client):
    host, node_key = await _enroll(client, "dist-read-2")

    # Enqueue via internal API
    enq = await client.post(
        "/api/v1/osquery/distributed/enqueue",
        json={
            "host_identifier": host,
            "tenant_id": "default",
            "query_text": "SELECT pid, name FROM processes;",
        },
    )
    assert enq.status_code == 200
    query_id = enq.json()["query_id"]

    # osqueryd reads the pending query
    read = await client.post(
        "/api/v1/osquery/distributed/read",
        json={"node_key": node_key},
    )
    assert read.status_code == 200
    assert query_id in read.json()["queries"]


@pytest.mark.asyncio
async def test_distributed_write_and_status(client):
    host, node_key = await _enroll(client, "dist-write-1")

    enq = await client.post(
        "/api/v1/osquery/distributed/enqueue",
        json={
            "host_identifier": host,
            "tenant_id": "default",
            "query_text": "SELECT * FROM users;",
        },
    )
    query_id = enq.json()["query_id"]

    rows = [{"uid": "0", "username": "root"}]
    with patch("app.api.v1.endpoints.distributed_write.forward_events", new=AsyncMock()):
        write = await client.post(
            "/api/v1/osquery/distributed/write",
            json={
                "node_key": node_key,
                "queries": {query_id: rows},
                "statuses": {query_id: 0},
            },
        )
    assert write.status_code == 200
    assert write.json()["node_invalid"] is False

    # Internal status endpoint should show completed
    status_resp = await client.get(f"/api/v1/osquery/distributed/{query_id}")
    assert status_resp.status_code == 200
    sdata = status_resp.json()
    assert sdata["status"] == "completed"
    assert sdata["rows"] == rows


@pytest.mark.asyncio
async def test_distributed_enqueue_unknown_host(client):
    resp = await client.post(
        "/api/v1/osquery/distributed/enqueue",
        json={
            "host_identifier": "nonexistent-host",
            "tenant_id": "default",
            "query_text": "SELECT 1;",
        },
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_distributed_status_not_found(client):
    resp = await client.get("/api/v1/osquery/distributed/no-such-id")
    assert resp.status_code == 404
