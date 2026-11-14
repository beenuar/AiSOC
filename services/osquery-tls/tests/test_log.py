"""Tests for POST /api/v1/osquery/log."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest


async def _enroll(client, host: str = "log-host") -> str:
    r = await client.post(
        "/api/v1/osquery/enroll",
        json={"enroll_secret": "test-enroll-secret", "host_identifier": host},
    )
    return r.json()["node_key"]


@pytest.mark.asyncio
async def test_log_result_forwarded(client):
    node_key = await _enroll(client, "log-host-1")
    rows = [{"pid": "1234", "name": "evil", "path": "/tmp/evil"}]
    log_data = [{"name": "suspicious_processes", "hostIdentifier": "log-host-1", "columns": rows[0]}]

    with patch("app.api.v1.endpoints.log.forward_events", new=AsyncMock()) as mock_fwd:
        resp = await client.post(
            "/api/v1/osquery/log",
            json={
                "node_key": node_key,
                "log_type": "result",
                "data": json.dumps(log_data),
            },
        )
    assert resp.status_code == 200
    assert resp.json()["node_invalid"] is False
    mock_fwd.assert_awaited_once()


@pytest.mark.asyncio
async def test_log_status_type_no_forward(client):
    node_key = await _enroll(client, "log-host-2")
    # status logs: forward_events IS still called but with zero events
    with patch("app.api.v1.endpoints.log.forward_events", new=AsyncMock()) as mock_fwd:
        resp = await client.post(
            "/api/v1/osquery/log",
            json={
                "node_key": node_key,
                "log_type": "status",
                "data": json.dumps([{"severity": "0", "message": "osqueryd starting"}]),
            },
        )
    assert resp.status_code == 200
    # status log type returns early with an empty event batch
    call_args = mock_fwd.call_args
    assert call_args is not None
    events_arg = call_args[0][0]
    assert events_arg == []
