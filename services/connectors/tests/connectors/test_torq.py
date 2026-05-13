"""Tests for the Torq connector (T4.2)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.torq import TorqConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "torq" / "sample_event.json"
_BASE = "https://api.torq.io/public/v1"
_AUTH = "https://api.torq.io/auth/v1/token"
_KEY_ID = "torq-key-id"
_KEY_SECRET = "torq-key-secret"  # noqa: S105 — fake test creds


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = TorqConnector.schema()
    assert schema.connector_id == "torq"
    assert schema.category == "saas"
    names = {f.name for f in schema.fields}
    assert {"key_id", "key_secret"} <= names
    secret = next(f for f in schema.fields if f.name == "key_secret")
    assert secret.type == "secret"
    assert Capability.PULL_AUDIT in TorqConnector.capabilities()


def test_registry_contains_torq():
    assert "torq" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["torq"] is TorqConnector


def test_normalize_roundtrip_execution_success(fixture):
    ev = dict(fixture["executions"][0], _aisoc_stream="execution")
    out = TorqConnector(_KEY_ID, _KEY_SECRET).normalize(ev)
    assert out["source"] == "torq"
    assert out["severity"] == "info"  # success → info per wave-1
    assert out["external_id"] == "torq-exec-exec-001"
    assert out["event_type"] == "torq.execution.success"
    assert out["actor_email"] == "soc-bot@example.com"


def test_normalize_roundtrip_execution_failed_to_high(fixture):
    ev = dict(fixture["executions"][1], _aisoc_stream="execution")
    out = TorqConnector(_KEY_ID, _KEY_SECRET).normalize(ev)
    assert out["severity"] == "high"  # failed → high per wave-1


def test_normalize_roundtrip_execution_warning_to_low(fixture):
    ev = dict(fixture["executions"][2], _aisoc_stream="execution")
    out = TorqConnector(_KEY_ID, _KEY_SECRET).normalize(ev)
    assert out["severity"] == "low"  # warning → low


def test_normalize_audit_workflow_deleted_high(fixture):
    ev = dict(fixture["events"][0], _aisoc_stream="audit_log")
    out = TorqConnector(_KEY_ID, _KEY_SECRET).normalize(ev)
    assert out["severity"] == "high"
    assert out["event_type"] == "torq.workflow.deleted"
    assert out["src_ip"] == "10.0.0.2"
    assert out["actor_email"] == "alice@example.com"


def test_normalize_audit_routine_info(fixture):
    ev = dict(fixture["events"][1], _aisoc_stream="audit_log")
    out = TorqConnector(_KEY_ID, _KEY_SECRET).normalize(ev)
    assert out["severity"] == "info"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_uses_pagination(fixture):
    # Auth token exchange.
    respx.post(_AUTH).mock(return_value=httpx.Response(200, json={"access_token": "tok-abc"}))

    exec_calls = 0

    def exec_handler(request: httpx.Request) -> httpx.Response:
        nonlocal exec_calls
        exec_calls += 1
        if exec_calls == 1:
            return httpx.Response(200, json={"executions": fixture["executions"], "next_page_token": "cur2"})
        return httpx.Response(200, json={"executions": [], "next_page_token": None})

    respx.get(f"{_BASE}/workflows/executions").mock(side_effect=exec_handler)
    respx.get(f"{_BASE}/audit-logs").mock(
        return_value=httpx.Response(200, json={"events": fixture["events"], "next_page_token": None}),
    )

    connector = TorqConnector(_KEY_ID, _KEY_SECRET)
    events = await connector.fetch_alerts(since_seconds=10**9)

    # Pagination ran (called twice: one full page + one empty page).
    assert exec_calls == 2
    # All events flowed through normalize().
    assert all(e["source"] == "torq" for e in events)
    exec_events = [e for e in events if e["external_id"].startswith("torq-exec-")]
    audit_events = [e for e in events if e["external_id"].startswith("torq-audit-")]
    assert len(exec_events) == 3
    assert len(audit_events) == 2


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    respx.post(_AUTH).mock(return_value=httpx.Response(200, json={"access_token": "tok-abc"}))
    respx.get(f"{_BASE}/workflows").mock(return_value=httpx.Response(200, json={"workflows": []}))
    result = await TorqConnector(_KEY_ID, _KEY_SECRET).test_connection()
    assert result["success"] is True


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_bad_creds():
    respx.post(_AUTH).mock(return_value=httpx.Response(401, text="unauthorized"))
    result = await TorqConnector(_KEY_ID, _KEY_SECRET).test_connection()
    assert result["success"] is False
    assert "401" in result["error"]
