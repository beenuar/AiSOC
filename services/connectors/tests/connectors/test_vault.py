"""Tests for the HashiCorp Vault audit connector (T4.9)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.vault import VaultConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "vault" / "sample_event.json"


@pytest.fixture(scope="module")
def fixture() -> list[dict]:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = VaultConnector.schema()
    assert schema.connector_id == "vault"
    assert schema.category == "iam"
    names = {f.name for f in schema.fields}
    assert {"vault_addr", "vault_token", "namespace"} <= names
    assert Capability.PULL_AUDIT in VaultConnector.capabilities()


def test_registry_contains_vault():
    assert "vault" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["vault"] is VaultConnector


def test_normalize_low_risk_read_to_info(fixture):
    c = VaultConnector()
    out = c.normalize(fixture[0])
    assert out["severity"] == "info"
    assert out["actor"] == "alice"
    assert out["src_ip"] == "10.0.1.5"


def test_normalize_policy_delete_to_high(fixture):
    c = VaultConnector()
    out = c.normalize(fixture[1])
    assert out["severity"] == "high"


def test_normalize_root_token_path_to_high(fixture):
    c = VaultConnector()
    out = c.normalize(fixture[2])
    assert out["severity"] == "high"


def test_normalize_rotate_with_error_promoted(fixture):
    c = VaultConnector()
    out = c.normalize(fixture[3])
    # rotate is a high-risk op → severity medium minimum; with error stays.
    assert out["severity"] in ("medium", "high")


@pytest.mark.asyncio
async def test_fetch_alerts_uses_pagination(fixture):
    # Vault uses an internal buffer rather than HTTP paging — pagination
    # surface is "drain repeatedly until empty".
    c = VaultConnector()
    # Override timestamps to "now" so the cutoff filter doesn't drop them.
    now_iso = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    events = [dict(e, time=now_iso) for e in fixture]
    queued = await c.ingest_audit_lines(events)
    assert queued == 4
    first = await c.fetch_alerts(since_seconds=300)
    assert len(first) == 4
    second = await c.fetch_alerts(since_seconds=300)
    assert second == []


@pytest.mark.asyncio
async def test_buffer_caps_at_size():
    c = VaultConnector(buffer_size="3")
    await c.ingest_audit_lines([{"i": i} for i in range(10)])
    # Buffer capped at 3 — only last 3 retained.
    assert len(c._buffer) == 3  # type: ignore[attr-defined]
    assert c._buffer[-1] == {"i": 9}  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_test_connection_buffer_only_mode():
    c = VaultConnector()  # no addr → buffer-only mode
    res = await c.test_connection()
    assert res["success"] is True
    assert res["mode"] == "buffer-only"


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_with_addr_health_active():
    c = VaultConnector(vault_addr="https://vault.example.com:8200", vault_token="tok")
    respx.get("https://vault.example.com:8200/v1/sys/health").respond(200, json={"initialized": True})
    respx.get("https://vault.example.com:8200/v1/sys/audit").respond(200, json={"data": {}})
    res = await c.test_connection()
    assert res["success"] is True
    assert res["addr"].startswith("https://vault")
