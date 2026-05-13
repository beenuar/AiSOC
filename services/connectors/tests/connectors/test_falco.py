"""Tests for the Falco connector (T4.2)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.falco import FalcoConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "falco" / "sample_event.json"


@pytest.fixture(scope="module")
def fixture() -> list[dict]:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = FalcoConnector.schema()
    assert schema.connector_id == "falco"
    assert schema.category == "siem"
    names = {f.name for f in schema.fields}
    assert {"webhook_path", "shared_secret", "minimum_priority"} <= names
    assert Capability.PULL_ALERTS in FalcoConnector.capabilities()


def test_registry_contains_falco():
    assert "falco" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["falco"] is FalcoConnector


def test_normalize_critical_to_high(fixture):
    out = FalcoConnector().normalize(fixture[0])
    assert out["source"] == "falco"
    assert out["severity"] == "high"
    assert out["actor"] == "root"
    assert out["namespace"] == "prod"
    assert out["event_type"] == "falco.terminal_shell_in_container"


def test_normalize_error_to_medium(fixture):
    out = FalcoConnector().normalize(fixture[1])
    assert out["severity"] == "medium"
    assert out["event_type"] == "falco.write_below_etc"


def test_normalize_informational_to_info(fixture):
    out = FalcoConnector().normalize(fixture[2])
    assert out["severity"] == "info"


def test_normalize_emergency_alert_warning():
    c = FalcoConnector()
    assert c.normalize({"priority": "EMERGENCY", "rule": "x"})["severity"] == "high"
    assert c.normalize({"priority": "ALERT", "rule": "x"})["severity"] == "high"
    assert c.normalize({"priority": "WARNING", "rule": "x"})["severity"] == "low"
    assert c.normalize({"priority": "NOTICE", "rule": "x"})["severity"] == "info"


def test_verify_webhook_open_mode_accepts():
    assert FalcoConnector().verify_webhook({}) is True


def test_verify_webhook_secret_required_and_constant_time():
    c = FalcoConnector(shared_secret="topsecret")  # noqa: S106 — test
    assert c.verify_webhook(None) is False
    assert c.verify_webhook({"X-Falco-Secret": "nope"}) is False
    assert c.verify_webhook({"X-Falco-Secret": "topsecret"}) is True
    # Case-insensitive lookup of the header name.
    assert c.verify_webhook({"x-falco-secret": "topsecret"}) is True


@pytest.mark.asyncio
async def test_fetch_alerts_uses_pagination(fixture):
    # The "pagination" surface for Falco is the in-memory webhook buffer:
    # repeated drains must terminate cleanly (no infinite loop) and the
    # second drain must return [] because the buffer was emptied.
    c = FalcoConnector()
    # Override the event times to "now" so the age filter doesn't drop them.
    now_iso = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    events = [dict(e, time=now_iso) for e in fixture]
    queued = c.ingest_webhook(events)
    assert queued == 3
    first = await c.fetch_alerts(since_seconds=300)
    # All three events drained and normalised.
    assert len(first) == 3
    severities = [e["severity"] for e in first]
    assert "high" in severities and "medium" in severities and "info" in severities
    # Buffer is empty — second poll terminates immediately.
    second = await c.fetch_alerts(since_seconds=300)
    assert second == []


@pytest.mark.asyncio
async def test_fetch_alerts_priority_floor_filters(fixture):
    # With WARNING floor, the INFORMATIONAL event must be dropped.
    c = FalcoConnector(minimum_priority="WARNING")
    now_iso = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    c.ingest_webhook([dict(e, time=now_iso) for e in fixture])
    out = await c.fetch_alerts(since_seconds=300)
    rules = [e["title"] for e in out]
    assert any("Terminal shell" in r for r in rules)
    assert any("Write below etc" in r for r in rules)
    assert not any("Read sensitive file" in r for r in rules)


@pytest.mark.asyncio
async def test_test_connection_reports_state():
    c = FalcoConnector(shared_secret="x")  # noqa: S106 — test
    res = await c.test_connection()
    assert res["success"] is True
    assert res["secret_configured"] is True
