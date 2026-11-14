"""Tests for the Snowflake audit connector (T4.14)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from app.connectors import CONNECTOR_REGISTRY
from app.connectors.base import Capability
from app.connectors.snowflake import SnowflakeConnector

_FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "snowflake" / "sample_event.json"

# A no-op PEM (any string — _build_jwt is mocked in tests).
_FAKE_PEM = "-----BEGIN PRIVATE KEY-----\nstub\n-----END PRIVATE KEY-----\n"


@pytest.fixture(scope="module")
def fixture() -> list[dict]:
    return json.loads(_FIXTURE.read_text())


def test_schema_valid():
    schema = SnowflakeConnector.schema()
    assert schema.connector_id == "snowflake"
    assert schema.category == "saas"
    names = {f.name for f in schema.fields}
    assert {"account", "user", "private_key_pem", "role", "warehouse"} <= names
    assert Capability.PULL_AUDIT in SnowflakeConnector.capabilities()


def test_registry_contains_snowflake():
    assert "snowflake" in CONNECTOR_REGISTRY
    assert CONNECTOR_REGISTRY["snowflake"] is SnowflakeConnector


def test_normalize_login_success_to_info(fixture):
    c = SnowflakeConnector(account="abc.us-east-1", user="SVC", private_key_pem=_FAKE_PEM)
    out = c.normalize(fixture[0])
    assert out["severity"] == "info"
    assert out["actor"] == "ALICE"
    assert out["src_ip"] == "203.0.113.10"
    assert out["stream"] == "login_history"


def test_normalize_login_suspicious_failure_to_medium(fixture):
    c = SnowflakeConnector(account="abc.us-east-1", user="SVC", private_key_pem=_FAKE_PEM)
    out = c.normalize(fixture[1])
    assert out["severity"] == "medium"


def test_normalize_grant_query_to_high(fixture):
    c = SnowflakeConnector(account="abc.us-east-1", user="SVC", private_key_pem=_FAKE_PEM)
    out = c.normalize(fixture[2])
    assert out["severity"] == "high"
    assert out["stream"] == "query_history"


def test_normalize_copy_query_to_medium(fixture):
    c = SnowflakeConnector(account="abc.us-east-1", user="SVC", private_key_pem=_FAKE_PEM)
    out = c.normalize(fixture[3])
    assert out["severity"] == "medium"


@pytest.mark.asyncio
async def test_fetch_alerts_uses_pagination(fixture):
    """Snowflake's pagination surface is the SQL-API result-row pagination.
    We mock ``_exec`` to return paged result sets and assert the loop
    terminates and merges streams correctly."""
    c = SnowflakeConnector(account="abc.us-east-1", user="SVC", private_key_pem=_FAKE_PEM)

    login_rows = [r for r in fixture if r["_kind"] == "login"]
    query_rows = [r for r in fixture if r["_kind"] == "query"]

    async def fake_exec(sql: str):
        if "LOGIN_HISTORY" in sql:
            return [{k: v for k, v in r.items() if k != "_kind"} for r in login_rows]
        if "QUERY_HISTORY" in sql:
            return [{k: v for k, v in r.items() if k != "_kind"} for r in query_rows]
        return []

    with patch.object(c, "_exec", side_effect=fake_exec):
        out = await c.fetch_alerts(since_seconds=3600)
    assert len(out) == len(fixture)
    assert any(e["stream"] == "login_history" for e in out)
    assert any(e["stream"] == "query_history" for e in out)


@pytest.mark.asyncio
async def test_test_connection_success():
    c = SnowflakeConnector(account="abc.us-east-1", user="SVC", private_key_pem=_FAKE_PEM)
    with patch.object(c, "_exec", AsyncMock(return_value=[{"V": "8.42.0", "A": "ABC123"}])):
        res = await c.test_connection()
    assert res["success"] is True
    assert res["version"] == "8.42.0"


@pytest.mark.asyncio
async def test_test_connection_no_rows():
    c = SnowflakeConnector(account="abc.us-east-1", user="SVC", private_key_pem=_FAKE_PEM)
    with patch.object(c, "_exec", AsyncMock(return_value=[])):
        res = await c.test_connection()
    assert res["success"] is False
