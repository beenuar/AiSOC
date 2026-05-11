"""
Unit tests for the Prisma Cloud connector.

Three concerns per connector apply here too:

1. ``schema()`` is shaped correctly (Prisma-specific field expectations).
2. ``normalize()`` produces an event dict downstream code can rely on,
   including severity ladder collapse and epoch-ms timestamp conversion.
3. ``test_connection()`` and ``fetch_alerts()`` route through ``httpx``
   the way we expect, driven by ``respx`` so we never hit real Prisma
   Cloud APIs.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.connectors.prisma_cloud import PrismaCloudConnector

_API = "https://api.prismacloud.io"
_KEY_ID = "00000000-0000-0000-0000-000000000001"
_SECRET = "super-secret-value"


# ---------------------------------------------------------------------------
# Schema sanity (Prisma-specific; generic contract checks live in test_schemas)
# ---------------------------------------------------------------------------


def test_prisma_cloud_schema_has_required_fields():
    schema = PrismaCloudConnector.schema()
    field_names = {f.name for f in schema.fields}
    assert {"api_url", "access_key_id", "secret_key", "compute_url"} <= field_names
    assert schema.category == "cloud"
    assert schema.connector_id == "prisma_cloud"


def test_prisma_cloud_schema_marks_secret_field():
    schema = PrismaCloudConnector.schema()
    secret = next(f for f in schema.fields if f.name == "secret_key")
    assert secret.type == "secret"


def test_prisma_cloud_compute_url_is_optional():
    schema = PrismaCloudConnector.schema()
    compute = next(f for f in schema.fields if f.name == "compute_url")
    assert compute.required is False, "compute_url must be optional; v7.1.0 only consumes the unified /alert endpoint"


# ---------------------------------------------------------------------------
# Normalize: shape + severity rules + timestamp coercion
# ---------------------------------------------------------------------------


def test_normalize_collapses_critical_into_high():
    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    raw = {
        "id": "alert-1",
        "alertTime": 1735689600000,  # 2025-01-01T00:00:00Z, epoch-ms
        "policy": {
            "name": "Public S3 bucket",
            "description": "S3 bucket is publicly readable",
            "severity": "critical",
        },
        "resource": {
            "name": "logs-bucket",
            "rrn": "rrn::s3:us-east-1:123:bucket/logs-bucket",
            "cloudType": "aws",
            "regionId": "us-east-1",
        },
    }
    out = connector.normalize(raw)
    assert out["source"] == "prisma_cloud"
    assert out["severity"] == "high", (
        "Prisma Cloud 'critical' must collapse into AiSOC 'high'; AiSOC does not expose a separate critical band"
    )
    assert out["external_id"] == "alert-1"
    assert out["title"] == "Public S3 bucket"
    assert out["cloud_resource"] == "rrn::s3:us-east-1:123:bucket/logs-bucket"
    assert out["cloud_platform"] == "aws"
    assert out["cloud_region"] == "us-east-1"
    assert out["created_at"] == "2025-01-01T00:00:00Z"


def test_normalize_maps_informational_to_info():
    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    raw = {
        "id": "alert-2",
        "policy": {"name": "Tag missing", "severity": "informational"},
    }
    out = connector.normalize(raw)
    assert out["severity"] == "info"


def test_normalize_handles_iso_timestamp_passthrough():
    """Some legacy payloads ship ISO strings — keep them as-is."""
    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    raw = {
        "id": "alert-3",
        "alertTime": "2026-01-01T12:00:00Z",
        "policy": {"name": "Drift detected", "severity": "medium"},
    }
    out = connector.normalize(raw)
    assert out["created_at"] == "2026-01-01T12:00:00Z"
    assert out["severity"] == "medium"


def test_normalize_falls_back_to_medium_for_unknown_severity():
    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    raw = {"id": "alert-4", "policy": {"name": "Unknown band", "severity": "weird"}}
    out = connector.normalize(raw)
    assert out["severity"] == "medium", "unrecognised severity must default to 'medium' — never silently drop"


# ---------------------------------------------------------------------------
# Live HTTP routing via respx
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_success():
    respx.post(f"{_API}/login").mock(return_value=httpx.Response(200, json={"token": "jwt-abc"}))
    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    result = await connector.test_connection()
    assert result["success"] is True
    assert result["api_url"] == _API


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_returns_friendly_error_on_auth_failure():
    respx.post(f"{_API}/login").mock(return_value=httpx.Response(401, text="invalid credentials"))
    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    result = await connector.test_connection()
    assert result["success"] is False
    assert "could not exchange access keys" in result["error"]


@pytest.mark.asyncio
@respx.mock
async def test_test_connection_handles_login_returning_no_token():
    """Prisma Cloud has been observed to return 200 with no token field
    when the access key is disabled. We must surface that as a failure."""
    respx.post(f"{_API}/login").mock(return_value=httpx.Response(200, json={"message": "key disabled"}))
    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    result = await connector.test_connection()
    assert result["success"] is False


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_returns_normalized_events_from_items_envelope():
    respx.post(f"{_API}/login").mock(return_value=httpx.Response(200, json={"token": "jwt-abc"}))
    respx.post(f"{_API}/alert/v1/alert").mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": "a-1",
                        "alertTime": 1735689600000,
                        "policy": {
                            "name": "Open SSH to internet",
                            "severity": "high",
                        },
                        "resource": {
                            "name": "i-abc",
                            "cloudType": "aws",
                            "regionId": "us-east-1",
                        },
                    }
                ]
            },
        )
    )

    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["source"] == "prisma_cloud"
    assert events[0]["external_id"] == "a-1"
    assert events[0]["severity"] == "high"
    assert events[0]["cloud_platform"] == "aws"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_handles_bare_list_envelope():
    """Some Prisma Cloud regions return a bare list instead of the
    ``{"items": [...]}`` envelope; the connector must accept both."""
    respx.post(f"{_API}/login").mock(return_value=httpx.Response(200, json={"token": "jwt-abc"}))
    respx.post(f"{_API}/alert/v1/alert").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "id": "a-2",
                    "policy": {"name": "Drift detected", "severity": "low"},
                }
            ],
        )
    )

    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    events = await connector.fetch_alerts(since_seconds=300)
    assert len(events) == 1
    assert events[0]["external_id"] == "a-2"
    assert events[0]["severity"] == "low"


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_returns_empty_list_when_login_fails():
    """If auth fails on poll we degrade gracefully — no crash, no events,
    and the scheduler will retry on the next interval."""
    respx.post(f"{_API}/login").mock(return_value=httpx.Response(500, text="internal server error"))
    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    events = await connector.fetch_alerts(since_seconds=300)
    assert events == []


@pytest.mark.asyncio
@respx.mock
async def test_fetch_alerts_returns_empty_list_when_alert_endpoint_5xxs():
    respx.post(f"{_API}/login").mock(return_value=httpx.Response(200, json={"token": "jwt-abc"}))
    respx.post(f"{_API}/alert/v1/alert").mock(return_value=httpx.Response(503, text="service unavailable"))
    connector = PrismaCloudConnector(_API, _KEY_ID, _SECRET)
    events = await connector.fetch_alerts(since_seconds=300)
    assert events == []
