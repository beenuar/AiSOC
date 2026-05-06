"""Unit tests for the connectors API proxy helpers.

Full end-to-end CRUD tests would need a Postgres fixture and the auth
stack wired up, which the rest of this test suite generally skips. The
parts that *are* worth covering in isolation are the inter-service
proxy helpers — they hold the catalog validation and error mapping
logic that the wizard depends on, and they fail in subtle ways when the
connectors microservice misbehaves.

We mock ``httpx.AsyncClient`` directly because:

* It's the seam between this service and the connectors microservice;
  pinning it in tests is enough to characterise our behaviour without
  pulling up a second FastAPI app.
* The error-mapping logic (503 / 502 / 422 passthrough) only has
  meaningful assertions when we can synthesise specific upstream
  status codes.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.api.v1.endpoints.connectors import (
    _fetch_catalog,
    _proxy_test_connection,
    _validate_connector_type,
)
from fastapi import HTTPException


def _mock_response(status_code: int, json_body: Any) -> MagicMock:
    """Build a MagicMock that quacks like an httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json = MagicMock(return_value=json_body)
    if status_code >= 400:
        resp.raise_for_status = MagicMock(side_effect=httpx.HTTPStatusError(f"upstream {status_code}", request=MagicMock(), response=resp))
    else:
        resp.raise_for_status = MagicMock()
    return resp


def _patched_client(get_resp: MagicMock | None = None, post_resp: MagicMock | None = None):
    """Patch httpx.AsyncClient with a context-managed mock client."""
    client_instance = MagicMock()
    client_instance.get = AsyncMock(return_value=get_resp) if get_resp else AsyncMock()
    client_instance.post = AsyncMock(return_value=post_resp) if post_resp else AsyncMock()
    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=None)
    return patch(
        "app.api.v1.endpoints.connectors.httpx.AsyncClient",
        return_value=client_cm,
    )


# ---------------------------------------------------------------- catalog


@pytest.mark.asyncio
async def test_fetch_catalog_returns_schemas() -> None:
    fake_schemas = [
        {"connector_id": "splunk", "name": "Splunk", "category": "siem", "fields": []},
    ]
    resp = _mock_response(200, {"schemas": fake_schemas})
    with _patched_client(get_resp=resp):
        result = await _fetch_catalog()
    assert result == fake_schemas


@pytest.mark.asyncio
async def test_fetch_catalog_raises_503_when_unreachable() -> None:
    """If the connectors service is down, surface 503 — not 500."""
    client_instance = MagicMock()
    client_instance.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=None)
    with patch(
        "app.api.v1.endpoints.connectors.httpx.AsyncClient",
        return_value=client_cm,
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _fetch_catalog()
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_fetch_catalog_raises_502_for_malformed_body() -> None:
    """A 200 with the wrong shape is the connectors service's fault."""
    resp = _mock_response(200, {"schemas": "not-a-list"})
    with _patched_client(get_resp=resp):
        with pytest.raises(HTTPException) as exc_info:
            await _fetch_catalog()
    assert exc_info.value.status_code == 502


# -------------------------------------------------------- type validation


@pytest.mark.asyncio
async def test_validate_connector_type_accepts_known() -> None:
    fake_schemas = [{"connector_id": "splunk", "category": "siem", "name": "Splunk"}]
    resp = _mock_response(200, {"schemas": fake_schemas})
    with _patched_client(get_resp=resp):
        entry = await _validate_connector_type("splunk")
    assert entry["connector_id"] == "splunk"
    assert entry["category"] == "siem"


@pytest.mark.asyncio
async def test_validate_connector_type_rejects_unknown() -> None:
    """Unknown connector_type → 422 with the list of known ids."""
    fake_schemas = [{"connector_id": "splunk", "category": "siem"}]
    resp = _mock_response(200, {"schemas": fake_schemas})
    with _patched_client(get_resp=resp):
        with pytest.raises(HTTPException) as exc_info:
            await _validate_connector_type("not_a_real_connector")
    assert exc_info.value.status_code == 422
    assert "splunk" in exc_info.value.detail


# ------------------------------------------------------------ test proxy


@pytest.mark.asyncio
async def test_proxy_test_connection_passthrough_success() -> None:
    """A 200 from upstream is returned as-is."""
    upstream_body = {"success": True, "connector": "splunk", "version": "9.0"}
    resp = _mock_response(200, upstream_body)
    with _patched_client(post_resp=resp):
        result = await _proxy_test_connection("splunk", {"token": "x"}, {"host": "y"})
    assert result == upstream_body


@pytest.mark.asyncio
async def test_proxy_test_connection_passthrough_connector_failure() -> None:
    """A 200 with success=False is *also* a normal return — connector said no."""
    upstream_body = {"success": False, "connector": "splunk", "error": "401 Unauthorized"}
    resp = _mock_response(200, upstream_body)
    with _patched_client(post_resp=resp):
        result = await _proxy_test_connection("splunk", {"token": "bad"}, {})
    # Critically, this is NOT raised — the wizard wants to render the
    # connector's own error message.
    assert result["success"] is False
    assert result["error"] == "401 Unauthorized"


@pytest.mark.asyncio
async def test_proxy_test_connection_422_passes_detail() -> None:
    """422 from upstream means schema mismatch; surface the detail."""
    resp = _mock_response(422, {"detail": "missing field 'tenant_id'"})
    with _patched_client(post_resp=resp):
        with pytest.raises(HTTPException) as exc_info:
            await _proxy_test_connection("azure_entra", {}, {})
    assert exc_info.value.status_code == 422
    assert "tenant_id" in exc_info.value.detail


@pytest.mark.asyncio
async def test_proxy_test_connection_404_becomes_503() -> None:
    """A 404 mid-request means the connector class vanished — transient.

    We treat it as 503 (try again) rather than 404 (the user did something
    wrong) because the catalog check happens *before* this proxy call,
    so by the time we get a 404 the catalog and the runtime have drifted.
    """
    resp = _mock_response(404, {"detail": "not found"})
    with _patched_client(post_resp=resp):
        with pytest.raises(HTTPException) as exc_info:
            await _proxy_test_connection("splunk", {}, {})
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_proxy_test_connection_5xx_becomes_502() -> None:
    """Upstream 500s are bad-gateway from our perspective."""
    resp = _mock_response(500, {"detail": "boom"})
    with _patched_client(post_resp=resp):
        with pytest.raises(HTTPException) as exc_info:
            await _proxy_test_connection("splunk", {}, {})
    assert exc_info.value.status_code == 502


@pytest.mark.asyncio
async def test_proxy_test_connection_unreachable_becomes_503() -> None:
    """Network errors are 503 — connectors service is down."""
    client_instance = MagicMock()
    client_instance.post = AsyncMock(side_effect=httpx.ConnectError("conn refused"))
    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=None)
    with patch(
        "app.api.v1.endpoints.connectors.httpx.AsyncClient",
        return_value=client_cm,
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _proxy_test_connection("splunk", {}, {})
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_proxy_test_connection_non_dict_body_normalised() -> None:
    """Defend against connectors microservice returning a non-dict 200."""
    resp = _mock_response(200, "ok")
    with _patched_client(post_resp=resp):
        result = await _proxy_test_connection("splunk", {}, {})
    assert isinstance(result, dict)
    assert result["success"] is False
