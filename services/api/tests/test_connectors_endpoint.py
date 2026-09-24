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

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from app.api.v1.endpoints.connectors import (
    _catalog_headers,
    _fetch_catalog,
    _load_fallback_catalog,
    _proxy_test_connection,
    _validate_connector_type,
    settings,
)
from fastapi import HTTPException

#: The tenant every proxied call is made on behalf of. The connectors
#: service refuses a service token that does not declare one.
_TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


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
        result = await _fetch_catalog(_TENANT)
    assert result.entries == fake_schemas
    assert result.source == "live"
    assert result.degraded is False


@pytest.mark.asyncio
async def test_fetch_catalog_falls_back_when_service_unreachable() -> None:
    """If the connectors microservice is down, the API serves the bundled
    catalog from the image. Single-tenant / demo deploys frequently run
    without a dedicated connectors service, so a transient network blip
    must not blow up listing the catalog. We only raise 503 if the
    bundled fallback is *also* empty (handled by the next test)."""
    client_instance = MagicMock()
    client_instance.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=None)
    with patch(
        "app.api.v1.endpoints.connectors.httpx.AsyncClient",
        return_value=client_cm,
    ):
        result = await _fetch_catalog(_TENANT)
    # The bundled catalog ships with at least one connector schema; we
    # don't pin a specific count because that's churned by the marketplace
    # sync. The contract is "non-empty list of schemas" — that's enough
    # for the API surface to keep serving.
    assert isinstance(result.entries, list)
    assert result.entries, "expected bundled fallback catalog to be non-empty"
    # Provenance is the point: a stand-in must be distinguishable from
    # the live registry, because this one stood in silently for 58 connectors.
    assert result.source == "bundled"
    assert result.degraded is True
    assert "unreachable" in result.reason


@pytest.mark.asyncio
async def test_fetch_catalog_raises_503_when_unreachable_and_no_fallback() -> None:
    """If the service is down AND the bundled fallback is empty, surface
    503 rather than returning an empty catalog (which would silently
    break the connectors UI). We patch the fallback loader to simulate a
    deploy that shipped without bundled schemas."""
    client_instance = MagicMock()
    client_instance.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=None)
    with (
        patch(
            "app.api.v1.endpoints.connectors.httpx.AsyncClient",
            return_value=client_cm,
        ),
        patch(
            "app.api.v1.endpoints.connectors._load_fallback_catalog",
            return_value=[],
        ),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _fetch_catalog(_TENANT)
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_fetch_catalog_raises_502_for_malformed_body() -> None:
    """A 200 with the wrong shape is the connectors service's fault."""
    resp = _mock_response(200, {"schemas": "not-a-list"})
    with _patched_client(get_resp=resp):
        with pytest.raises(HTTPException) as exc_info:
            await _fetch_catalog(_TENANT)
    assert exc_info.value.status_code == 502


# -------------------------------------------------------- type validation


@pytest.mark.asyncio
async def test_validate_connector_type_accepts_known() -> None:
    fake_schemas = [{"connector_id": "splunk", "category": "siem", "name": "Splunk"}]
    resp = _mock_response(200, {"schemas": fake_schemas})
    with _patched_client(get_resp=resp):
        entry = await _validate_connector_type("splunk", _TENANT)
    assert entry["connector_id"] == "splunk"
    assert entry["category"] == "siem"


@pytest.mark.asyncio
async def test_validate_connector_type_rejects_unknown() -> None:
    """Unknown connector_type → 422 with the list of known ids."""
    fake_schemas = [{"connector_id": "splunk", "category": "siem"}]
    resp = _mock_response(200, {"schemas": fake_schemas})
    with _patched_client(get_resp=resp):
        with pytest.raises(HTTPException) as exc_info:
            await _validate_connector_type("not_a_real_connector", _TENANT)
    assert exc_info.value.status_code == 422
    assert "splunk" in exc_info.value.detail


# ------------------------------------------- catalog authentication (the defect)


@pytest.mark.asyncio
async def test_catalog_request_carries_the_service_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """The proxy must authenticate. This is the whole of the original defect.

    Every route on the connectors service sits behind
    ``require_console_or_service_auth``, which needs a bearer credential and —
    for a service token — the tenant the caller is acting for. The proxy sent
    neither, so it was answered 401 on every call and served the bundled
    catalog *every time*, with 26 entries against a registry of 84. Nothing
    failed; the wizard just showed a confidently wrong list.

    Asserting on the outgoing request rather than the return value is
    deliberate: a test that only checks "we got a catalog back" passes just as
    happily when the catalog came from the fallback.
    """
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "test-service-token")
    monkeypatch.delenv("AISOC_CONNECTORS_SERVICE_TOKEN", raising=False)

    fake_schemas = [{"connector_id": "splunk", "category": "siem", "fields": []}]
    client_instance = MagicMock()
    client_instance.get = AsyncMock(return_value=_mock_response(200, {"schemas": fake_schemas}))
    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=None)

    with patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=client_cm):
        result = await _fetch_catalog(_TENANT)

    assert result.source == "live"
    headers = client_instance.get.await_args.kwargs["headers"]
    assert headers["Authorization"] == "Bearer test-service-token"
    assert headers["X-AiSOC-Tenant-ID"] == str(_TENANT)


def test_catalog_headers_prefer_the_connectors_specific_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Per-service override wins over the shared platform token."""
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "shared")
    monkeypatch.setenv("AISOC_CONNECTORS_SERVICE_TOKEN", "specific")
    assert _catalog_headers(_TENANT)["Authorization"] == "Bearer specific"


def test_catalog_headers_still_assert_the_tenant_without_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """No token configured: send the tenant anyway, never a blank credential.

    A dev-mode connectors service accepts the call; a production one fails
    closed, which is the correct outcome for a deployment that never
    configured a service token. Sending ``Bearer `` would be neither.
    """
    monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)
    monkeypatch.delenv("AISOC_CONNECTORS_SERVICE_TOKEN", raising=False)
    headers = _catalog_headers(_TENANT)
    assert "Authorization" not in headers
    assert headers["X-AiSOC-Tenant-ID"] == str(_TENANT)


@pytest.mark.asyncio
async def test_unknown_type_is_503_not_422_when_the_catalog_is_degraded() -> None:
    """ "I could not look it up" must not be reported as "it does not exist".

    A connectors service rolled forward ahead of this API image legitimately
    knows connector types the bundled catalog does not. Answering 422
    "unknown connector_type" sends the operator to debug a connector that is
    fine — which is exactly what the stale bundle did, on every request, for
    58 connectors.
    """
    client_instance = MagicMock()
    client_instance.get = AsyncMock(side_effect=httpx.ConnectError("connection refused"))
    client_cm = MagicMock()
    client_cm.__aenter__ = AsyncMock(return_value=client_instance)
    client_cm.__aexit__ = AsyncMock(return_value=None)
    with (
        patch("app.api.v1.endpoints.connectors.httpx.AsyncClient", return_value=client_cm),
        patch(
            "app.api.v1.endpoints.connectors._load_fallback_catalog",
            return_value=[{"connector_id": "splunk", "category": "siem"}],
        ),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _validate_connector_type("a_newer_connector", _TENANT)
    assert exc_info.value.status_code == 503
    assert "unreachable" in exc_info.value.detail


@pytest.mark.asyncio
async def test_unknown_type_is_422_when_the_bundle_is_authoritative(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no connectors service deployed, the bundle *is* the source of truth.

    That deployment is not degraded and 422 is the honest answer, so the
    503 above must not swallow the real rejection.
    """
    monkeypatch.setattr(settings, "CONNECTORS_SERVICE_URL", "", raising=False)
    with patch(
        "app.api.v1.endpoints.connectors._load_fallback_catalog",
        return_value=[{"connector_id": "splunk", "category": "siem"}],
    ):
        with pytest.raises(HTTPException) as exc_info:
            await _validate_connector_type("not_a_real_connector", _TENANT)
    assert exc_info.value.status_code == 422
    assert "splunk" in exc_info.value.detail


def test_bundled_catalog_is_well_formed_and_covers_more_than_a_sample() -> None:
    """The artefact the image ships is a real catalog, not a stub.

    Deliberately a floor rather than an exact count — the exact number is the
    generator's business, gated by
    ``scripts/generate_connector_catalog_fallback.py --check``. What this
    catches is the artefact silently becoming a placeholder again, which is
    the shape it was in: a 26-entry subset that looked like a catalog.
    """
    bundled = _load_fallback_catalog()
    assert len(bundled) >= 80, f"bundled catalog has only {len(bundled)} entries; regenerate it"
    assert all(isinstance(e.get("connector_id"), str) and e["connector_id"] for e in bundled)
    assert len({e["connector_id"] for e in bundled}) == len(bundled), "duplicate connector_id in the bundled catalog"


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
