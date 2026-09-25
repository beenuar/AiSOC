"""The connector-poll push has to present a credential and declare a tenant.

``/v1/ingest`` no longer takes the caller's word for which tenant a batch
belongs to. This process pushes for every tenant it polls, so it holds the
shared service token rather than a per-tenant one, and the tenant it is
acting for travels on ``X-Tenant-ID`` where the ingest service intersects
it with what the credential authorises.

Both halves matter and both are asserted here: a push with no Authorization
header is refused at the far end, and a push that omits the tenant header
resolves to an empty scope there. Either omission is silent on this side —
the request goes out looking fine — which is why the test inspects the
headers that were actually sent rather than only the return value.
"""

from __future__ import annotations

import uuid

import httpx
import pytest
from app.ingest_client import IngestClient, IngestClientError, resolve_service_token

TENANT = uuid.UUID("11111111-1111-4111-8111-111111111111")


def _client(monkeypatch: pytest.MonkeyPatch, handler, **kwargs) -> IngestClient:
    """An IngestClient whose transport records what it was asked to send."""
    client = IngestClient("http://ingest-worker:8080", **kwargs)
    monkeypatch.setattr(
        client,
        "_get_client",
        lambda: _async_client(handler),
    )
    return client


async def _async_client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.mark.asyncio
async def test_push_presents_the_service_token_and_declares_the_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"accepted": 1, "rejected": 0})

    client = _client(monkeypatch, handler, service_token="svc-secret")
    result = await client.push_events(
        tenant_id=TENANT,
        connector_id=uuid.uuid4(),
        connector_type="crowdstrike",
        events=[{"severity": "high", "title": "t"}],
    )

    assert result["accepted"] == 1
    assert seen["authorization"] == "Bearer svc-secret"
    assert seen["x-tenant-id"] == str(TENANT)


@pytest.mark.asyncio
async def test_push_without_a_token_sends_no_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    # The client does not invent a credential, and does not fall back to an
    # unauthenticated push that looks successful. It sends what it has; the
    # ingest service refuses it.
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(401, text='{"error":"missing ingest credential"}')

    client = _client(monkeypatch, handler, service_token="")
    with pytest.raises(IngestClientError) as excinfo:
        await client.push_events(
            tenant_id=TENANT,
            connector_id=uuid.uuid4(),
            connector_type="crowdstrike",
            events=[{"severity": "high", "title": "t"}],
        )

    assert "authorization" not in seen
    # The error has to name the fix. A bare "401" sends an operator to the
    # connector's own credentials, which are not the problem.
    assert "AISOC_SERVICE_TOKEN" in str(excinfo.value)


def test_service_token_precedence_matches_the_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AISOC_INGEST_SERVICE_TOKEN", raising=False)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "shared")
    assert resolve_service_token() == "shared"

    monkeypatch.setenv("AISOC_INGEST_SERVICE_TOKEN", "specific")
    assert resolve_service_token() == "specific"

    monkeypatch.setenv("AISOC_INGEST_SERVICE_TOKEN", "")
    assert resolve_service_token() == "shared"

    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "")
    assert resolve_service_token() == ""
