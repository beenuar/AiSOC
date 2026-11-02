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

import json
import uuid

import httpx
import pytest
from app.ingest_client import MAX_BATCH_SIZE, IngestClient, IngestClientError, resolve_service_token

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


def _events(n: int) -> list[dict[str, str]]:
    return [{"severity": "high", "title": f"event-{i}"} for i in range(n)]


def _batch_size(request: httpx.Request) -> int:
    body = json.loads(request.read().decode("utf-8"))
    return len(body["events"])


@pytest.mark.asyncio
async def test_push_events_chunks_oversized_batches(monkeypatch: pytest.MonkeyPatch) -> None:
    """A poll larger than the ingest cap never produces an oversized request.

    The transport refuses any body over ``MAX_BATCH_SIZE`` with 413, which is
    what the ingest service does. Chunking has to stay under that cap, and
    the accepted/rejected counts have to be the sum across chunks so the
    scheduler can still tell whether every submitted event was accepted.
    """
    requests_seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        batch_size = _batch_size(request)
        requests_seen.append(batch_size)
        assert request.headers["authorization"] == "Bearer svc-secret"
        assert request.headers["x-tenant-id"] == str(TENANT)
        if batch_size > MAX_BATCH_SIZE:
            return httpx.Response(413, text=f"batch size exceeds maximum of {MAX_BATCH_SIZE}")
        # One rejection in the tail chunk, so the summed counts are not just
        # a copy of the event list length.
        rejected = 1 if batch_size < MAX_BATCH_SIZE else 0
        return httpx.Response(200, json={"accepted": batch_size - rejected, "rejected": rejected})

    client = _client(monkeypatch, handler, service_token="svc-secret")

    # 2500 is above the cap and not a round multiple, so the last chunk is a
    # short one. Without chunking the transport answers 413 and the push
    # raises; with it, the requests are 1000, 1000, and 500.
    result = await client.push_events(
        tenant_id=TENANT,
        connector_id=uuid.uuid4(),
        connector_type="sentinelone",
        events=_events(2500),
    )

    assert requests_seen == [MAX_BATCH_SIZE, MAX_BATCH_SIZE, 500]
    assert all(size <= MAX_BATCH_SIZE for size in requests_seen)
    assert result["accepted"] == 2499
    assert result["rejected"] == 1


@pytest.mark.asyncio
async def test_push_events_does_not_chunk_when_under_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    """A batch already within the cap is one request."""
    requests_seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        batch_size = _batch_size(request)
        requests_seen.append(batch_size)
        return httpx.Response(200, json={"accepted": batch_size, "rejected": 0})

    client = _client(monkeypatch, handler, service_token="svc-secret")
    result = await client.push_events(
        tenant_id=TENANT,
        connector_id=uuid.uuid4(),
        connector_type="dropbox",
        events=_events(MAX_BATCH_SIZE),
    )

    assert result == {"accepted": MAX_BATCH_SIZE, "rejected": 0}
    assert requests_seen == [MAX_BATCH_SIZE]


@pytest.mark.asyncio
async def test_chunk_that_is_still_too_large_is_a_hard_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 413 on one chunk aborts the push.

    Chunking only splits at the client's cap. If a chunk is still too large
    for the ingest service, the refusal has to surface as ``IngestClientError``
    rather than being retried or dropped — otherwise the server-side guard
    stops meaning anything.
    """
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        batch_size = _batch_size(request)
        assert batch_size <= MAX_BATCH_SIZE
        if calls == 2:
            return httpx.Response(413, text="batch size exceeds maximum of 1000")
        return httpx.Response(200, json={"accepted": batch_size, "rejected": 0})

    client = _client(monkeypatch, handler, service_token="svc-secret")
    with pytest.raises(IngestClientError) as excinfo:
        await client.push_events(
            tenant_id=TENANT,
            connector_id=uuid.uuid4(),
            connector_type="dropbox",
            events=_events(MAX_BATCH_SIZE + 1),
        )

    assert "413" in str(excinfo.value)
    assert calls == 2
