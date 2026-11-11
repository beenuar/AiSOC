"""An unavailable risk engine is not an empty queue, zero count, or absent host."""

import uuid

import httpx
import pytest
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import fusion
from fastapi import FastAPI

TENANT = uuid.UUID("00000000-0000-0000-0000-000000000111")


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["queue", "stats", "host/WS-42"])
@pytest.mark.parametrize("mode", ["unconfigured", "timeout", "upstream_error"])
async def test_unavailable_is_503(monkeypatch, path, mode):
    app = FastAPI()
    app.include_router(fusion.router, prefix="/api/v1")
    app.dependency_overrides[get_current_user] = lambda: CurrentUser(uuid.uuid4(), TENANT, "analyst", "analyst@example.test")
    monkeypatch.setattr(fusion, "_FUSION_URL", "" if mode == "unconfigured" else "http://fusion.test")
    real = httpx.AsyncClient

    async def handler(req):
        if mode == "timeout":
            raise httpx.ReadTimeout("unavailable")
        return httpx.Response(503)

    class Client(real):
        def __init__(self, *a, **kw):
            kw.setdefault("transport", httpx.MockTransport(handler))
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    async with real(transport=httpx.ASGITransport(app), base_url="http://api.test") as client:
        result = await client.get("/api/v1/fusion/entity-risk/" + path)
    assert result.status_code == 503, result.text


@pytest.mark.asyncio
@pytest.mark.parametrize("status, body", [(200, {"entities": []}), (404, {"detail": "entity_not_found"})])
async def test_real_empty_and_real_absence_are_preserved(monkeypatch, status, body):
    monkeypatch.setattr(fusion, "_FUSION_URL", "http://fusion.test")
    real = httpx.AsyncClient

    async def handler(req):
        return httpx.Response(status, json=body)

    class Client(real):
        def __init__(self, *a, **kw):
            kw["transport"] = httpx.MockTransport(handler)
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", Client)
    from fastapi import HTTPException

    if status == 404:
        with pytest.raises(HTTPException) as exc:
            await fusion._proxy_get("/entity-risk/host/WS-42")
        assert exc.value.status_code == 404
    else:
        assert await fusion._proxy_get("/entity-risk/queue") == body
