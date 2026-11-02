"""Auth0 log polling reads every page of the poll window."""

from __future__ import annotations

import httpx
import pytest
from app.connectors import auth0
from app.connectors.auth0 import Auth0Connector


def _log(i: int) -> dict:
    return {"log_id": f"log-{i}", "type": "s", "date": "2099-01-01T00:00:00.000Z", "user_name": f"user{i}@example.com"}


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # noqa: ANN001
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(auth0.httpx, "AsyncClient", factory)


def _connector() -> Auth0Connector:
    return Auth0Connector(domain="tenant.example.auth0.com", client_id="id", client_secret="secret")  # noqa: S106 — test


@pytest.mark.asyncio
async def test_fetch_alerts_reads_every_page(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {"0": [_log(i) for i in range(100)], "1": [_log(i) for i in range(100, 200)], "2": [_log(i) for i in range(200, 240)]}
    seen_pages: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        page = request.url.params["page"]
        seen_pages.append(page)
        return httpx.Response(200, json=pages[page])

    _patch_client(monkeypatch, handler)
    out = await _connector().fetch_alerts()

    assert seen_pages == ["0", "1", "2"]
    assert len(out) == 240


@pytest.mark.asyncio
async def test_fetch_alerts_stops_at_the_search_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    seen_pages: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth/token":
            return httpx.Response(200, json={"access_token": "tok"})
        seen_pages.append(request.url.params["page"])
        return httpx.Response(200, json=[_log(i) for i in range(100)])

    _patch_client(monkeypatch, handler)
    out = await _connector().fetch_alerts()

    # Auth0 lets a search page through at most 1,000 results.
    assert len(seen_pages) == 10
    assert len(out) == 1000
