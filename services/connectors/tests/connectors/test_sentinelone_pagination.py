"""SentinelOne threat polling follows the API's cursor pagination."""

from __future__ import annotations

import httpx
import pytest
from app.connectors import sentinelone
from app.connectors.sentinelone import SentinelOneConnector


def _threat(i: int) -> dict:
    # ``confidenceLevel`` is spelled the way the vendor spells it. The threats
    # endpoint publishes ``malicious`` / ``suspicious`` / ``n/a``, not a
    # Low-High ladder, so a fixture saying "High" describes a response
    # SentinelOne never sends.
    return {
        "id": f"t-{i}",
        "threatInfo": {"threatName": f"threat-{i}", "confidenceLevel": "malicious"},
        "agentRealtimeInfo": {"agentComputerName": f"host-{i}"},
    }


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # noqa: ANN001
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(sentinelone.httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_fetch_alerts_reads_every_page(monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {
        None: ([_threat(i) for i in range(100)], "cursor-2"),
        "cursor-2": ([_threat(i) for i in range(100, 200)], "cursor-3"),
        "cursor-3": ([_threat(i) for i in range(200, 230)], None),
    }
    seen_cursors: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("cursor")
        seen_cursors.append(cursor)
        data, next_cursor = pages[cursor]
        return httpx.Response(200, json={"data": data, "pagination": {"nextCursor": next_cursor, "totalItems": 230}})

    _patch_client(monkeypatch, handler)
    out = await SentinelOneConnector(api_token="t", base_url="https://s1.example").fetch_alerts()  # noqa: S106 — test

    assert seen_cursors == [None, "cursor-2", "cursor-3"]
    assert len(out) == 230
    assert len({e["external_id"] for e in out}) == 230


@pytest.mark.asyncio
async def test_fetch_alerts_stops_without_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"data": [_threat(1)], "pagination": {"nextCursor": None}})

    _patch_client(monkeypatch, handler)
    out = await SentinelOneConnector(api_token="t", base_url="https://s1.example").fetch_alerts()  # noqa: S106 — test

    assert calls == 1
    assert [e["external_id"] for e in out] == ["t-1"]


@pytest.mark.asyncio
async def test_every_page_carries_the_same_filters(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only the cursor may change between pages.

    The parameters are what scope the sweep: ``createdAt__gte`` is the poll
    window and ``siteIds`` is the tenant's slice of the console. An edit that
    rebuilt the parameter dict per page instead of mutating one would drop
    both after page one, and the sweep would start returning threats from
    every other site in the account — a scope leak that reads as a working
    paginator, because the threat count goes up rather than down.
    """
    next_cursor = {None: "cursor-2", "cursor-2": None}
    seen: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.url.params))
        cursor = request.url.params.get("cursor")
        return httpx.Response(200, json={"data": [_threat(1)], "pagination": {"nextCursor": next_cursor[cursor]}})

    _patch_client(monkeypatch, handler)
    conn = SentinelOneConnector(api_token="t", base_url="https://s1.example", site_id="site-7")  # noqa: S106 — test
    await conn.fetch_alerts(since_seconds=900)

    assert len(seen) == 2, "expected a second request, otherwise there is nothing to compare across pages"
    first, second = seen
    assert "cursor" not in first, "the first request must not send a cursor"
    assert second["cursor"] == "cursor-2"
    assert first["siteIds"] == second["siteIds"] == "site-7"
    assert first["createdAt__gte"] == second["createdAt__gte"]
    assert {k: v for k, v in second.items() if k != "cursor"} == first
