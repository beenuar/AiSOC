"""SentinelOne threat polling follows the API's cursor pagination."""

from __future__ import annotations

import httpx
import pytest
from app.connectors import sentinelone
from app.connectors.sentinelone import SentinelOneConnector


def _threat(i: int) -> dict:
    return {
        "id": f"t-{i}",
        "threatInfo": {"threatName": f"threat-{i}", "confidenceLevel": "High"},
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
