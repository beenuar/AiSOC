"""Cisco Umbrella activity polling reads every page of the poll window."""

from __future__ import annotations

import httpx
import pytest
from app.connectors import cisco_umbrella
from app.connectors.cisco_umbrella import CiscoUmbrellaConnector


def _event(i: int) -> dict:
    return {"domain": f"bad-{i}.example", "verdict": "blocked", "timestamp": 4070908800000 + i, "categories": []}


def _patch_client(monkeypatch: pytest.MonkeyPatch, handler) -> None:  # noqa: ANN001
    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(cisco_umbrella.httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_fetch_alerts_reads_every_page(monkeypatch: pytest.MonkeyPatch) -> None:
    events = [_event(i) for i in range(230)]
    seen_offsets: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        offset = request.url.params.get("offset")
        seen_offsets.append(offset)
        start = int(offset or 0)
        limit = int(request.url.params["limit"])
        return httpx.Response(200, json={"data": events[start : start + limit]})

    _patch_client(monkeypatch, handler)
    out = await CiscoUmbrellaConnector(api_key="k", api_secret="s").fetch_alerts()  # noqa: S106 — test

    assert seen_offsets == ["0", "100", "200"]
    assert len(out) == 230
