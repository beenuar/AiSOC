"""Wazuh indexer reads are followed through ``search_after`` to the window's end.

OpenSearch (which the Wazuh indexer is) documents ``search_after`` as the
live-pagination mechanism for sorted queries: the request repeats with the
previous page's last ``sort`` values, and the sort needs a tiebreaker to be a
total order. Before #1820 the connector sent one ``size: 1000`` request and
stopped, so a window holding more hits than one page lost the overflow for
good — the next poll's window opens where this one closed, and nothing ever
asked for the rest again.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from app.connectors import wazuh
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.wazuh import WazuhConnector

PAGE = 1000


def _hit(i: int) -> dict[str, Any]:
    return {
        "_id": f"doc-{i}",
        "_source": {
            "rule": {"level": 8, "id": "5710", "description": f"alert {i}"},
            "agent": {"name": "host-1", "id": "001"},
            "@timestamp": "2026-11-11T00:00:00.000Z",
        },
        "sort": [1762800000000 + i, i],
    }


def _page_body(hits: list[dict[str, Any]]) -> dict[str, Any]:
    return {"hits": {"total": {"value": len(hits)}, "hits": hits}}


def _connector(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
    **kwargs: Any,
) -> WazuhConnector:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **client_kwargs: Any) -> httpx.AsyncClient:
        client_kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **client_kwargs)

    monkeypatch.setattr(wazuh.httpx, "AsyncClient", factory)
    defaults: dict[str, Any] = {
        "indexer_url": "https://indexer.example:9200",
        "username": "aisoc",
        "password": "secret",  # noqa: S106 — test credential
        "vuln_mode": "alerts",
    }
    defaults.update(kwargs)
    return WazuhConnector(**defaults)


def _requests_log() -> tuple[list[dict[str, Any]], Callable[[httpx.Request], httpx.Response]]:
    """A handler serving three full pages then a short one, logging bodies."""
    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        seen.append(body)
        page_number = len(seen) - 1
        if page_number < 3:
            start = page_number * PAGE
            return httpx.Response(200, json=_page_body([_hit(i) for i in range(start, start + PAGE)]))
        return httpx.Response(200, json=_page_body([_hit(3 * PAGE)]))

    return seen, handler


@pytest.mark.asyncio
async def test_window_is_read_to_the_end(monkeypatch: pytest.MonkeyPatch) -> None:
    seen, handler = _requests_log()
    connector = _connector(monkeypatch, handler)

    alerts = await connector.fetch_alerts(since_seconds=300)

    assert len(alerts) == 3 * PAGE + 1
    assert len(seen) == 4
    # Every follow-up request carries the previous page's last sort values.
    assert "search_after" not in seen[0]
    for page_number in (1, 2, 3):
        previous_last = (page_number * PAGE) - 1
        assert seen[page_number]["search_after"] == [1762800000000 + previous_last, previous_last]


@pytest.mark.asyncio
async def test_sort_gains_a_doc_tiebreaker(monkeypatch: pytest.MonkeyPatch) -> None:
    seen, handler = _requests_log()
    connector = _connector(monkeypatch, handler)

    await connector.fetch_alerts(since_seconds=300)

    sort = seen[0]["sort"]
    assert sort[0] == {"@timestamp": {"order": "asc"}}
    assert {"_doc": {"order": "asc"}} in sort


@pytest.mark.asyncio
async def test_short_first_page_is_one_request(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_page_body([_hit(0), _hit(1)]))

    connector = _connector(monkeypatch, handler)
    alerts = await connector.fetch_alerts(since_seconds=300)

    assert len(alerts) == 2
    assert calls == 1


@pytest.mark.asyncio
async def test_failed_later_page_keeps_what_was_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        if "search_after" not in body:
            return httpx.Response(200, json=_page_body([_hit(i) for i in range(PAGE)]))
        return httpx.Response(503, text="indexer restarting")

    connector = _connector(monkeypatch, handler)
    alerts = await connector.fetch_alerts(since_seconds=300)

    assert len(alerts) == PAGE


@pytest.mark.asyncio
async def test_transport_error_on_later_page_keeps_what_was_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        if "search_after" not in body:
            return httpx.Response(200, json=_page_body([_hit(i) for i in range(PAGE)]))
        raise httpx.ConnectError("boom", request=request)

    connector = _connector(monkeypatch, handler)
    alerts = await connector.fetch_alerts(since_seconds=300)

    assert len(alerts) == PAGE


@pytest.mark.asyncio
async def test_opening_failure_still_returns_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    connector = _connector(monkeypatch, handler)
    assert await connector.fetch_alerts(since_seconds=300) == []


@pytest.mark.asyncio
async def test_full_page_without_sort_values_stops_safely(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        hits = [{k: v for k, v in _hit(i).items() if k != "sort"} for i in range(PAGE)]
        return httpx.Response(200, json=_page_body(hits))

    connector = _connector(monkeypatch, handler)
    alerts = await connector.fetch_alerts(since_seconds=300)

    # Kept the page, refused to loop on a read it cannot continue safely.
    assert len(alerts) == PAGE
    assert calls == 1


@pytest.mark.asyncio
async def test_page_cap_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        start = calls * PAGE
        calls += 1
        return httpx.Response(200, json=_page_body([_hit(i) for i in range(start, start + PAGE)]))

    connector = _connector(monkeypatch, handler)
    alerts = await connector.fetch_alerts(since_seconds=300)

    assert calls == DEFAULT_MAX_PAGES
    assert len(alerts) == DEFAULT_MAX_PAGES * PAGE


@pytest.mark.asyncio
async def test_vulnerability_findings_also_page(monkeypatch: pytest.MonkeyPatch) -> None:
    def vuln_hit(i: int) -> dict[str, Any]:
        hit = _hit(i)
        hit["_source"]["rule"]["groups"] = ["vulnerability-detector"]
        hit["_source"]["data"] = {"vulnerability": {"cve": f"CVE-2026-{1000 + i}", "severity": "High"}}
        return hit

    seen: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode())
        seen.append(body)
        if "search_after" not in body:
            return httpx.Response(200, json=_page_body([vuln_hit(i) for i in range(PAGE)]))
        return httpx.Response(200, json=_page_body([vuln_hit(PAGE)]))

    connector = _connector(monkeypatch, handler, vuln_mode="inventory")
    findings = await connector.fetch_vulnerability_findings(since_seconds=3600)

    assert len(seen) == 2
    assert len(findings) == PAGE + 1
