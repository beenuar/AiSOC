"""Trend Vision One workbench alerts and OAT detections are read to the end of the poll window.

Both ``GET /v3.0/workbench/alerts`` and ``GET /v3.0/oat/detections`` answer a
capped page of ``items`` plus ``nextLink``, the complete URL of the next page
(``.../v3.0/workbench/alerts?skipToken=...``). Trend's own clients keep
requesting that URL, unchanged and with the same headers, until a response no
longer carries one: ``get_items`` in Trend's API cookbook
(https://github.com/trendmicro/tm-v1-api-cookbook) and ``_consume_linkable``
in the ``pytmv1`` SDK (https://pypi.org/project/pytmv1/), whose
``ListAlertsResp`` and ``ListOatsResp`` both carry ``next_link``. Trend's API
mock serves exactly that shape for the alert list.

The connector read only the first response of each feed, and because the next
poll's window opens where this one closed, whatever did not fit was never
requested again.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import trend_vision_one
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.trend_vision_one import TrendVisionOneConnector

_WORKBENCH = "/v3.0/workbench/alerts"


def _items(prefix: str, start: int, count: int) -> list[dict[str, Any]]:
    return [{"id": f"{prefix}-{i}", "severity": "high", "model": "m"} for i in range(start, start + count)]


def _connector(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> TrendVisionOneConnector:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(trend_vision_one.httpx, "AsyncClient", factory)
    return TrendVisionOneConnector(region="eu", api_token="tok")  # noqa: S106 — test


def _paged(prefix: str, total: int, request: httpx.Request) -> httpx.Response:
    """Serve ``total`` rows 100 at a time behind a ``skipToken`` link, as Trend's mock does."""
    start = int(request.url.params.get("skipToken", "0"))
    body: dict[str, Any] = {"totalCount": total, "count": min(100, total - start), "items": _items(prefix, start, min(100, total - start))}
    if start + 100 < total:
        body["nextLink"] = f"https://{request.url.host}{request.url.path}?skipToken={start + 100}"
    return httpx.Response(200, json=body)


def _single(prefix: str) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(200, json={"items": _items(prefix, 0, 1)})


def _route(
    workbench: Callable[[httpx.Request], httpx.Response],
    oat: Callable[[httpx.Request], httpx.Response],
) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        return workbench(request) if request.url.path == _WORKBENCH else oat(request)

    return handler


@pytest.mark.asyncio
async def test_every_page_of_both_feeds_arrives(monkeypatch: pytest.MonkeyPatch) -> None:
    """250 workbench alerts and 130 OAT detections in one window arrive in full, not the first 100 of each."""
    out = await _connector(
        monkeypatch,
        _route(lambda request: _paged("wb", 250, request), lambda request: _paged("oat", 130, request)),
    ).fetch_alerts()

    assert sorted(row["alert_id"] for row in out) == sorted([f"wb-{i}" for i in range(250)] + [f"oat-{i}" for i in range(130)])
    assert {row["raw_event"]["_aisoc_stream"] for row in out if row["alert_id"].startswith("wb-")} == {"workbench"}
    assert {row["raw_event"]["_aisoc_stream"] for row in out if row["alert_id"].startswith("oat-")} == {"oat"}


@pytest.mark.asyncio
async def test_the_next_link_is_requested_verbatim_on_the_region_host_with_the_token(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def workbench(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _paged("wb", 150, request)

    await _connector(monkeypatch, _route(workbench, _single("oat"))).fetch_alerts()

    assert len(seen) == 2
    assert str(seen[1].url) == "https://api.eu.xdr.trendmicro.com/v3.0/workbench/alerts?skipToken=100"
    assert seen[0].url.params["orderBy"] == "createdDateTime"
    assert "startDateTime" in seen[0].url.params
    assert all(request.headers["authorization"] == "Bearer tok" for request in seen)


@pytest.mark.parametrize("ending", [{}, {"nextLink": ""}, {"nextLink": None}], ids=["absent", "empty", "null"])
@pytest.mark.asyncio
async def test_each_end_of_collection_stops_the_read(monkeypatch: pytest.MonkeyPatch, ending: dict[str, Any]) -> None:
    calls = 0

    def workbench(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"items": _items("wb", 0, 1), **ending})

    out = await _connector(monkeypatch, _route(workbench, _single("oat"))).fetch_alerts()

    assert calls == 1
    assert len(out) == 2


@pytest.mark.asyncio
async def test_a_rate_limit_on_a_later_page_keeps_what_was_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def workbench(request: httpx.Request) -> httpx.Response:
        if "skipToken" in request.url.params:
            return httpx.Response(429, json={"error": {"code": "TooManyRequests"}})
        return _paged("wb", 300, request)

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, _route(workbench, _single("oat"))).fetch_alerts()

    assert len(out) == 101, "a failure on page two is not a reason to discard page one, or the other feed"
    assert [(log["feed"], log["status"]) for log in logs if log["event"] == "connector.paging.next_page_failed"] == [
        ("trend_vision_one.workbench", 429)
    ]


@pytest.mark.parametrize(("failing", "surviving"), [("workbench", "oat"), ("oat", "workbench")])
@pytest.mark.asyncio
async def test_a_refused_opening_request_is_logged_and_the_other_feed_is_still_read(
    monkeypatch: pytest.MonkeyPatch, failing: str, surviving: str
) -> None:
    """Either refusal is named in the log; a refused OAT request used to be dropped without one."""

    def refused(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"code": "AccessDenied"}})

    handlers = {"workbench": _single("wb"), "oat": _single("oat"), failing: refused}

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, _route(handlers["workbench"], handlers["oat"])).fetch_alerts()

    assert [row["raw_event"]["_aisoc_stream"] for row in out] == [surviving]
    assert [(log["stream"], log["status"]) for log in logs if log["event"] == "trend_vision_one.feed_failed"] == [(failing, 403)]


@pytest.mark.asyncio
async def test_a_transport_error_on_one_feed_does_not_lose_the_other(monkeypatch: pytest.MonkeyPatch) -> None:
    def workbench(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, _route(workbench, _single("oat"))).fetch_alerts()

    assert [row["alert_id"] for row in out] == ["oat-0"]
    assert [log["stream"] for log in logs if log["event"] == "trend_vision_one.feed_exception"] == ["workbench"]


@pytest.mark.asyncio
async def test_a_link_that_never_ends_is_bounded_and_announced(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def workbench(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            200, json={"items": _items("wb", calls, 1), "nextLink": f"https://{request.url.host}{_WORKBENCH}?skipToken={calls}"}
        )

    with structlog.testing.capture_logs() as logs:
        await _connector(monkeypatch, _route(workbench, _single("oat"))).fetch_alerts()

    assert calls == DEFAULT_MAX_PAGES
    assert [log["feed"] for log in logs if log["event"] == "connector.paging.page_cap_reached"] == ["trend_vision_one.workbench"]
