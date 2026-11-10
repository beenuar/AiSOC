"""Datadog Cloud SIEM signals are read to the end of the poll window.

https://docs.datadoghq.com/api/latest/security-monitoring/#get-a-quick-list-of-security-signals
  ``GET /api/v2/security_monitoring/signals`` caps a response at ``page[limit]``
  and returns ``meta.page.after``: "The cursor used to get the next results, if
  any. To make the next request, use the same parameters with the addition of
  the ``page[cursor]``." The published OpenAPI document declares the same
  contract as ``x-pagination: {cursorParam: page[cursor], cursorPath:
  meta.page.after, resultsPath: data}``, and Datadog's generated clients end
  that read on an empty page or an absent cursor.

The connector asks for ``sort=-timestamp``, so a window holding more signals
than one page loses its oldest ones, and because the next poll's window opens
where this one closed, nothing ever asks for them again.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import datadog_cloud_siem
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.datadog_cloud_siem import DatadogCloudSIEMConnector


def _signals(start: int, count: int) -> list[dict[str, Any]]:
    return [{"id": f"signal-{i}", "type": "signal", "attributes": {"severity": "high", "title": "t"}} for i in range(start, start + count)]


def _connector(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> DatadogCloudSIEMConnector:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(datadog_cloud_siem.httpx, "AsyncClient", factory)
    return DatadogCloudSIEMConnector(site="eu1", api_key="api", application_key="app")


def _body(signals: list[dict[str, Any]], after: Any) -> dict[str, Any]:
    return {"data": signals, "links": {"next": ""}, "meta": {"page": {"after": after}}}


@pytest.mark.asyncio
async def test_every_page_of_a_busy_window_arrives(monkeypatch: pytest.MonkeyPatch) -> None:
    """Datadog cursors are base64, so this also proves ``+``, ``/`` and ``=`` survive being sent back."""
    total = 250
    cursors: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("page[cursor]")
        cursors.append(cursor)
        start = int(cursor.split("/")[1].rstrip("=")) if cursor else 0
        following = start + 100
        after = f"eyJ+/{following}==" if following < total else None
        return httpx.Response(200, json=_body(_signals(start, min(100, total - start)), after))

    out = await _connector(monkeypatch, handler).fetch_alerts()

    assert cursors == [None, "eyJ+/100==", "eyJ+/200=="]
    assert sorted(row["alert_id"] for row in out) == sorted(f"signal-{i}" for i in range(total))


@pytest.mark.asyncio
async def test_every_request_of_the_read_keeps_the_window_the_order_and_the_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_body(_signals(len(seen), 1), None if len(seen) == 2 else "next"))

    await _connector(monkeypatch, handler).fetch_alerts()

    assert len(seen) == 2
    assert all(request.url.host == "api.datadoghq.eu" for request in seen)
    assert all(request.url.path == "/api/v2/security_monitoring/signals" for request in seen)
    assert seen[0].url.params["filter[from]"] == seen[1].url.params["filter[from]"]
    assert [request.url.params["sort"] for request in seen] == ["-timestamp", "-timestamp"]
    assert [request.url.params["page[limit]"] for request in seen] == ["100", "100"]
    assert all(request.headers["dd-api-key"] == "api" and request.headers["dd-application-key"] == "app" for request in seen)


@pytest.mark.asyncio
async def test_a_short_page_with_a_cursor_is_not_the_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """The cursor ends the collection, not the page length."""
    pages = iter([_body(_signals(0, 3), "more"), _body(_signals(3, 2), None)])

    out = await _connector(monkeypatch, lambda request: httpx.Response(200, json=next(pages))).fetch_alerts()

    assert len(out) == 5


@pytest.mark.parametrize(
    "ending",
    [
        {"data": _signals(0, 1), "meta": {"page": {"after": ""}}},
        {"data": _signals(0, 1), "meta": {"page": {"after": None}}},
        {"data": _signals(0, 1), "meta": {"page": {}}},
        {"data": _signals(0, 1), "meta": {}},
        {"data": _signals(0, 1)},
    ],
    ids=["empty", "null", "absent", "no-page", "no-meta"],
)
@pytest.mark.asyncio
async def test_each_end_of_collection_stops_the_read(monkeypatch: pytest.MonkeyPatch, ending: dict[str, Any]) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=ending)

    out = await _connector(monkeypatch, handler).fetch_alerts()

    assert calls == 1
    assert len(out) == 1


@pytest.mark.asyncio
async def test_an_empty_page_ends_the_read_even_beside_a_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    """Datadog's own clients stop here, so the cursor is not a promise of more and the page cap is not spent."""
    pages = iter([_body(_signals(0, 100), "more"), _body([], "still-more")])
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=next(pages))

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, handler).fetch_alerts()

    assert calls == 2
    assert len(out) == 100
    assert "connector.paging.page_cap_reached" not in [log["event"] for log in logs]


@pytest.mark.asyncio
async def test_a_rate_limit_on_a_later_page_keeps_what_was_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "page[cursor]" in request.url.params:
            return httpx.Response(429, json={"errors": ["Rate limit exceeded"]})
        return httpx.Response(200, json=_body(_signals(0, 100), "more"))

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, handler).fetch_alerts()

    assert len(out) == 100, "a failure on page two is not a reason to discard page one"
    assert [log["status"] for log in logs if log["event"] == "connector.paging.token_page_failed"] == [429]


@pytest.mark.asyncio
async def test_a_refused_opening_request_is_logged_and_returns_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, lambda request: httpx.Response(403, json={"errors": ["Forbidden"]})).fetch_alerts()

    assert out == []
    assert [log["status"] for log in logs if log["event"] == "connector.paging.token_page_failed"] == [403]


@pytest.mark.asyncio
async def test_a_cursor_that_never_ends_is_bounded_and_announced(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_body(_signals(calls, 1), "again"))

    with structlog.testing.capture_logs() as logs:
        await _connector(monkeypatch, handler).fetch_alerts()

    assert calls == DEFAULT_MAX_PAGES
    assert "connector.paging.page_cap_reached" in [log["event"] for log in logs]
