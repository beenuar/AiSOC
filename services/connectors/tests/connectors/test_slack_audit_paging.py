"""Slack audit logs are read to the end of the poll window.

https://docs.slack.dev/apis/web-api/pagination
  Set "the ``cursor`` parameter equal to the ``next_cursor`` value you received
  on the last request". An "empty, null, or non-existent ``next_cursor``" means
  there are no further results, and "it's possible to receive *fewer* results
  than your specified ``limit``, even when there are additional results to
  retrieve".

https://docs.slack.dev/reference/audit-logs-api/methods-actions-reference
  Results default to descending order, "most to least recent".

So a connector reading only the first response loses the oldest entries of a
busy window, and because the next poll's window opens where this one closed,
nothing ever asks for them again.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import slack_audit
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.slack_audit import SlackAuditConnector


def _entries(start: int, count: int) -> list[dict[str, Any]]:
    return [{"id": f"entry-{i}", "date_create": 4070908800, "action": "user_login"} for i in range(start, start + count)]


def _connector(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> SlackAuditConnector:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(slack_audit.httpx, "AsyncClient", factory)
    return SlackAuditConnector(access_token="tok")


def _body(entries: list[dict[str, Any]], next_cursor: Any) -> dict[str, Any]:
    return {"entries": entries, "response_metadata": {"next_cursor": next_cursor}}


@pytest.mark.asyncio
async def test_every_page_of_a_busy_window_arrives(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cursors end in ``=``, so this also proves one survives being sent back."""
    total = 450
    cursors: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        cursor = request.url.params.get("cursor")
        cursors.append(cursor)
        start = int(cursor.rstrip("=")) if cursor else 0
        following = start + 200
        return httpx.Response(200, json=_body(_entries(start, min(200, total - start)), f"{following}=" if following < total else ""))

    out = await _connector(monkeypatch, handler).fetch_alerts()

    assert cursors == [None, "200=", "400="]
    assert sorted(row["external_id"] for row in out) == sorted(f"entry-{i}" for i in range(total))


@pytest.mark.asyncio
async def test_every_request_of_the_read_keeps_the_window_and_the_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_body(_entries(0, 1), "" if len(seen) == 2 else "next"))

    await _connector(monkeypatch, handler).fetch_alerts()

    assert seen[0].url.params["oldest"] == seen[1].url.params["oldest"]
    assert seen[1].url.params["limit"] == "200"
    assert all(request.headers["authorization"] == "Bearer tok" for request in seen)


@pytest.mark.asyncio
async def test_a_short_page_with_a_cursor_is_not_the_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """Slack says this happens, and a client testing ``len(page) < limit`` would stop early."""
    pages = iter([_body(_entries(0, 3), "more"), _body(_entries(3, 2), "")])

    out = await _connector(monkeypatch, lambda request: httpx.Response(200, json=next(pages))).fetch_alerts()

    assert len(out) == 5


@pytest.mark.parametrize(
    "ending",
    [
        {"entries": _entries(0, 1), "response_metadata": {"next_cursor": ""}},
        {"entries": _entries(0, 1), "response_metadata": {"next_cursor": None}},
        {"entries": _entries(0, 1), "response_metadata": {}},
        {"entries": _entries(0, 1)},
    ],
    ids=["empty", "null", "absent", "no-metadata"],
)
@pytest.mark.asyncio
async def test_each_documented_end_of_collection_stops_the_read(monkeypatch: pytest.MonkeyPatch, ending: dict[str, Any]) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=ending)

    out = await _connector(monkeypatch, handler).fetch_alerts()

    assert calls == 1
    assert len(out) == 1


@pytest.mark.asyncio
async def test_a_rate_limit_on_a_later_page_keeps_what_was_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "cursor" in request.url.params:
            return httpx.Response(429, text="ratelimited")
        return httpx.Response(200, json=_body(_entries(0, 200), "more"))

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, handler).fetch_alerts()

    assert len(out) == 200, "a failure on page two is not a reason to discard page one"
    assert [log["status"] for log in logs if log["event"] == "connector.paging.token_page_failed"] == [429]


@pytest.mark.asyncio
async def test_a_refused_opening_request_is_logged_and_returns_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, lambda request: httpx.Response(403, text="missing_scope")).fetch_alerts()

    assert out == []
    assert [log["status"] for log in logs if log["event"] == "connector.paging.token_page_failed"] == [403]


@pytest.mark.asyncio
async def test_a_cursor_that_never_ends_is_bounded_and_announced(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_body(_entries(calls, 1), "again"))

    with structlog.testing.capture_logs() as logs:
        await _connector(monkeypatch, handler).fetch_alerts()

    assert calls == DEFAULT_MAX_PAGES
    assert "connector.paging.page_cap_reached" in [log["event"] for log in logs]
