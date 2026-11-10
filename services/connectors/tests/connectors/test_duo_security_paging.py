"""Duo authentication logs are read to the end of the poll window.

https://duo.com/docs/adminapi#authentication-logs
  "Returns a paged list of authentication log events ... To fetch all results,
  call repeatedly with the next_offset paging parameter as long as the result
  metadata has next_offset values." ``limit`` is "Default: 100; Max: 1000", and
  ``next_offset`` comes back as a 13-character millisecond timestamp and the
  event txid, to be sent with "both of these values ... separated by a comma".

A connector reading only the first response keeps 100 authentications of a
busy window, and because the next poll's window opens where this one closed,
nothing ever asks for the rest again.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import urllib.parse
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import duo_security
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.duo_security import DuoSecurityConnector

_IKEY = "DIXXXXXXXXXXXXXXXXXX"
_SKEY = "duo-secret"  # noqa: S105 — test
_HOST = "api-x.duosecurity.com"


def _entries(start: int, count: int) -> list[dict[str, Any]]:
    return [{"txid": f"tx-{i}", "result": "success", "user": {"name": "alice"}} for i in range(start, start + count)]


def _body(entries: list[dict[str, Any]], next_offset: Any = None) -> dict[str, Any]:
    metadata: dict[str, Any] = {"total_objects": len(entries)}
    if next_offset is not None:
        metadata["next_offset"] = next_offset
    return {"stat": "OK", "response": {"authlogs": entries, "metadata": metadata}}


def _connector(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> DuoSecurityConnector:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(duo_security.httpx, "AsyncClient", factory)
    return DuoSecurityConnector(integration_key=_IKEY, secret_key=_SKEY, api_hostname=_HOST)


def _signed_by_the_secret(request: httpx.Request) -> bool:
    """Verify the request the way Duo does: over the parameters it actually received."""
    received = sorted(urllib.parse.parse_qsl(request.url.query.decode()))
    canon = "\n".join(
        [
            request.headers["date"],
            request.method,
            request.url.host,
            request.url.path,
            "&".join(f"{urllib.parse.quote(k, '~')}={urllib.parse.quote(v, '~')}" for k, v in received),
        ]
    )
    expected = hmac.new(_SKEY.encode(), canon.encode(), hashlib.sha1).hexdigest()
    return request.headers["authorization"] == "Basic " + base64.b64encode(f"{_IKEY}:{expected}".encode()).decode()


@pytest.mark.asyncio
async def test_every_page_of_a_busy_window_arrives(monkeypatch: pytest.MonkeyPatch) -> None:
    total = 2500
    offsets: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        offset = request.url.params.get("next_offset")
        offsets.append(offset)
        start = int(offset.split(",")[1].removeprefix("tx-")) if offset else 0
        following = start + 1000
        next_offset = ["1767268800000", f"tx-{following}"] if following < total else None
        return httpx.Response(200, json=_body(_entries(start, min(1000, total - start)), next_offset))

    out = await _connector(monkeypatch, handler).fetch_alerts()

    assert offsets == [None, "1767268800000,tx-1000", "1767268800000,tx-2000"]
    assert sorted(row["external_id"] for row in out) == sorted(f"tx-{i}" for i in range(total))


@pytest.mark.asyncio
async def test_every_request_of_the_read_keeps_the_window_and_is_signed_for_its_own_parameters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_body(_entries(len(seen), 1), None if len(seen) == 2 else ["1767268800000", "tx-next"]))

    await _connector(monkeypatch, handler).fetch_alerts()

    assert len(seen) == 2
    assert seen[0].url.params["mintime"] == seen[1].url.params["mintime"]
    assert seen[0].url.params["maxtime"] == seen[1].url.params["maxtime"]
    assert [request.url.params["limit"] for request in seen] == ["1000", "1000"]
    assert "next_offset" not in seen[0].url.params
    assert all(_signed_by_the_secret(request) for request in seen), "Duo refuses a page whose signature omits next_offset"


@pytest.mark.asyncio
async def test_a_short_page_with_an_offset_is_not_the_end(monkeypatch: pytest.MonkeyPatch) -> None:
    """Duo ends the log by omitting next_offset, not by shortening a page."""
    pages = iter([_body(_entries(0, 3), ["1767268800000", "tx-3"]), _body(_entries(3, 2))])

    out = await _connector(monkeypatch, lambda request: httpx.Response(200, json=next(pages))).fetch_alerts()

    assert len(out) == 5


@pytest.mark.parametrize(
    "ending",
    [
        _body(_entries(0, 1)),
        {"stat": "OK", "response": {"authlogs": _entries(0, 1), "metadata": {"next_offset": None}}},
        {"stat": "OK", "response": {"authlogs": _entries(0, 1), "metadata": {"next_offset": []}}},
        {"stat": "OK", "response": {"authlogs": _entries(0, 1)}},
    ],
    ids=["absent", "null", "empty", "no-metadata"],
)
@pytest.mark.asyncio
async def test_each_end_of_the_log_stops_the_read(monkeypatch: pytest.MonkeyPatch, ending: dict[str, Any]) -> None:
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
        if "next_offset" in request.url.params:
            return httpx.Response(429, json={"stat": "FAIL", "code": 42901, "message": "Too Many Requests"})
        return httpx.Response(200, json=_body(_entries(0, 1000), ["1767268800000", "tx-1000"]))

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, handler).fetch_alerts()

    assert len(out) == 1000, "a failure on page two is not a reason to discard page one"
    assert [log["status"] for log in logs if log["event"] == "connector.paging.next_page_failed"] == [429]


@pytest.mark.asyncio
async def test_a_network_error_on_a_later_page_keeps_what_was_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "next_offset" in request.url.params:
            raise httpx.ConnectError("connection reset", request=request)
        return httpx.Response(200, json=_body(_entries(0, 1000), ["1767268800000", "tx-1000"]))

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, handler).fetch_alerts()

    assert len(out) == 1000
    assert "connector.paging.next_page_error" in [log["event"] for log in logs]


@pytest.mark.asyncio
async def test_an_unreadable_later_page_keeps_what_was_read(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "next_offset" in request.url.params:
            return httpx.Response(200, json=["not", "a", "duo", "reply"])
        return httpx.Response(200, json=_body(_entries(0, 1000), ["1767268800000", "tx-1000"]))

    out = await _connector(monkeypatch, handler).fetch_alerts()

    assert len(out) == 1000


@pytest.mark.asyncio
async def test_a_refused_opening_request_still_fails_the_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scheduler records a raised fetch as a failed poll; an empty list would read as a quiet estate."""
    connector = _connector(monkeypatch, lambda request: httpx.Response(401, json={"stat": "FAIL", "code": 40103}))

    with pytest.raises(httpx.HTTPStatusError):
        await connector.fetch_alerts()


@pytest.mark.asyncio
async def test_an_offset_that_never_ends_is_bounded_and_announced(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_body(_entries(calls, 1), ["1767268800000", f"tx-{calls + 1}"]))

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, handler).fetch_alerts()

    assert calls == DEFAULT_MAX_PAGES
    assert len(out) == DEFAULT_MAX_PAGES
    assert "connector.paging.page_cap_reached" in [log["event"] for log in logs]
