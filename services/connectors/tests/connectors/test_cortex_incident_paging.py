"""Cortex XDR and Cortex XSIAM incidents are read to the end of the poll window.

``POST /public_api/v1/incidents/get_incidents`` pages by offset: a request
returns the incidents from ``search_from`` up to ``search_to``, at most 100 of
them, and carries no link or token to the next page. Palo Alto's own
integration describes the page size as "The default and maximum is 100" and
reads page ``n`` as ``search_from = n * limit``, ``search_to = search_from +
limit`` (``get_incidents`` in ``CoreIRApiModule``, which the Cortex XDR and
Cortex XSIAM integrations share:
https://github.com/demisto/content/blob/master/Packs/ApiModules/Scripts/CoreIRApiModule/CoreIRApiModule.py
and https://github.com/demisto/content/blob/master/Packs/CortexXDR/Integrations/CortexXDRIR/CortexXDRIR.yml).

Both connectors asked for offsets 0 to 100 and stopped, and because the next
poll's window opens where this one closed, every incident past the hundredth
was never requested again.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import cortex_xdr, cortex_xsiam
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.base import BaseConnector
from app.connectors.cortex_xdr import CortexXDRConnector
from app.connectors.cortex_xsiam import CortexXSIAMConnector

Handler = Callable[[httpx.Request], httpx.Response]


def _mock(monkeypatch: pytest.MonkeyPatch, module: Any, handler: Handler) -> None:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", factory)


def _xdr(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> BaseConnector:
    _mock(monkeypatch, cortex_xdr, handler)
    return CortexXDRConnector(api_key_id="7", api_key="key", fqdn="api-t.xdr.eu.paloaltonetworks.com")


def _xsiam(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> BaseConnector:
    _mock(monkeypatch, cortex_xsiam, handler)
    return CortexXSIAMConnector(tenant_fqdn="api-t.xdr.eu.paloaltonetworks.com", api_key_id="7", api_key="key")


_CONNECTORS = pytest.mark.parametrize("make", [_xdr, _xsiam], ids=["cortex_xdr", "cortex_xsiam"])


def _request_data(request: httpx.Request) -> dict[str, Any]:
    return json.loads(request.content)["request_data"]


def _incidents(start: int, count: int) -> list[dict[str, Any]]:
    return [
        {"incident_id": str(i), "severity": "high", "description": f"incident {i}", "hosts": ["h"]} for i in range(start, start + count)
    ]


def _window(total: int, seen: list[dict[str, Any]] | None = None) -> Handler:
    """Serve ``total`` incidents the way ``get_incidents`` does: the rows from ``search_from`` to ``search_to``."""

    def handler(request: httpx.Request) -> httpx.Response:
        data = _request_data(request)
        if seen is not None:
            seen.append(data)
        start, end = data["search_from"], min(data["search_to"], total)
        rows = _incidents(start, max(0, end - start))
        return httpx.Response(200, json={"reply": {"total_count": total, "result_count": len(rows), "incidents": rows}})

    return handler


def _ids(out: list[dict[str, Any]]) -> list[str]:
    return [row["raw_event"]["incident_id"] for row in out]


@_CONNECTORS
@pytest.mark.asyncio
async def test_every_page_of_a_busy_window_arrives(monkeypatch: pytest.MonkeyPatch, make: Callable[..., BaseConnector]) -> None:
    """250 incidents in one window arrive in full, not the first 100."""
    seen: list[dict[str, Any]] = []

    out = await make(monkeypatch, _window(250, seen)).fetch_alerts()

    assert [(data["search_from"], data["search_to"]) for data in seen] == [(0, 100), (100, 200), (200, 300)]
    assert _ids(out) == [str(i) for i in range(250)]


@_CONNECTORS
@pytest.mark.asyncio
async def test_every_page_keeps_the_window_and_reads_oldest_first(
    monkeypatch: pytest.MonkeyPatch, make: Callable[..., BaseConnector]
) -> None:
    """An incident created mid-read must join the end of the list, not shift the offsets still to be read."""
    seen: list[dict[str, Any]] = []

    await make(monkeypatch, _window(150, seen)).fetch_alerts()

    assert len(seen) == 2
    assert seen[0]["filters"] == seen[1]["filters"]
    assert seen[0]["filters"][0]["field"] == "creation_time"
    assert seen[0]["filters"][0]["operator"] == "gte"
    assert [data["sort"] for data in seen] == [{"field": "creation_time", "keyword": "asc"}] * 2


@_CONNECTORS
@pytest.mark.asyncio
async def test_a_short_page_ends_the_read(monkeypatch: pytest.MonkeyPatch, make: Callable[..., BaseConnector]) -> None:
    seen: list[dict[str, Any]] = []

    out = await make(monkeypatch, _window(42, seen)).fetch_alerts()

    assert len(seen) == 1
    assert len(out) == 42


@_CONNECTORS
@pytest.mark.asyncio
async def test_a_window_that_fills_its_last_page_exactly_ends_on_the_empty_page(
    monkeypatch: pytest.MonkeyPatch, make: Callable[..., BaseConnector]
) -> None:
    seen: list[dict[str, Any]] = []

    with structlog.testing.capture_logs() as logs:
        out = await make(monkeypatch, _window(200, seen)).fetch_alerts()

    assert [data["search_from"] for data in seen] == [0, 100, 200]
    assert len(out) == 200
    assert "connector.paging.page_cap_reached" not in [log["event"] for log in logs]


@_CONNECTORS
@pytest.mark.asyncio
async def test_a_rate_limit_on_a_later_page_keeps_what_was_read(
    monkeypatch: pytest.MonkeyPatch, make: Callable[..., BaseConnector]
) -> None:
    full = _window(1000)

    def handler(request: httpx.Request) -> httpx.Response:
        if _request_data(request)["search_from"] == 200:
            return httpx.Response(429, json={"reply": {"err_msg": "Too many requests"}})
        return full(request)

    with structlog.testing.capture_logs() as logs:
        out = await make(monkeypatch, handler).fetch_alerts()

    assert len(out) == 200, "a failure on page three is not a reason to discard pages one and two"
    assert [log["status"] for log in logs if log["event"] == "connector.paging.next_page_failed"] == [429]


@_CONNECTORS
@pytest.mark.asyncio
async def test_a_transport_error_on_a_later_page_keeps_what_was_read(
    monkeypatch: pytest.MonkeyPatch, make: Callable[..., BaseConnector]
) -> None:
    full = _window(1000)

    def handler(request: httpx.Request) -> httpx.Response:
        if _request_data(request)["search_from"] == 100:
            raise httpx.ReadTimeout("timed out", request=request)
        return full(request)

    with structlog.testing.capture_logs() as logs:
        out = await make(monkeypatch, handler).fetch_alerts()

    assert len(out) == 100
    assert "connector.paging.next_page_error" in [log["event"] for log in logs]


@_CONNECTORS
@pytest.mark.asyncio
async def test_a_window_past_the_page_cap_is_bounded_and_announced(
    monkeypatch: pytest.MonkeyPatch, make: Callable[..., BaseConnector]
) -> None:
    seen: list[dict[str, Any]] = []

    with structlog.testing.capture_logs() as logs:
        out = await make(monkeypatch, _window(100 * DEFAULT_MAX_PAGES + 1, seen)).fetch_alerts()

    assert len(seen) == DEFAULT_MAX_PAGES
    assert len(out) == 100 * DEFAULT_MAX_PAGES
    assert [log["event"] for log in logs].count("connector.paging.page_cap_reached") == 1


@pytest.mark.asyncio
async def test_cortex_xdr_signs_every_page_for_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    """The advanced-auth hash covers a fresh nonce and timestamp, so a page cannot reuse the opening request's."""
    seen: list[httpx.Request] = []
    full = _window(150)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return full(request)

    await _xdr(monkeypatch, handler).fetch_alerts()

    assert len(seen) == 2
    assert all(request.url.host == "api-t.xdr.eu.paloaltonetworks.com" for request in seen)
    assert all(request.headers["x-xdr-auth-id"] == "7" for request in seen)
    assert seen[0].headers["x-xdr-nonce"] != seen[1].headers["x-xdr-nonce"]


@pytest.mark.asyncio
async def test_cortex_xdr_still_raises_on_a_refused_opening_request(monkeypatch: pytest.MonkeyPatch) -> None:
    """So the scheduler records a failed poll rather than a quiet one, as before."""
    with pytest.raises(httpx.HTTPStatusError):
        await _xdr(monkeypatch, lambda request: httpx.Response(401, json={"reply": {"err_msg": "unauthorized"}})).fetch_alerts()


@pytest.mark.asyncio
async def test_cortex_xsiam_still_logs_a_refused_opening_request_and_returns_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    with structlog.testing.capture_logs() as logs:
        out = await _xsiam(monkeypatch, lambda request: httpx.Response(401, json={"reply": {"err_msg": "unauthorized"}})).fetch_alerts()

    assert out == []
    assert [log["status"] for log in logs if log["event"] == "cortex_xsiam.fetch_failed"] == [401]
