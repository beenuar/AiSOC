"""Okta, GitHub and GitLab collections are read through the ``Link`` header.

All three vendors answer a capped collection request with the first page and a
``Link: <url>; rel="next"`` header, and all three connectors read the first
response and stopped:

* Okta System Log — https://developer.okta.com/docs/reference/system-log-query/
  "Then retrieve the next page of events through the ``link`` response header
  value with the ``next`` link relation." A request with no ``until`` has "an
  infinite number of pages" and the next link is "always present, even if there
  are no new events", so the instruction is to "continue this process until no
  events are returned".
* GitHub audit log and code scanning —
  https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api
* GitLab group audit events — https://docs.gitlab.com/api/rest/#keyset-based-pagination
  allows ``order_by=id`` and ``sort=desc``, and says to "use only the given link
  to retrieve the next page instead of building your own URL".

Reading one page is unrecoverable rather than slow: the next poll's window opens
where this one closed, so a row left unread is never requested again. Okta sorts
oldest-first, which makes the rows it dropped the tail of whatever burst
overflowed its 50-row page, and a password-spraying run is exactly that burst.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import structlog
from app.connectors import _paging, github, gitlab, okta
from app.connectors.github import GitHubConnector
from app.connectors.gitlab import GitLabConnector
from app.connectors.okta import OktaConnector

_OKTA = "https://acme.okta.com"
_OKTA_TYPES = 5
_GITHUB = "https://api.github.com"
_GITLAB = "https://gitlab.example.com"


def _mock_client(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
    handler: Callable[[httpx.Request], httpx.Response],
) -> None:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", factory)


def _query(request: httpx.Request) -> dict[str, str]:
    return {key: values[0] for key, values in parse_qs(urlparse(str(request.url)).query).items()}


def _okta_rows(event_type: str, start: int, count: int) -> list[dict[str, Any]]:
    return [
        {
            "uuid": f"{event_type}-{i}",
            "published": "2099-01-01T00:00:00.000Z",
            "eventType": event_type,
            "outcome": {"result": "FAILURE"},
        }
        for i in range(start, start + count)
    ]


def _okta_polling_handler(
    per_type: int,
    page_size: int,
    requested: list[str],
) -> Callable[[httpx.Request], httpx.Response]:
    """Serve an Okta polling read: a next link on every page, including the empty one.

    The self and next relations arrive as two separate header lines, which is
    how Okta sends them, and the cursor is opaque to the client.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        query = _query(request)
        event_type = query["eventType"]
        start = int(query.get("after", 0))
        page = _okta_rows(event_type, start, max(0, min(page_size, per_type - start)))
        following = f"{_OKTA}/api/v1/logs?eventType={event_type}&limit={query['limit']}&after={start + len(page)}"
        return httpx.Response(
            200,
            json=page,
            headers=[("link", f'<{request.url}>; rel="self"'), ("link", f'<{following}>; rel="next"')],
        )

    return handler


def _okta(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> OktaConnector:
    _mock_client(monkeypatch, okta, handler)
    return OktaConnector(domain=_OKTA, api_token="tok")


@pytest.mark.asyncio
async def test_okta_reads_past_the_first_page_of_every_event_type(monkeypatch: pytest.MonkeyPatch) -> None:
    """A burst larger than one page arrives whole, for each event type polled."""
    requested: list[str] = []
    connector = _okta(monkeypatch, _okta_polling_handler(per_type=2300, page_size=1000, requested=requested))

    out = await connector.fetch_alerts()

    assert len(out) == 2300 * _OKTA_TYPES, "reading one page silently discards the rest of the window"
    assert len({row["external_id"] for row in out}) == len(out), "paging must not re-deliver a row"


@pytest.mark.asyncio
async def test_okta_stops_at_the_empty_page_of_a_polling_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """The next link never goes away on a polling read, so it cannot be the stop.

    Three data pages and one empty page per event type. Without the empty-page
    rule this reads to the page cap on every event type on every poll, spending
    the org's System Log rate limit on nothing.
    """
    requested: list[str] = []
    connector = _okta(monkeypatch, _okta_polling_handler(per_type=2300, page_size=1000, requested=requested))

    await connector.fetch_alerts()

    assert len(requested) == 4 * _OKTA_TYPES


@pytest.mark.asyncio
async def test_okta_asks_for_its_maximum_page(monkeypatch: pytest.MonkeyPatch) -> None:
    requested: list[str] = []
    connector = _okta(monkeypatch, _okta_polling_handler(per_type=1, page_size=1, requested=requested))

    await connector.fetch_alerts()

    assert parse_qs(urlparse(requested[0]).query)["limit"] == ["1000"]


@pytest.mark.asyncio
async def test_okta_follows_the_link_verbatim_with_its_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """Okta says not to craft the cursor; the second request must be the link itself."""
    link = f"{_OKTA}/api/v1/logs?after=opaque%3D%3D&eventType=user.account.lock"
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if str(request.url) == link:
            return httpx.Response(200, json=[])
        if _query(request)["eventType"] == "user.account.lock":
            return httpx.Response(200, json=_okta_rows("user.account.lock", 0, 1), headers={"link": f'<{link}>; rel="next"'})
        return httpx.Response(200, json=[])

    await _okta(monkeypatch, handler).fetch_alerts()

    followed = [request for request in seen if str(request.url) == link]
    assert len(followed) == 1
    assert followed[0].headers["authorization"] == "SSWS tok"


@pytest.mark.asyncio
async def test_okta_keeps_the_pages_it_read_when_a_later_one_is_rate_limited(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        query = _query(request)
        if "after" in query:
            return httpx.Response(429, text="rate limited")
        event_type = query["eventType"]
        following = f"{_OKTA}/api/v1/logs?eventType={event_type}&after=1"
        return httpx.Response(200, json=_okta_rows(event_type, 0, 1), headers={"link": f'<{following}>; rel="next"'})

    with structlog.testing.capture_logs() as logs:
        out = await _okta(monkeypatch, handler).fetch_alerts()

    assert len(out) == _OKTA_TYPES, "a failure on page two is not a reason to discard page one"
    assert [log["status"] for log in logs if log["event"] == "connector.paging.next_page_failed"] == [429] * _OKTA_TYPES


@pytest.mark.parametrize(
    "link",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://acme.okta.com.attacker.example/api/v1/logs",
        "https://acme.okta.com@attacker.example/api/v1/logs",
        "//attacker.example/api/v1/logs",
        "http://acme.okta.com/api/v1/logs?after=1",
        "https://acme.okta.com:8443/api/v1/logs?after=1",
    ],
)
@pytest.mark.asyncio
async def test_a_next_link_cannot_lead_off_the_configured_origin(monkeypatch: pytest.MonkeyPatch, link: str) -> None:
    """The egress guard never saw this URL, and the credential would travel with it."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=_okta_rows(_query(request)["eventType"], 0, 1), headers={"link": f'<{link}>; rel="next"'})

    with structlog.testing.capture_logs() as logs:
        out = await _okta(monkeypatch, handler).fetch_alerts()

    assert len(seen) == _OKTA_TYPES, "only the opening requests may be sent"
    assert all(url.startswith(f"{_OKTA}/api/v1/logs?") for url in seen)
    assert len(out) == _OKTA_TYPES, "the rows of the opening page are still good"
    assert sum(log["event"] == "connector.paging.next_link_refused" for log in logs) == _OKTA_TYPES


def _response_to(url: str, **kwargs: Any) -> httpx.Response:
    return httpx.Response(200, request=httpx.Request("GET", url), **kwargs)


@pytest.mark.asyncio
async def test_a_relative_link_resolves_against_the_opening_request() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=[{"id": 2}])

    first = _response_to(f"{_GITLAB}/api/v4/x", json=[{"id": 1}], headers={"link": '</api/v4/x?id_after=1>; rel="next"'})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        rows = await _paging.read_link_header_pages(client, first, headers={}, feed="f")

    assert seen == [f"{_GITLAB}/api/v4/x?id_after=1"]
    assert rows == [{"id": 1}, {"id": 2}]


@pytest.mark.asyncio
async def test_reaching_the_page_cap_is_announced_and_a_finished_read_is_not() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[{"id": 2}], headers={"link": f'<{request.url}>; rel="next"'})

    url = f"{_OKTA}/api/v1/logs"
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with structlog.testing.capture_logs() as capped:
            first = _response_to(url, json=[{"id": 1}], headers={"link": f'<{url}>; rel="next"'})
            rows = await _paging.read_link_header_pages(client, first, headers={}, feed="f", max_pages=3)
        with structlog.testing.capture_logs() as stopped:
            first = _response_to(url, json=[{"id": 1}], headers={"link": f'<{url}>; rel="next"'})
            await _paging.read_link_header_pages(
                client, first, headers={}, feed="f", max_pages=3, stop_when=lambda page: page[0]["id"] == 2
            )

    assert len(rows) == 3
    assert [log["event"] for log in capped] == ["connector.paging.page_cap_reached"]
    assert stopped == [], "a read that stopped because it was finished was not cut short"


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _github_handler(
    audit_rows: list[dict[str, Any]],
    alerts: list[dict[str, Any]],
    requested: list[str],
) -> Callable[[httpx.Request], httpx.Response]:
    """Serve both GitHub streams 100 at a time behind an opaque ``Link`` cursor."""

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        rows = audit_rows if request.url.path.endswith("/audit-log") else alerts
        start = int(_query(request).get("after", 0))
        page = rows[start : start + 100]
        headers = {}
        if start + 100 < len(rows):
            headers["link"] = f'<{_GITHUB}{request.url.path}?per_page=100&after={start + 100}>; rel="next"'
        return httpx.Response(200, json=page, headers=headers)

    return handler


def _github_alert(number: int, created: datetime) -> dict[str, Any]:
    return {
        "number": number,
        "created_at": _iso(created),
        "rule": {"id": "py/sql-injection", "security_severity_level": "high"},
        "repository": {"full_name": "acme/app"},
    }


@pytest.mark.asyncio
async def test_github_audit_log_reads_every_page(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{"_document_id": f"doc-{i}", "@timestamp": 4070908800000, "action": "org.update_member"} for i in range(250)]
    requested: list[str] = []
    _mock_client(monkeypatch, github, _github_handler(rows, [], requested))

    out = await GitHubConnector("acme", "tok").fetch_alerts()

    assert sorted(row["external_id"] for row in out) == sorted(f"doc-{i}" for i in range(250))
    assert sum("/audit-log" in url for url in requested) == 3


@pytest.mark.asyncio
async def test_github_code_scanning_reads_a_window_larger_than_one_page(monkeypatch: pytest.MonkeyPatch) -> None:
    """A first scan of a large organization opens hundreds of alerts at once."""
    now = datetime.now(UTC)
    alerts = [_github_alert(i, now) for i in range(230)]
    _mock_client(monkeypatch, github, _github_handler([], alerts, []))

    out = await GitHubConnector("acme", "tok").fetch_alerts()

    assert sorted(row["external_id"] for row in out) == sorted(f"code-scanning-{i}" for i in range(230))


@pytest.mark.asyncio
async def test_github_code_scanning_stops_requesting_once_a_page_passes_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """This collection has no time filter, so it runs back to the org's oldest open alert."""
    now = datetime.now(UTC)
    alerts = [_github_alert(i, now) for i in range(150)] + [_github_alert(i, now - timedelta(days=30)) for i in range(150, 900)]
    requested: list[str] = []
    _mock_client(monkeypatch, github, _github_handler([], alerts, requested))

    out = await GitHubConnector("acme", "tok").fetch_alerts()

    assert sum("/code-scanning/alerts" in url for url in requested) == 2, "the second page shows the window has ended"
    assert len(out) == 150, "rows older than the window are still filtered out"


def _gitlab_handler(
    audit_rows: list[dict[str, Any]],
    requested: list[httpx.Request],
) -> Callable[[httpx.Request], httpx.Response]:
    """Serve group audit events 100 at a time behind a keyset ``Link`` cursor.

    The vulnerability half of this connector is no longer a ``Link``-header
    read — it polled a route GitLab does not serve and now goes through
    ``Group.vulnerabilities`` on GraphQL (issue #1754), covered by
    ``test_gitlab_vulnerabilities.py``. It is answered here with an empty
    connection so this file stays about the audit stream.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(request)
        if request.url.path.endswith("/api/graphql"):
            empty = {"pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}
            return httpx.Response(200, json={"data": {"group": {"vulnerabilities": empty}}})
        start = int(_query(request).get("cursor", 0))
        page = audit_rows[start : start + 100]
        headers = {}
        if start + 100 < len(audit_rows):
            headers["link"] = f'<{_GITLAB}{request.url.path}?pagination=keyset&cursor={start + 100}>; rel="next"'
        return httpx.Response(200, json=page, headers=headers)

    return handler


@pytest.mark.asyncio
async def test_gitlab_audit_events_open_a_keyset_read_and_follow_it(monkeypatch: pytest.MonkeyPatch) -> None:
    rows = [{"id": i, "created_at": "2099-01-01T00:00:00Z", "details": {"action_name": "user_add"}} for i in range(250)]
    requested: list[httpx.Request] = []
    _mock_client(monkeypatch, gitlab, _gitlab_handler(rows, requested))

    out = await GitLabConnector(group="acme", token="tok", gitlab_url=_GITLAB).fetch_alerts()

    audit = [request for request in requested if request.url.path.endswith("/audit_events")]
    assert len(audit) == 3
    opening = _query(audit[0])
    assert (opening["pagination"], opening["order_by"], opening["sort"]) == ("keyset", "id", "desc")
    assert len(out) == 250
