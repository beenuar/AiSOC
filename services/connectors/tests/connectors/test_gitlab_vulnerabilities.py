"""The GitLab vulnerability stream reads a route GitLab actually serves.

The old stream polled ``GET /groups/{id}/security/vulnerability_findings``,
which does not exist. Probed against gitlab.com, the three answers separate
cleanly and that separation is the whole finding:

    /groups/gitlab-org                                 -> 200
    /groups/gitlab-org/audit_events                    -> 403 {"message": ...}
    /projects/278964/vulnerability_findings            -> 401 {"message": ...}
    /groups/gitlab-org/security/vulnerability_findings -> 404 {"error": ...}
    /groups/gitlab-org/definitely_not_a_route          -> 404 {"error": ...}

Grape answers an existing route you may not read with ``message`` and a route
it never served with ``error``, so the findings path is in the second class —
and the connector folded its 404 into the same branch as a 403, reporting our
own wrong URL as the tenant's plan limitation (issue #1754).

The replacement is ``Group.vulnerabilities`` on GitLab's GraphQL API. It is
group-scoped, so there is nothing to enumerate; it sorts ``detected_desc``
and carries ``detectedAt``, so a clock-derived poll window is readable; and
it pages with a Relay cursor. GitLab says of the REST findings endpoint that
it "is in the process of being deprecated and considered unstable… Use the
GraphQL API instead" (https://docs.gitlab.com/api/vulnerability_findings/).

Two behaviours below were measured against the live endpoint rather than
assumed, because both are easy to get backwards:

* An authorization-filtered page comes back ``nodes: []`` with
  ``hasNextPage: true``, so an empty page must not end the read.
* Every outcome is HTTP 200, including a rejected query. ``errors`` is our
  defect, a null ``group`` is a wrong or invisible path, and a null
  ``vulnerabilities`` is the plan. Only the last is a tenant condition, and
  collapsing them is the same mistake as the original 403/404 conflation.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import gitlab
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.gitlab import GitLabConnector

_BASE = "https://gitlab.example.com"
_DEAD_REST_ROUTE = "/security/vulnerability_findings"


def _connector(monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]) -> GitLabConnector:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(gitlab.httpx, "AsyncClient", factory)
    return GitLabConnector(group="acme", token="tok", gitlab_url=_BASE)


def _node(index: int, detected: datetime, severity: str = "CRITICAL") -> dict[str, Any]:
    return {
        "id": f"gid://gitlab/Vulnerability/{index}",
        "uuid": f"uuid-{index}",
        "title": f"Hard-coded credential #{index}",
        "description": "A secret was committed to the repository.",
        "severity": severity,
        "state": "DETECTED",
        "reportType": "SECRET_DETECTION",
        "detectedAt": detected.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "webUrl": f"{_BASE}/acme/app/-/security/vulnerabilities/{index}",
        "project": {"id": "gid://gitlab/Project/1", "name": "payments-api", "fullPath": "acme/payments-api"},
        "scanner": {"id": "gid://gitlab/Scanner/1", "name": "Gitleaks", "vendor": "GitLab"},
        "identifiers": [{"externalType": "cwe", "externalId": "798", "name": "CWE-798", "url": None}],
    }


def _connection(nodes: list[dict[str, Any]], cursor: str | None) -> dict[str, Any]:
    return {
        "data": {
            "group": {
                "vulnerabilities": {
                    "pageInfo": {"hasNextPage": cursor is not None, "endCursor": cursor},
                    "nodes": nodes,
                }
            }
        }
    }


def _router(
    graphql: Callable[[httpx.Request], httpx.Response],
    *,
    audit: list[dict[str, Any]] | None = None,
    audit_status: int = 200,
    seen: list[httpx.Request] | None = None,
) -> Callable[[httpx.Request], httpx.Response]:
    """Serve the audit-events REST route and the GraphQL endpoint.

    Anything else 404s with Grape's route-not-found body, exactly as
    gitlab.com answers the route this connector used to call — so a request
    to the dead path is indistinguishable here from what production did.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        if request.url.path.endswith("/api/graphql"):
            return graphql(request)
        if request.url.path.endswith("/audit_events"):
            if audit_status != 200:
                return httpx.Response(audit_status, json={"message": f"{audit_status}"})
            return httpx.Response(200, json=audit or [])
        return httpx.Response(404, json={"error": "404 Not Found"})

    return handler


def _single_page(nodes: list[dict[str, Any]]) -> Callable[[httpx.Request], httpx.Response]:
    return lambda request: httpx.Response(200, json=_connection(nodes, None))


# --------------------------------------------------------------------------
# the route


@pytest.mark.asyncio
async def test_the_dead_rest_route_is_never_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pre-fix control. This connector asked for a path GitLab does not serve."""
    seen: list[httpx.Request] = []
    now = datetime.now(UTC)
    handler = _router(_single_page([_node(1, now)]), seen=seen)

    await _connector(monkeypatch, handler).fetch_alerts()

    requested = [str(request.url) for request in seen]
    assert not [url for url in requested if _DEAD_REST_ROUTE in url], (
        f"the connector still polls a route GitLab answers 404 for: {requested}"
    )
    assert any(url.endswith("/api/graphql") for url in requested), "the vulnerability stream must reach GitLab's GraphQL endpoint"


@pytest.mark.asyncio
async def test_a_vulnerability_detected_in_the_window_becomes_an_alert(monkeypatch: pytest.MonkeyPatch) -> None:
    now = datetime.now(UTC)
    handler = _router(_single_page([_node(1, now), _node(2, now, severity="MEDIUM")]))

    out = await _connector(monkeypatch, handler).fetch_alerts()

    findings = [row for row in out if row["external_id"].startswith("finding-")]
    assert [row["external_id"] for row in findings] == ["finding-uuid-1", "finding-uuid-2"]
    assert [row["severity"] for row in findings] == ["critical", "medium"], "GraphQL returns the enum upper-cased"
    assert findings[0]["project_name"] == "payments-api"
    assert findings[0]["scanner_name"] == "Gitleaks"
    assert findings[0]["identifier"] == "CWE-798"
    assert findings[0]["created_at"] == _node(1, now)["detectedAt"]


@pytest.mark.asyncio
async def test_the_query_asks_for_newest_first_and_carries_the_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[httpx.Request] = []
    handler = _router(_single_page([]), seen=seen)

    await _connector(monkeypatch, handler).fetch_alerts()

    graphql = [request for request in seen if str(request.url).endswith("/api/graphql")]
    assert len(graphql) == 1
    assert graphql[0].method == "POST"
    assert graphql[0].headers["private-token"] == "tok"
    body = json.loads(graphql[0].content)
    assert "sort: detected_desc" in body["query"], "a window read needs the newest rows first"
    assert body["variables"] == {"fullPath": "acme", "after": None, "first": 100}


# --------------------------------------------------------------------------
# paging and the window


@pytest.mark.asyncio
async def test_the_relay_cursor_is_followed_to_the_end_of_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """250 vulnerabilities detected inside one window arrive whole."""
    now = datetime.now(UTC)
    nodes = [_node(i, now) for i in range(250)]
    cursors: list[str | None] = []

    def graphql(request: httpx.Request) -> httpx.Response:
        after = json.loads(request.content)["variables"]["after"]
        cursors.append(after)
        start = int(after) if after else 0
        page = nodes[start : start + 100]
        following = start + 100
        return httpx.Response(200, json=_connection(page, str(following) if following < len(nodes) else None))

    out = await _connector(monkeypatch, _router(graphql)).fetch_alerts()

    assert cursors == [None, "100", "200"]
    findings = [row for row in out if row["external_id"].startswith("finding-")]
    assert len(findings) == 250
    assert len({row["external_id"] for row in findings}) == 250, "paging must not re-deliver a node"


@pytest.mark.asyncio
async def test_the_read_stops_at_the_page_that_passes_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """The connection has no time argument, so this is the only thing bounding it.

    Without the stop, a first poll against a group with years of history
    walks back to its oldest vulnerability — on every poll, forever.
    """
    now = datetime.now(UTC)
    nodes = [_node(i, now) for i in range(60)] + [_node(i, now - timedelta(days=30)) for i in range(60, 900)]
    requests = 0

    def graphql(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        after = json.loads(request.content)["variables"]["after"]
        start = int(after) if after else 0
        page = nodes[start : start + 100]
        following = start + 100
        return httpx.Response(200, json=_connection(page, str(following) if following < len(nodes) else None))

    out = await _connector(monkeypatch, _router(graphql)).fetch_alerts()

    assert requests == 1, "the first page already shows the window has ended"
    findings = [row for row in out if row["external_id"].startswith("finding-")]
    assert len(findings) == 60, "nodes detected before the window are not emitted"


@pytest.mark.asyncio
async def test_an_empty_page_with_a_cursor_does_not_end_the_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """Measured against gitlab.com: authorization filtering empties a page without shortening the connection.

    A live unauthenticated request to ``Group.vulnerabilities`` on
    ``gitlab-org`` answered ``nodes: []`` beside ``hasNextPage: true``. A
    reader that stopped there would report a quiet estate for a group it
    simply could not see all of.
    """
    now = datetime.now(UTC)
    pages = iter(
        [
            _connection([], "a"),
            _connection([], "b"),
            _connection([_node(1, now)], None),
        ]
    )

    out = await _connector(monkeypatch, _router(lambda request: httpx.Response(200, json=next(pages)))).fetch_alerts()

    assert [row["external_id"] for row in out if row["external_id"].startswith("finding-")] == ["finding-uuid-1"]


@pytest.mark.asyncio
async def test_a_cursor_that_never_ends_is_bounded_and_announced(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    now = datetime.now(UTC)

    def graphql(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        # Always in-window, always another page: the shape a token that can
        # read nothing produces, and the only thing holding it is the cap.
        return httpx.Response(200, json=_connection([] if calls % 2 else [_node(calls, now)], f"c{calls}"))

    with structlog.testing.capture_logs() as logs:
        await _connector(monkeypatch, _router(graphql)).fetch_alerts()

    assert calls == DEFAULT_MAX_PAGES
    assert "connector.paging.page_cap_reached" in [log["event"] for log in logs]


# --------------------------------------------------------------------------
# the three GraphQL outcomes that are not data


@pytest.mark.asyncio
async def test_a_rejected_query_is_not_an_empty_estate(monkeypatch: pytest.MonkeyPatch) -> None:
    """GraphQL answers 200 for a query it refuses, so silence here is our bug wearing a tenant's clothes."""
    rejection = {"errors": [{"message": "Field 'notAField' doesn't exist on type 'Vulnerability'"}]}
    audit = [{"id": 1, "created_at": "2099-01-01T00:00:00Z", "details": {"custom_message": "user_add"}}]

    with structlog.testing.capture_logs() as logs:
        out = await _connector(
            monkeypatch,
            _router(lambda request: httpx.Response(200, json=rejection), audit=audit),
        ).fetch_alerts()

    events = [log["event"] for log in logs]
    assert "gitlab.vulnerabilities_query_rejected" in events
    assert "gitlab.vulnerabilities_unavailable" not in events, "our defect must never be filed as a plan limitation"
    assert not [row for row in out if row["external_id"].startswith("finding-")]
    assert len(out) == 1, "a broken vulnerability query does not take the audit stream down with it"


@pytest.mark.asyncio
async def test_a_rejection_on_a_later_page_keeps_what_was_read(monkeypatch: pytest.MonkeyPatch) -> None:
    """A vendor hiccup on page three is not a reason to discard pages one and two.

    The same property the shared readers hold. Returning nothing here would
    turn a transient failure into exactly the silent emptiness this stream
    was fixed for.
    """
    now = datetime.now(UTC)
    pages = iter(
        [
            _connection([_node(1, now)], "a"),
            _connection([_node(2, now)], "b"),
            {"errors": [{"message": "Query has complexity of 301, which exceeds max complexity of 300"}]},
        ]
    )

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, _router(lambda request: httpx.Response(200, json=next(pages)))).fetch_alerts()

    assert [row["external_id"] for row in out] == ["finding-uuid-1", "finding-uuid-2"]
    assert "gitlab.vulnerabilities_query_rejected" in [log["event"] for log in logs]


@pytest.mark.asyncio
async def test_a_group_that_does_not_resolve_is_not_a_plan_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """``data.group: null`` is what gitlab.com returns for a path nobody can see."""
    with structlog.testing.capture_logs() as logs:
        out = await _connector(
            monkeypatch,
            _router(lambda request: httpx.Response(200, json={"data": {"group": None}})),
        ).fetch_alerts()

    matched = [log for log in logs if log["event"] == "gitlab.group_not_found"]
    assert matched and matched[0]["log_level"] == "warning"
    assert matched[0]["group"] == "acme"
    assert "gitlab.vulnerabilities_unavailable" not in [log["event"] for log in logs]
    assert out == []


@pytest.mark.asyncio
async def test_a_group_without_the_security_dashboard_is_a_plan_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one outcome that really is the tenant's plan, and the only one logged at info."""
    body = {"data": {"group": {"vulnerabilities": None}}}

    with structlog.testing.capture_logs() as logs:
        out = await _connector(monkeypatch, _router(lambda request: httpx.Response(200, json=body))).fetch_alerts()

    matched = [log for log in logs if log["event"] == "gitlab.vulnerabilities_unavailable"]
    assert matched and matched[0]["log_level"] == "info"
    assert out == []


@pytest.mark.asyncio
async def test_a_transport_level_failure_keeps_the_audit_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    audit = [{"id": 1, "created_at": "2099-01-01T00:00:00Z", "details": {"custom_message": "user_add"}}]

    with structlog.testing.capture_logs() as logs:
        out = await _connector(
            monkeypatch,
            _router(lambda request: httpx.Response(502, text="bad gateway"), audit=audit),
        ).fetch_alerts()

    assert [log["status"] for log in logs if log["event"] == "connector.paging.token_page_failed"] == [502]
    assert len(out) == 1


# --------------------------------------------------------------------------
# 404 is not 403, on the REST half either


@pytest.mark.asyncio
async def test_audit_events_403_is_a_plan_or_ownership_condition(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = _router(_single_page([]), audit_status=403)

    with structlog.testing.capture_logs() as logs:
        await _connector(monkeypatch, handler).fetch_alerts()

    matched = [log for log in logs if log["event"] == "gitlab.audit_events_forbidden"]
    assert matched and matched[0]["log_level"] == "info"
    assert "gitlab.group_not_found" not in [log["event"] for log in logs]


@pytest.mark.asyncio
async def test_audit_events_404_names_the_group_rather_than_the_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    """The route exists — gitlab.com answers it 403 — so a 404 is about the group, not the tier."""
    handler = _router(_single_page([]), audit_status=404)

    with structlog.testing.capture_logs() as logs:
        await _connector(monkeypatch, handler).fetch_alerts()

    matched = [log for log in logs if log["event"] == "gitlab.group_not_found"]
    assert matched, "a 404 must not be reported as a tier limitation"
    assert matched[0]["log_level"] == "warning"
    assert matched[0]["gitlab_url"] == _BASE
    assert "gitlab.audit_events_forbidden" not in [log["event"] for log in logs]
