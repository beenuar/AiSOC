"""Huntress Managed EDR incident reports through the v1 REST API.

Every path, parameter and field name below is the one the Huntress API
reference documents and the connector module cites. The payloads are
synthetic: they carry the documented field names, and addresses are RFC 5737
documentation ranges.

The properties pinned here, each a way this could be wired wrong:

1. **The credential only goes to Huntress.** The host is fixed, and the
   following page is built from `pagination.next_page_token` rather than by
   requesting `next_page_url`, so no host named in a response is ever sent
   the key.
2. **The window is found by ordering.** The list has no time filter, so it is
   read by `updated_at`, newest first, until a page passes the window's
   start. A failed later page keeps what was read, and the bound is
   announced when it binds.
3. **A report is raised once, when it is delivered.** The window is applied
   to `sent_at`, closed at the moment the read started, so a later update to
   a report does not raise it again and an undelivered report is not raised.
4. **The host is resolved from the agent, within budget.** Each distinct
   agent is looked up once, the lookups are bounded and stop on a 429, and a
   failed lookup never costs the report.
5. **The ladder is the vendor's.** Low, high and critical each keep their own
   tier; `critical` is never collapsed into `high`.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import _CONNECTOR_CLASSES
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.base import Capability
from app.connectors.huntress import _MAX_AGENT_LOOKUPS, HuntressConnector, HuntressError


def _ago(seconds: float) -> str:
    """An ISO 8601 timestamp ``seconds`` before now, in the `Z` form Huntress sends."""
    return (datetime.now(UTC) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


#: One incident report in the shape `GET /v1/incident_reports` returns. Synthetic.
_REPORT: dict[str, Any] = {
    "id": 1874213,
    "account_id": 4021,
    "organization_id": 77310,
    "agent_id": 9182734,
    "status": "sent",
    "severity": "critical",
    "platform": "windows",
    "subject": "CRITICAL - Incident on WS-0142 (Example Org)",
    "summary": "Huntress detected a malicious scheduled task on this host. We recommend removing the file and scheduled task.",
    "body": "<Content>",
    "indicator_types": ["footholds", "process_detections"],
    "indicator_counts": {"footholds": 1, "process_detections": 2},
    "remediations": {"total_count": 1, "has_more": False, "items": [{"id": 1, "type": "manual", "action": "Delete File"}]},
    "psa_ticket_eids": [],
    "sent_at": "2026-11-12T09:41:07Z",
    "status_updated_at": "2026-11-12T09:41:07Z",
    "updated_at": "2026-11-12T09:41:07Z",
    "closed_at": None,
}

#: The agent record `GET /v1/agents/{id}` returns for the report's host. Synthetic.
_AGENT: dict[str, Any] = {
    "id": 9182734,
    "account_id": 4021,
    "organization_id": 77310,
    "hostname": "WS-0142",
    "domain_name": "corp.example",
    "ipv4_address": "192.0.2.42",
    "external_ip": "203.0.113.9",
    "os": "Windows 11 Pro",
    "platform": "windows",
}


def _report(report_id: int, *, sent: float | None = 60, updated: float | None = None, **overrides: Any) -> dict[str, Any]:
    """A report delivered ``sent`` seconds ago and last updated ``updated`` seconds ago."""
    updated = sent if updated is None else updated
    return {
        **_REPORT,
        "id": report_id,
        "sent_at": None if sent is None else _ago(sent),
        "updated_at": None if updated is None else _ago(updated),
        **overrides,
    }


def _page(reports: list[dict[str, Any]], token: str | None = None) -> dict[str, Any]:
    """The documented envelope, with a `next_page_url` that points somewhere a client must not follow."""
    pagination: dict[str, Any] = {}
    if token is not None:
        pagination = {"next_page_token": token, "next_page_url": f"https://attacker.example/v1/incident_reports?page_token={token}"}
    return {"incident_reports": reports, "pagination": pagination}


class Vendor:
    """The Huntress API behind one transport."""

    def __init__(
        self,
        reports: Callable[[httpx.Request], httpx.Response] | None = None,
        agents: Callable[[httpx.Request], httpx.Response] | None = None,
    ) -> None:
        self.requests: list[httpx.Request] = []
        self._reports = reports or (lambda request: httpx.Response(200, json=_page([])))
        self._agents = agents or (lambda request: httpx.Response(200, json={"agent": _AGENT}))

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/v1/incident_reports":
            return self._reports(request)
        if request.url.path.startswith("/v1/agents/"):
            return self._agents(request)
        if request.url.path == "/v1/account":
            return httpx.Response(200, json={"account": {"id": 4021, "name": "Example MSP", "subdomain": "example"}})
        return httpx.Response(404, json={"errors": ["no route"]})

    def connector(self) -> HuntressConnector:
        return HuntressConnector(api_key="api-key", api_secret="api-secret", transport=httpx.MockTransport(self.handle))

    def report_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == "/v1/incident_reports"]

    def agent_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path.startswith("/v1/agents/")]


def _serving(*pages: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """Serve ``pages`` in order, keyed by the token each request carries."""
    by_token: dict[str | None, dict[str, Any]] = {}
    token: str | None = None
    for page in pages:
        by_token[token] = page
        token = page["pagination"].get("next_page_token")
    return lambda request: httpx.Response(200, json=by_token[request.url.params.get("page_token")])


class TestRegistration:
    def test_the_connector_is_in_the_registry(self) -> None:
        assert "huntress" in {cls.connector_id for cls in _CONNECTOR_CLASSES}

    def test_both_halves_of_the_credential_are_secret_and_required(self) -> None:
        fields = {f.name: (f.type, f.required) for f in HuntressConnector.schema().fields}
        assert fields == {"api_key": ("secret", True), "api_secret": ("secret", True)}

    def test_it_is_a_read_only_edr_source(self) -> None:
        assert HuntressConnector.schema().category == "edr"
        assert HuntressConnector.capabilities() == (Capability.PULL_ALERTS,)

    def test_the_docs_url_matches_the_generated_slug(self) -> None:
        assert HuntressConnector.schema().docs_url == "/docs/connectors/huntress"


class TestWhereTheCredentialGoes:
    @pytest.mark.asyncio
    async def test_the_fixed_host_is_read_over_https_with_basic_auth(self) -> None:
        vendor = Vendor()
        await vendor.connector().fetch_alerts()
        (request,) = vendor.requests
        assert (request.url.scheme, request.url.host, request.url.path) == ("https", "api.huntress.io", "/v1/incident_reports")
        expected = base64.b64encode(b"api-key:api-secret").decode()
        assert request.headers["Authorization"] == f"Basic {expected}"

    @pytest.mark.asyncio
    async def test_the_next_page_url_in_a_response_is_never_requested(self) -> None:
        vendor = Vendor(_serving(_page([_report(1)], token="dG9rZW4"), _page([_report(2)])))
        await vendor.connector().fetch_alerts()
        assert [r.url.host for r in vendor.report_requests()] == ["api.huntress.io", "api.huntress.io"]
        assert vendor.report_requests()[1].url.params["page_token"] == "dG9rZW4"


class TestReadingTheWindow:
    @pytest.mark.asyncio
    async def test_the_list_is_read_newest_update_first_at_the_documented_maximum(self) -> None:
        vendor = Vendor()
        await vendor.connector().fetch_alerts()
        (request,) = vendor.requests
        assert dict(request.url.params) == {"limit": "500", "sort_field": "updated_at", "sort_direction": "desc"}

    @pytest.mark.asyncio
    async def test_every_page_is_followed_until_the_token_runs_out(self) -> None:
        vendor = Vendor(
            _serving(
                _page([_report(i, sent=10) for i in range(500)], token="p2"),
                _page([_report(i, sent=20) for i in range(500, 1000)], token="p3"),
                _page([_report(i, sent=30) for i in range(1000, 1007)]),
            ),
            agents=lambda request: httpx.Response(404),
        )
        out = await vendor.connector().fetch_alerts()
        assert len(out) == 1007
        assert [r.url.params.get("page_token") for r in vendor.report_requests()] == [None, "p2", "p3"]

    @pytest.mark.asyncio
    async def test_the_read_stops_once_a_page_passes_the_start_of_the_window(self) -> None:
        """No time filter exists, so a newest-first read would otherwise walk the account's whole history."""
        vendor = Vendor(
            _serving(
                _page([_report(1, sent=60), _report(2, sent=7200)], token="p2"),
                _page([_report(3, sent=9000)], token="p3"),
            )
        )
        out = await vendor.connector().fetch_alerts(since_seconds=300)
        assert len(vendor.report_requests()) == 1
        assert [row["external_id"] for row in out] == ["1"]

    @pytest.mark.asyncio
    async def test_an_unreadable_timestamp_on_the_oldest_row_does_not_end_the_read(self) -> None:
        vendor = Vendor(
            _serving(
                _page([_report(1, sent=60, updated=60), _report(2, sent=None, updated=None)], token="p2"),
                _page([_report(3, sent=120)]),
            )
        )
        out = await vendor.connector().fetch_alerts(since_seconds=300)
        assert len(vendor.report_requests()) == 2
        assert [row["external_id"] for row in out] == ["1", "3"]

    @pytest.mark.asyncio
    async def test_a_report_updated_mid_read_is_returned_once(self) -> None:
        """An update moves a report to the top of the list, so it can appear on two pages."""
        vendor = Vendor(_serving(_page([_report(1), _report(2)], token="p2"), _page([_report(2), _report(3)])))
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["1", "2", "3"]

    @pytest.mark.asyncio
    async def test_a_failure_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def reports(request: httpx.Request) -> httpx.Response:
            if "page_token" not in request.url.params:
                return httpx.Response(200, json=_page([_report(1), _report(2)], token="p2"))
            return httpx.Response(503, text="unavailable")

        out = await Vendor(reports).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["1", "2"]

    @pytest.mark.asyncio
    async def test_a_collection_that_never_ends_is_bounded_and_announced(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(200, json=_page([_report(1)], token="again")))
        with structlog.testing.capture_logs() as logs:
            await vendor.connector().fetch_alerts()
        assert len(vendor.report_requests()) == DEFAULT_MAX_PAGES
        assert any(entry["event"] == "connector.paging.page_cap_reached" for entry in logs)


class TestWhatIsReturned:
    @pytest.mark.asyncio
    async def test_a_report_delivered_before_the_window_but_updated_inside_it_is_not_raised_again(self) -> None:
        """Closing or commenting on a report updates it; that is not a new incident."""
        vendor = Vendor(_serving(_page([_report(1, sent=86_400, updated=30, status="closed"), _report(2, sent=60)])))
        out = await vendor.connector().fetch_alerts(since_seconds=300)
        assert [row["external_id"] for row in out] == ["2"]

    @pytest.mark.asyncio
    async def test_a_report_never_delivered_is_not_raised(self) -> None:
        vendor = Vendor(_serving(_page([_report(1, sent=None, updated=30, status="dismissed"), _report(2, sent=60)])))
        out = await vendor.connector().fetch_alerts(since_seconds=300)
        assert [row["external_id"] for row in out] == ["2"]

    @pytest.mark.asyncio
    async def test_a_report_delivered_after_the_read_started_is_left_for_the_next_window(self) -> None:
        """The next poll's window opens where this one closed, so raising it here would raise it twice."""
        vendor = Vendor(_serving(_page([_report(1, sent=-30), _report(2, sent=60)])))
        out = await vendor.connector().fetch_alerts(since_seconds=300)
        assert [row["external_id"] for row in out] == ["2"]

    @pytest.mark.asyncio
    async def test_the_window_opens_since_seconds_ago(self) -> None:
        vendor = Vendor(_serving(_page([_report(1, sent=500), _report(2, sent=700)])))
        out = await vendor.connector().fetch_alerts(since_seconds=600)
        assert [row["external_id"] for row in out] == ["1"]

    @pytest.mark.asyncio
    async def test_an_offset_timestamp_is_compared_as_the_instant_it_names(self) -> None:
        """A wall-clock reading in +05:30 is a minute old, not five and a half hours in the future."""
        sent = (datetime.now(UTC) - timedelta(seconds=60)).astimezone(timezone(timedelta(hours=5, minutes=30)))
        vendor = Vendor(_serving(_page([_report(1, sent_at=sent.isoformat(), updated_at=sent.isoformat())])))
        assert len(await vendor.connector().fetch_alerts(since_seconds=300)) == 1


class TestTheHostBehindAReport:
    @pytest.mark.asyncio
    async def test_the_agent_is_looked_up_and_its_host_lifted(self) -> None:
        vendor = Vendor(_serving(_page([_report(1)])))
        (event,) = await vendor.connector().fetch_alerts()
        (lookup,) = vendor.agent_requests()
        assert (lookup.url.host, lookup.url.path) == ("api.huntress.io", "/v1/agents/9182734")
        assert event["hostname"] == "WS-0142"
        assert event["src_ip"] == "192.0.2.42"
        assert event["external_ip"] == "203.0.113.9"
        assert event["os"] == "Windows 11 Pro"
        assert event["raw_event"]["agent"] == _AGENT

    @pytest.mark.asyncio
    async def test_each_distinct_agent_is_looked_up_once(self) -> None:
        reports = [_report(1), _report(2), _report(3, agent_id=555), _report(4, agent_id=None, platform="microsoft_365")]
        vendor = Vendor(_serving(_page(reports)))
        out = await vendor.connector().fetch_alerts()
        assert sorted(r.url.path for r in vendor.agent_requests()) == ["/v1/agents/555", "/v1/agents/9182734"]
        assert len(out) == 4
        assert "hostname" not in out[3]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("agent_id", ["../account", 0, -1, True, 1.5])
    async def test_only_a_positive_integer_agent_id_reaches_a_request_path(self, agent_id: Any) -> None:
        vendor = Vendor(_serving(_page([_report(1, agent_id=agent_id)])))
        (event,) = await vendor.connector().fetch_alerts()
        assert vendor.agent_requests() == []
        assert "hostname" not in event

    @pytest.mark.asyncio
    async def test_the_lookups_are_bounded_and_the_bound_announced(self) -> None:
        reports = [_report(i, agent_id=1000 + i) for i in range(_MAX_AGENT_LOOKUPS + 5)]
        vendor = Vendor(_serving(_page(reports)))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(vendor.agent_requests()) == _MAX_AGENT_LOOKUPS
        assert len(out) == _MAX_AGENT_LOOKUPS + 5
        (capped,) = [entry for entry in logs if entry["event"] == "huntress.agent_lookups_capped"]
        assert (capped["agents"], capped["looked_up"]) == (_MAX_AGENT_LOOKUPS + 5, _MAX_AGENT_LOOKUPS)

    @pytest.mark.asyncio
    async def test_an_exhausted_rate_limit_stops_the_lookups_and_keeps_every_report(self) -> None:
        reports = [_report(i, agent_id=1000 + i) for i in range(5)]
        vendor = Vendor(_serving(_page(reports)), agents=lambda request: httpx.Response(429, text="Too Many Requests"))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(vendor.agent_requests()) == 1
        assert len(out) == 5
        assert any(entry["event"] == "huntress.agent_lookups_rate_limited" for entry in logs)

    @pytest.mark.asyncio
    async def test_a_failed_lookup_costs_the_host_never_the_report(self) -> None:
        def agents(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/555"):
                raise httpx.ConnectError("connection reset", request=request)
            if request.url.path.endswith("/556"):
                return httpx.Response(404, json={"errors": ["not found"]})
            return httpx.Response(200, text="not json")

        reports = [_report(1, agent_id=555), _report(2, agent_id=556), _report(3, agent_id=557)]
        out = await Vendor(_serving(_page(reports)), agents=agents).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["1", "2", "3"]
        assert all("hostname" not in row and "agent" not in row["raw_event"] for row in out)


class TestFailures:
    @pytest.mark.asyncio
    async def test_a_refused_opening_request_raises_rather_than_reading_as_quiet(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(401, json={"errors": ["Unauthorized"]}))
        with pytest.raises(HuntressError, match="HTTP 401 to GET /v1/incident_reports.*API secret key"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == 1

    @pytest.mark.asyncio
    async def test_an_unreachable_api_raises_rather_than_reading_as_quiet(self) -> None:
        """The page reader keeps going past a transport error on a later page; on the first it would return nothing."""

        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        with pytest.raises(HuntressError, match="could not be reached.*connection refused"):
            await Vendor(unreachable).connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_a_transport_error_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def reports(request: httpx.Request) -> httpx.Response:
            if "page_token" not in request.url.params:
                return httpx.Response(200, json=_page([_report(1)], token="p2"))
            raise httpx.ReadTimeout("timed out", request=request)

        out = await Vendor(reports).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["1"]

    @pytest.mark.asyncio
    async def test_a_forbidden_credential_names_the_role(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(403, json={"errors": ["Forbidden"]}))
        with pytest.raises(HuntressError, match="HTTP 403.*role"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_exhausted_rate_limit_says_so(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(429, text="Too Many Requests"))
        with pytest.raises(HuntressError, match="HTTP 429.*60 requests a minute"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_a_working_connection_reads_the_account(self) -> None:
        vendor = Vendor()
        result = await vendor.connector().test_connection()
        assert result == {"success": True, "connector": "huntress", "account": "Example MSP"}
        (request,) = vendor.requests
        assert (request.url.host, request.url.path) == ("api.huntress.io", "/v1/account")

    @pytest.mark.asyncio
    async def test_bad_credentials_are_reported_by_test_connection(self) -> None:
        def refuse(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"errors": ["Unauthorized"]})

        connector = HuntressConnector(api_key="k", api_secret="s", transport=httpx.MockTransport(refuse))
        result = await connector.test_connection()
        assert (result["success"], result["connector"]) == (False, "huntress")
        assert result["error"].startswith("Huntress answered HTTP 401 to GET /v1/account")

    @pytest.mark.asyncio
    async def test_a_network_failure_is_reported_by_test_connection(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        connector = HuntressConnector(api_key="k", api_secret="s", transport=httpx.MockTransport(unreachable))
        result = await connector.test_connection()
        assert result["success"] is False
        assert "connection refused" in result["error"]


class TestNormalize:
    def _normalize(self, **overrides: Any) -> dict[str, Any]:
        return HuntressConnector(api_key="k", api_secret="s").normalize({**_REPORT, **overrides})

    def test_the_envelope_is_canonical(self) -> None:
        event = self._normalize()
        assert event["source"] == "huntress"
        assert event["raw_event"] == _REPORT
        assert "raw" not in event
        assert event["external_id"] == "1874213"
        assert event["title"] == "CRITICAL - Incident on WS-0142 (Example Org)"
        assert event["description"].startswith("Huntress detected a malicious scheduled task")
        assert event["created_at"] == "2026-11-12T09:41:07Z"

    def test_the_report_context_is_kept(self) -> None:
        event = self._normalize()
        assert event["status"] == "sent"
        assert event["platform"] == "windows"
        assert event["indicator_types"] == ["footholds", "process_detections"]
        assert event["endpoint_id"] == "9182734"
        assert event["organization_id"] == "77310"

    def test_a_report_without_its_agent_record_has_no_host(self) -> None:
        event = self._normalize()
        for key in ("hostname", "src_ip", "external_ip", "os"):
            assert key not in event

    def test_malformed_fields_are_tolerated(self) -> None:
        event = self._normalize(subject=None, summary=7, indicator_types="footholds", agent="not an object", id=True)
        assert event["title"] == "Huntress incident report"
        for key in ("description", "indicator_types", "hostname", "external_id"):
            assert key not in event

    @pytest.mark.parametrize(("vendor", "tier"), [("low", "low"), ("high", "high"), ("critical", "critical"), (" CRITICAL ", "critical")])
    def test_each_published_severity_maps_to_its_own_tier(self, vendor: str, tier: str) -> None:
        assert self._normalize(severity=vendor)["severity"] == tier

    @pytest.mark.parametrize("vendor", ["medium", "severe", "", None, 3])
    def test_a_value_outside_the_published_three_carries_no_severity(self, vendor: Any) -> None:
        assert "severity" not in self._normalize(severity=vendor)
