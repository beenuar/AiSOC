"""Sophos Central alerts through the SIEM Integration API.

Every endpoint, header and field name below is the one Sophos documents and
the connector module cites. The payloads are synthetic: they carry the
documented field names, and addresses are RFC 5737 documentation ranges.

The properties pinned here, each a way this could be wired wrong:

1. **The tenant and its host come from the credential.** A tenant credential
   names its own data region through whoami; a partner or organization
   credential has none and must be pointed at one tenant, whose host comes
   from the tenant lookup. The bearer token is never sent to a host outside
   sophos.com.
2. **`has_more` ends the read, not the cursor.** `next_cursor` is present on
   the last page too, so a reader that ends on an absent token would
   re-request the final page until the page cap.
3. **The 24-hour ceiling is respected.** A backfill asking for a full day is
   shortened to fit rather than refused by the vendor.
4. **The ladder is the vendor's.** Sophos publishes LOW, MEDIUM and HIGH, so
   nothing is ever `critical`.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import _CONNECTOR_CLASSES
from app.connectors._paging import DEFAULT_MAX_PAGES, read_token_pages
from app.connectors.base import Capability
from app.connectors.sophos_central import SophosCentralConnector, SophosCentralError

TENANT = "57ca9a6b-885f-4e36-95ec-290548c26059"
PARTNER = "d24c5dd6-804d-48d8-827c-c9300c24ae7f"
REGION = "https://api-eu01.central.sophos.com"

#: One alert in the shape `GET /siem/v1/alerts` returns. Synthetic.
_ALERT: dict[str, Any] = {
    "id": "8bbd989a-6cab-407f-a586-c5064b94f76a",
    "customer_id": "d1271b33-4e24-4cc3-951a-badc38976ca3",
    "created_at": "2026-11-11T07:07:52.094Z",
    "when": "2026-11-11T07:07:48.000Z",
    "severity": "high",
    "type": "Event::Endpoint::Threat::IpsInboundDetection",
    "description": "Intrusion prevention blocked an inbound SMB exploit attempt on WKS-4219",
    "threat": "OS-WINDOWS Microsoft Windows SMB remote code execution attempt",
    "threat_cleanable": False,
    "location": "WKS-4219",
    "source": "CORP\\jdoe",
    "event_service_event_id": "8bbd989a-6cab-407f-a586-c5064b94f76a",
    "data": {
        "endpoint_id": "0320820b-84b4-41ea-95fd-5893fb17e420",
        "endpoint_type": "computer",
        "endpoint_platform": "windows",
        "source_info": {"ip": "192.0.2.17"},
        "ips_threat": {"remote_ip": "203.0.113.9", "remote_port": "445", "local_port": "49152"},
    },
}


def _alerts(start: int, count: int, **overrides: Any) -> list[dict[str, Any]]:
    return [{**_ALERT, "id": f"alert-{i}", **overrides} for i in range(start, start + count)]


def _page(items: list[dict[str, Any]], *, has_more: bool, cursor: str = "cursor-end") -> dict[str, Any]:
    return {"items": items, "has_more": has_more, "next_cursor": cursor}


class Vendor:
    """Sophos ID, the global API and one data region, behind one transport.

    ``alerts`` answers each alerts request; the rest answer the way the
    vendor documents unless a test replaces them.
    """

    def __init__(
        self,
        alerts: Callable[[httpx.Request], httpx.Response] | None = None,
        *,
        whoami: dict[str, Any] | None = None,
        tenant_lookup: httpx.Response | None = None,
        token_status: int = 200,
    ) -> None:
        self.requests: list[httpx.Request] = []
        self.tokens_issued = 0
        self._alerts = alerts or (lambda request: httpx.Response(200, json=_page([], has_more=False)))
        self._whoami = whoami or {
            "id": TENANT,
            "idType": "tenant",
            "apiHosts": {"global": "https://api.central.sophos.com", "dataRegion": REGION},
        }
        self._tenant_lookup = tenant_lookup
        self._token_status = token_status

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == "id.sophos.com":
            if self._token_status != 200:
                return httpx.Response(self._token_status, json={"errorCode": "oauth.client_app_does_not_exist"})
            self.tokens_issued += 1
            return httpx.Response(200, json={"access_token": f"jwt-{self.tokens_issued}", "expires_in": 3600})
        if request.url.path == "/whoami/v1":
            return httpx.Response(200, json=self._whoami)
        if "/v1/tenants/" in request.url.path:
            return self._tenant_lookup or httpx.Response(404, json={"error": "notFound"})
        if request.url.path == "/siem/v1/alerts":
            return self._alerts(request)
        return httpx.Response(404, json={"error": "no route"})

    def connector(self, tenant_id: str = "") -> SophosCentralConnector:
        return SophosCentralConnector(
            client_id="client", client_secret="secret", tenant_id=tenant_id, transport=httpx.MockTransport(self.handle)
        )

    def alert_requests(self) -> list[httpx.Request]:
        return [request for request in self.requests if request.url.path == "/siem/v1/alerts"]


class TestRegistration:
    def test_the_connector_is_in_the_registry(self) -> None:
        assert "sophos_central" in {cls.connector_id for cls in _CONNECTOR_CLASSES}

    def test_only_the_client_secret_is_secret(self) -> None:
        assert {f.name for f in SophosCentralConnector.schema().fields if f.type == "secret"} == {"client_secret"}

    def test_the_tenant_is_optional_and_the_credential_is_not(self) -> None:
        required = {f.name: f.required for f in SophosCentralConnector.schema().fields}
        assert required == {"client_id": True, "client_secret": True, "tenant_id": False}

    def test_it_is_a_read_only_edr_source(self) -> None:
        schema = SophosCentralConnector.schema()
        assert schema.category == "edr"
        assert SophosCentralConnector.capabilities() == (Capability.PULL_ALERTS,)

    def test_the_docs_url_matches_the_generated_slug(self) -> None:
        """The docs generator hyphenates a connector id with no existing page."""
        assert SophosCentralConnector.schema().docs_url == "/docs/connectors/sophos-central"

    def test_a_tenant_id_that_is_not_a_uuid_is_refused_before_any_request(self) -> None:
        """It is interpolated into a request path, so `../` or a query string must never reach it."""
        with pytest.raises(ValueError, match="not a Sophos Central tenant ID"):
            SophosCentralConnector(client_id="c", client_secret="s", tenant_id="../whoami/v1?x=")

    def test_a_blank_tenant_id_is_a_tenant_credential(self) -> None:
        SophosCentralConnector(client_id="c", client_secret="s", tenant_id="  ")


class TestTenantCredential:
    @pytest.mark.asyncio
    async def test_it_authenticates_and_reads_the_data_region_whoami_names(self) -> None:
        vendor = Vendor()
        await vendor.connector().fetch_alerts()

        token = vendor.requests[0]
        assert (token.method, str(token.url)) == ("POST", "https://id.sophos.com/api/v2/oauth2/token")
        form = httpx.QueryParams(token.content.decode())
        assert dict(form) == {"grant_type": "client_credentials", "client_id": "client", "client_secret": "secret", "scope": "token"}

        whoami = vendor.requests[1]
        assert str(whoami.url) == "https://api.central.sophos.com/whoami/v1"
        assert whoami.headers["Authorization"] == "Bearer jwt-1"

        (alerts,) = vendor.alert_requests()
        assert alerts.url.host == "api-eu01.central.sophos.com"
        assert alerts.headers["X-Tenant-ID"] == TENANT
        assert alerts.headers["Authorization"] == "Bearer jwt-1"

    @pytest.mark.asyncio
    async def test_the_tenant_is_resolved_once_per_instance(self) -> None:
        vendor = Vendor()
        connector = vendor.connector()
        await connector.fetch_alerts()
        await connector.fetch_alerts()
        assert [r.url.path for r in vendor.requests].count("/whoami/v1") == 1
        assert vendor.tokens_issued == 1

    @pytest.mark.asyncio
    async def test_a_matching_configured_tenant_is_accepted_whatever_its_case(self) -> None:
        vendor = Vendor()
        await vendor.connector(tenant_id=TENANT.upper()).fetch_alerts()
        assert len(vendor.alert_requests()) == 1

    @pytest.mark.asyncio
    async def test_a_tenant_credential_pointed_at_another_tenant_is_refused(self) -> None:
        vendor = Vendor()
        result = await vendor.connector(tenant_id=PARTNER).test_connection()
        assert result["success"] is False
        assert f"belongs to tenant {TENANT}" in result["error"]
        assert vendor.alert_requests() == []


class TestPartnerAndOrganizationCredentials:
    @pytest.mark.parametrize(("id_type", "header"), [("partner", "X-Partner-ID"), ("organization", "X-Organization-ID")])
    @pytest.mark.asyncio
    async def test_the_named_tenant_is_looked_up_and_read_on_its_own_host(self, id_type: str, header: str) -> None:
        vendor = Vendor(
            whoami={"id": PARTNER, "idType": id_type, "apiHosts": {"global": "https://api.central.sophos.com"}},
            tenant_lookup=httpx.Response(200, json={"id": TENANT, "dataRegion": "us03", "apiHost": "https://api-us03.central.sophos.com"}),
        )
        await vendor.connector(tenant_id=TENANT).fetch_alerts()

        (lookup,) = [r for r in vendor.requests if "/v1/tenants/" in r.url.path]
        assert str(lookup.url) == f"https://api.central.sophos.com/{id_type}/v1/tenants/{TENANT}"
        assert lookup.headers[header] == PARTNER

        (alerts,) = vendor.alert_requests()
        assert alerts.url.host == "api-us03.central.sophos.com"
        assert alerts.headers["X-Tenant-ID"] == TENANT

    @pytest.mark.parametrize(("id_type", "article"), [("partner", "a"), ("organization", "an")])
    @pytest.mark.asyncio
    async def test_without_a_tenant_id_the_operator_is_told_to_set_one(self, id_type: str, article: str) -> None:
        vendor = Vendor(whoami={"id": PARTNER, "idType": id_type, "apiHosts": {"global": "https://api.central.sophos.com"}})
        result = await vendor.connector().test_connection()
        assert result["success"] is False
        assert result["error"].startswith(f"This is {article} {id_type} credential")
        assert "Set Tenant ID" in result["error"]

    @pytest.mark.asyncio
    async def test_a_tenant_the_partner_cannot_see_is_reported_as_such(self) -> None:
        vendor = Vendor(whoami={"id": PARTNER, "idType": "partner", "apiHosts": {"global": "https://api.central.sophos.com"}})
        with pytest.raises(SophosCentralError, match=f"HTTP 404 when looking up tenant {TENANT}"):
            await vendor.connector(tenant_id=TENANT).fetch_alerts()


class TestTheCredentialStaysWithTheVendor:
    @pytest.mark.parametrize(
        "host",
        [
            "https://169.254.169.254",
            "http://api-eu01.central.sophos.com",
            "https://api-eu01.central.sophos.com.example.net",
            "https://evilsophos.com",
            None,
        ],
    )
    @pytest.mark.asyncio
    async def test_a_data_region_outside_sophos_is_never_requested(self, host: str | None) -> None:
        """The host comes from a response, so the egress guard that vets configured URLs never sees it."""
        vendor = Vendor(whoami={"id": TENANT, "idType": "tenant", "apiHosts": {"dataRegion": host}})
        with pytest.raises(SophosCentralError, match="outside sophos.com"):
            await vendor.connector().fetch_alerts()
        assert vendor.alert_requests() == []

    @pytest.mark.asyncio
    async def test_only_the_checked_scheme_host_and_port_reach_the_request(self) -> None:
        vendor = Vendor(
            whoami={
                "id": TENANT,
                "idType": "tenant",
                "apiHosts": {"dataRegion": "https://user@API-EU01.central.sophos.com:8443/elsewhere?x=1"},
            }
        )
        await vendor.connector().fetch_alerts()
        (alerts,) = vendor.alert_requests()
        assert (alerts.url.scheme, alerts.url.host, alerts.url.port, alerts.url.path) == (
            "https",
            "api-eu01.central.sophos.com",
            8443,
            "/siem/v1/alerts",
        )
        assert alerts.url.userinfo == b""


class TestReadingTheWindowToTheEnd:
    @pytest.mark.asyncio
    async def test_every_page_arrives_and_the_cursor_replaces_from_date(self) -> None:
        def alerts(request: httpx.Request) -> httpx.Response:
            cursor = request.url.params.get("cursor")
            if cursor is None:
                return httpx.Response(200, json=_page(_alerts(0, 1000), has_more=True, cursor="c1"))
            if cursor == "c1":
                return httpx.Response(200, json=_page(_alerts(1000, 1000), has_more=True, cursor="c2"))
            return httpx.Response(200, json=_page(_alerts(2000, 3), has_more=False, cursor="c3"))

        vendor = Vendor(alerts)
        out = await vendor.connector().fetch_alerts()

        assert [row["external_id"] for row in out] == [f"alert-{i}" for i in range(2003)]
        first, *following = vendor.alert_requests()
        assert set(first.url.params) == {"from_date", "limit"}
        assert first.url.params["limit"] == "1000"
        assert [dict(r.url.params) for r in following] == [{"cursor": "c1", "limit": "1000"}, {"cursor": "c2", "limit": "1000"}]

    @pytest.mark.asyncio
    async def test_has_more_false_ends_the_read_although_a_cursor_is_present(self) -> None:
        """The defect `more_field` exists for: Sophos returns `next_cursor` on the last page too."""
        vendor = Vendor(lambda request: httpx.Response(200, json=_page(_alerts(0, 5), has_more=False, cursor="resume-here")))
        out = await vendor.connector().fetch_alerts()
        assert len(out) == 5
        assert len(vendor.alert_requests()) == 1

    @pytest.mark.asyncio
    async def test_a_failure_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def alerts(request: httpx.Request) -> httpx.Response:
            if request.url.params.get("cursor") is None:
                return httpx.Response(200, json=_page(_alerts(0, 1000), has_more=True, cursor="c1"))
            return httpx.Response(503, text="unavailable")

        out = await Vendor(alerts).connector().fetch_alerts()
        assert len(out) == 1000

    @pytest.mark.asyncio
    async def test_a_cursor_that_never_ends_is_bounded_and_announced(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(200, json=_page(_alerts(0, 1), has_more=True, cursor="again")))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(vendor.alert_requests()) == DEFAULT_MAX_PAGES
        assert len(out) == DEFAULT_MAX_PAGES
        assert any(entry["event"] == "connector.paging.page_cap_reached" for entry in logs)


class TestTheWindow:
    @pytest.mark.asyncio
    async def test_the_window_opens_since_seconds_ago(self) -> None:
        vendor = Vendor()
        before = int(time.time())
        await vendor.connector().fetch_alerts(since_seconds=600)
        from_date = int(vendor.alert_requests()[0].url.params["from_date"])
        assert before - 600 <= from_date <= int(time.time()) - 600

    @pytest.mark.asyncio
    async def test_a_backfill_past_the_24_hour_ceiling_is_shortened_and_logged(self) -> None:
        """The scheduler's outage backfill asks for exactly 24 hours, which the API refuses."""
        vendor = Vendor()
        with structlog.testing.capture_logs() as logs:
            await vendor.connector().fetch_alerts(since_seconds=24 * 60 * 60)
        from_date = int(vendor.alert_requests()[0].url.params["from_date"])
        assert from_date > time.time() - 24 * 60 * 60 + 60
        assert any(entry["event"] == "sophos_central.window_shortened" for entry in logs)


class TestFailures:
    @pytest.mark.asyncio
    async def test_a_refused_opening_request_raises_rather_than_reading_as_quiet(self) -> None:
        """An empty list means "nothing happened"; the scheduler records an exception as a failed poll."""
        vendor = Vendor(lambda request: httpx.Response(403, json={"error": "forbidden"}))
        with pytest.raises(SophosCentralError, match="HTTP 403 to GET /siem/v1/alerts.*role does not allow"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_a_lapsed_token_is_renewed_once_and_the_request_retried(self) -> None:
        def alerts(request: httpx.Request) -> httpx.Response:
            if request.headers["Authorization"] == "Bearer jwt-1":
                return httpx.Response(401, json={"error": "expired"})
            return httpx.Response(200, json=_page(_alerts(0, 2), has_more=False))

        vendor = Vendor(alerts)
        out = await vendor.connector().fetch_alerts()
        assert len(out) == 2
        assert [r.headers["Authorization"] for r in vendor.alert_requests()] == ["Bearer jwt-1", "Bearer jwt-2"]

    @pytest.mark.asyncio
    async def test_bad_credentials_are_reported_by_test_connection(self) -> None:
        vendor = Vendor(token_status=401)
        result = await vendor.connector().test_connection()
        assert (result["success"], result["connector"]) == (False, "sophos_central")
        assert result["error"].startswith("Sophos ID refused the client credentials (HTTP 401)")
        assert [r.url.host for r in vendor.requests] == ["id.sophos.com"]

    @pytest.mark.asyncio
    async def test_a_working_connection_names_the_tenant_and_region_it_found(self) -> None:
        vendor = Vendor()
        result = await vendor.connector().test_connection()
        assert result == {"success": True, "connector": "sophos_central", "tenant_id": TENANT, "data_region": REGION}
        assert len(vendor.alert_requests()) == 1


class TestNormalize:
    def _normalize(self, **overrides: Any) -> dict[str, Any]:
        return SophosCentralConnector(client_id="c", client_secret="s").normalize({**_ALERT, **overrides})

    def test_the_envelope_is_canonical(self) -> None:
        event = self._normalize()
        assert event["source"] == "sophos_central"
        assert event["raw_event"] == _ALERT
        assert "raw" not in event
        assert event["external_id"] == _ALERT["id"]
        assert event["title"] == _ALERT["description"]
        assert event["event_type"] == "Event::Endpoint::Threat::IpsInboundDetection"
        assert event["threat"] == _ALERT["threat"]
        assert event["created_at"] == "2026-11-11T07:07:52.094Z"

    def test_the_device_user_and_addresses_are_lifted(self) -> None:
        event = self._normalize()
        assert event["hostname"] == "WKS-4219"
        assert event["actor"] == "CORP\\jdoe"
        assert event["src_ip"] == "192.0.2.17"
        assert event["dst_ip"] == "203.0.113.9"
        assert event["endpoint_id"] == "0320820b-84b4-41ea-95fd-5893fb17e420"
        assert event["endpoint_type"] == "computer"

    def test_no_user_is_not_a_user(self) -> None:
        assert "actor" not in self._normalize(source="n/a")

    def test_an_alert_without_ips_detail_has_no_destination(self) -> None:
        event = self._normalize(data={"endpoint_id": "e", "source_info": {"ip": "192.0.2.5"}})
        assert "dst_ip" not in event
        assert event["src_ip"] == "192.0.2.5"

    def test_a_malformed_data_object_is_tolerated(self) -> None:
        event = self._normalize(data="not an object")
        assert event["hostname"] == "WKS-4219"
        assert "src_ip" not in event

    def test_the_title_falls_back_to_the_threat_then_the_type(self) -> None:
        assert self._normalize(description="")["title"] == _ALERT["threat"]
        assert self._normalize(description=None, threat=None)["title"] == _ALERT["type"]

    @pytest.mark.parametrize(("vendor", "tier"), [("LOW", "low"), ("MEDIUM", "medium"), ("HIGH", "high"), ("high", "high")])
    def test_each_published_severity_maps_to_its_tier(self, vendor: str, tier: str) -> None:
        assert self._normalize(severity=vendor)["severity"] == tier

    @pytest.mark.parametrize("vendor", ["critical", "CRITICAL", "none", "", None, 3])
    def test_a_value_outside_the_published_three_carries_no_severity(self, vendor: Any) -> None:
        """Never `critical`: Sophos does not publish it. Never a guess: the class still promotes."""
        assert "severity" not in self._normalize(severity=vendor)


class TestTheMoreFlagOnTheTokenReader:
    """`more_field` on the shared reader, independent of any one vendor."""

    @pytest.mark.parametrize("flag", [False, None, "true", 1])
    @pytest.mark.asyncio
    async def test_anything_but_true_ends_the_read(self, flag: Any) -> None:
        calls: list[str | None] = []

        async def request(token: str | None) -> httpx.Response:
            calls.append(token)
            body: dict[str, Any] = {"items": [{"n": len(calls)}], "next_cursor": "more"}
            if flag is not None:
                body["has_more"] = flag
            return httpx.Response(200, json=body)

        rows = await read_token_pages(request=request, items_field="items", token_field="next_cursor", more_field="has_more", feed="t")
        assert calls == [None]
        assert rows == [{"n": 1}]

    @pytest.mark.asyncio
    async def test_true_still_needs_a_token_to_continue(self) -> None:
        calls: list[str | None] = []

        async def request(token: str | None) -> httpx.Response:
            calls.append(token)
            return httpx.Response(200, json={"items": [{}], "has_more": True})

        await read_token_pages(request=request, items_field="items", token_field="next_cursor", more_field="has_more", feed="t")
        assert calls == [None]

    @pytest.mark.asyncio
    async def test_without_more_field_the_token_alone_decides(self) -> None:
        calls: list[str | None] = []

        async def request(token: str | None) -> httpx.Response:
            calls.append(token)
            done = len(calls) == 3
            return httpx.Response(200, json={"items": [{}], "has_more": False, "next_cursor": None if done else f"t{len(calls)}"})

        await read_token_pages(request=request, items_field="items", token_field="next_cursor", feed="t")
        assert calls == [None, "t1", "t2"]
