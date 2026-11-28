"""Cisco Meraki MX security events through the Dashboard API v1.

Every host, parameter and field name below is the one Meraki documents and the
connector module cites; the two events are the examples in Meraki's OpenAPI
document for `getOrganizationApplianceSecurityEvents`, with the addresses
moved into RFC 5737 documentation ranges.

The properties pinned here, each a way this could be wired wrong:

1. **The API key only goes to Meraki.** The region is a select over the five
   dashboards, and a redirect or a `next` link is followed only to an HTTPS
   host inside the configured region's domain.
2. **The window is read to the end.** The `next` link is followed until it is
   absent or a page is empty, a failed later page keeps what was read, and
   the bound is announced when it binds.
3. **Only rated events are returned.** A TLS decryption failure or a file
   scanned clean is not a threat, and this connector's events are promoted
   unconditionally.
4. **The ladder is Snort's.** IDS priorities 1 to 4 each keep their own tier,
   and nothing is invented above `high`.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import _CONNECTOR_CLASSES
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.base import Capability
from app.connectors.cisco_meraki import CiscoMerakiConnector, CiscoMerakiError

_ORG = "2930418"
_PATH = f"/api/v1/organizations/{_ORG}/appliance/security/events"

#: An intrusion detection alert, as Meraki's reference shows it.
_IDS: dict[str, Any] = {
    "ts": "2026-11-12T10:33:46.090210Z",
    "eventType": "IDS Alert",
    "deviceMac": "00:18:0a:01:02:03",
    "clientMac": "A1:B2:C3:D4:E5:F6",
    "srcIp": "198.51.100.4:34195",
    "destIp": "192.0.2.40:80",
    "protocol": "tcp/ip",
    "priority": "2",
    "classification": "4",
    "blocked": True,
    "message": "SERVER-WEBAPP JBoss JMX console access attempt",
    "signature": "1:21516:9",
    "sigSource": "",
    "ruleId": "meraki:intrusion/snort/GID/1/SID/26267",
}

#: A file Advanced Malware Protection judged malicious.
_FILE: dict[str, Any] = {
    "ts": "2026-11-12T10:34:02.511000Z",
    "eventType": "File Scanned",
    "clientName": "COMPUTER-M-V78J",
    "clientMac": "10:dd:b1:eb:88:f8",
    "clientIp": "192.0.2.17",
    "srcIp": "192.0.2.17",
    "destIp": "203.0.113.48",
    "protocol": "http",
    "uri": "http://www.example.com/program/FavoriteIconsUninstall.exe",
    "canonicalName": "PUA.Win.Dropper.Kraddare::1201",
    "destinationPort": 80,
    "fileHash": "3ec1b9a95fe62aa25fc959643a0f227b76d253094681934daaf628d3574b3463",
    "fileType": "MS_EXE",
    "fileSizeBytes": 193688,
    "disposition": "Malicious",
    "action": "Blocked",
}

#: A TLS decryption failure, which Meraki lists beside the threats.
_TLS: dict[str, Any] = {
    "ts": "2026-11-12T10:35:10.000000Z",
    "eventType": "TLS Decrypt Alert",
    "deviceMac": "00:18:0a:01:02:03",
    "clientName": "COMPUTER-M-V78J",
    "clientIp": "192.0.2.17",
    "srcIp": "192.0.2.17:51528",
    "destIp": "203.0.113.48:443",
    "protocol": "tcp",
    "sourcePort": 51528,
    "destinationPort": 443,
    "message": "Connection to destination failed to be decrypted",
    "errorCode": 0,
    "serverName": "www.example.com",
    "direction": 2,
    "nbarApplication": "web-browsing",
}


def _alerts(start: int, count: int) -> list[dict[str, Any]]:
    """Distinct IDS alerts, one second apart, oldest first."""
    base = datetime(2026, 11, 12, 10, 0, 0, tzinfo=UTC)
    return [
        {**_IDS, "ts": (base + timedelta(seconds=i)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"), "srcIp": f"198.51.100.4:{1024 + i}"}
        for i in range(start, start + count)
    ]


def _page(rows: list[dict[str, Any]], next_url: str | None = None) -> httpx.Response:
    headers = {"Link": f"<{next_url}>; rel=next"} if next_url else {}
    return httpx.Response(200, json=rows, headers=headers)


def _next(after: int, host: str = "api.meraki.com") -> str:
    return f"https://{host}{_PATH}?perPage=1000&sortOrder=ascending&startingAfter={after}"


class Vendor:
    """Every Meraki dashboard host behind one transport."""

    def __init__(self, events: Callable[[httpx.Request], httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._events = events or (lambda request: _page([]))

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == _PATH:
            return self._events(request)
        return httpx.Response(404, json={"errors": ["Not found"]})

    def connector(self, region: str = "global") -> CiscoMerakiConnector:
        return CiscoMerakiConnector(
            region=region, organization_id=_ORG, api_key="meraki-api-key", transport=httpx.MockTransport(self.handle)
        )


def _serving(*responses: httpx.Response) -> Callable[[httpx.Request], httpx.Response]:
    replies = iter(responses)
    return lambda request: next(replies)


class TestRegistration:
    def test_the_connector_is_in_the_registry(self) -> None:
        assert "cisco_meraki" in {cls.connector_id for cls in _CONNECTOR_CLASSES}

    def test_only_the_api_key_is_secret(self) -> None:
        assert {f.name for f in CiscoMerakiConnector.schema().fields if f.type == "secret"} == {"api_key"}

    def test_every_field_is_required(self) -> None:
        required = {f.name: f.required for f in CiscoMerakiConnector.schema().fields}
        assert required == {"region": True, "organization_id": True, "api_key": True}

    def test_the_region_offers_the_five_dashboards(self) -> None:
        (region,) = [f for f in CiscoMerakiConnector.schema().fields if f.name == "region"]
        assert region.type == "select"
        assert [option["value"] for option in region.options or []] == ["global", "canada", "china", "india", "fedramp"]

    def test_it_is_a_read_only_network_source(self) -> None:
        assert CiscoMerakiConnector.schema().category == "network"
        assert CiscoMerakiConnector.capabilities() == (Capability.PULL_ALERTS,)

    def test_the_docs_url_matches_the_generated_slug(self) -> None:
        assert CiscoMerakiConnector.schema().docs_url == "/docs/connectors/cisco-meraki"

    @pytest.mark.parametrize("region", ["", "us", "eu", "https://api.meraki.com", "169.254.169.254"])
    def test_a_region_outside_the_five_is_refused_before_any_request(self, region: str) -> None:
        """There is no URL field: the host is chosen from Meraki's list or not at all."""
        with pytest.raises(ValueError, match="not a Meraki dashboard region"):
            CiscoMerakiConnector(region=region, organization_id=_ORG, api_key="k")

    @pytest.mark.parametrize("organization_id", ["", "  ", "123/../../admins", "123?x=1", "12 34", "123#frag"])
    def test_an_organization_id_that_could_leave_the_path_is_refused(self, organization_id: str) -> None:
        with pytest.raises(ValueError, match="not a Meraki organization id"):
            CiscoMerakiConnector(region="global", organization_id=organization_id, api_key="k")


class TestWhereTheKeyGoes:
    @pytest.mark.parametrize(
        ("region", "host"),
        [
            ("global", "api.meraki.com"),
            ("canada", "api.meraki.ca"),
            ("china", "api.meraki.cn"),
            ("india", "api.meraki.in"),
            ("fedramp", "api.gov-meraki.com"),
            (" Canada ", "api.meraki.ca"),
        ],
    )
    @pytest.mark.asyncio
    async def test_each_region_reads_its_own_host_over_https(self, region: str, host: str) -> None:
        vendor = Vendor()
        await vendor.connector(region).fetch_alerts()
        (request,) = vendor.requests
        assert (request.url.scheme, request.url.host, request.url.path) == ("https", host, _PATH)

    @pytest.mark.asyncio
    async def test_the_key_is_sent_as_a_bearer_token(self) -> None:
        vendor = Vendor()
        await vendor.connector().fetch_alerts()
        assert vendor.requests[0].headers["Authorization"] == "Bearer meraki-api-key"

    @pytest.mark.asyncio
    async def test_a_redirect_to_the_organizations_shard_is_followed(self) -> None:
        def events(request: httpx.Request) -> httpx.Response:
            if request.url.host == "api.meraki.com":
                return httpx.Response(308, headers={"Location": str(request.url.copy_with(host="n149.meraki.com"))})
            return _page([_IDS])

        vendor = Vendor(events)
        out = await vendor.connector().fetch_alerts()

        assert [r.url.host for r in vendor.requests] == ["api.meraki.com", "n149.meraki.com"]
        assert vendor.requests[1].headers["Authorization"] == "Bearer meraki-api-key"
        assert vendor.requests[1].url.params["sortOrder"] == "ascending"
        assert len(out) == 1

    @pytest.mark.parametrize(
        "location",
        [
            "https://attacker.example/api/v1/organizations/2930418/appliance/security/events",
            "https://meraki.com.attacker.example/api/v1/organizations/2930418/appliance/security/events",
            "http://n149.meraki.com/api/v1/organizations/2930418/appliance/security/events",
            "https://n149.meraki.com:8443/api/v1/organizations/2930418/appliance/security/events",
            "https://n149.meraki.ca/api/v1/organizations/2930418/appliance/security/events",
        ],
    )
    @pytest.mark.asyncio
    async def test_a_redirect_outside_the_regions_domain_is_refused_and_reported(self, location: str) -> None:
        vendor = Vendor(lambda request: httpx.Response(302, headers={"Location": location}))
        with pytest.raises(CiscoMerakiError, match="redirect to .* not an HTTPS host of the meraki.com dashboard"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == 1

    @pytest.mark.asyncio
    async def test_a_redirect_loop_is_bounded(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(307, headers={"Location": str(request.url)}))
        with pytest.raises(CiscoMerakiError, match="redirect"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == 4

    @pytest.mark.asyncio
    async def test_a_next_link_outside_the_regions_domain_is_never_requested(self) -> None:
        vendor = Vendor(_serving(_page(_alerts(0, 3), next_url="https://attacker.example/steal?startingAfter=3")))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert [r.url.host for r in vendor.requests] == ["api.meraki.com"]
        assert len(out) == 3
        assert any(entry["event"] == "cisco_meraki.next_link_refused" for entry in logs)

    @pytest.mark.asyncio
    async def test_a_malformed_next_link_ends_the_read_with_the_pages_in_hand(self) -> None:
        vendor = Vendor(_serving(_page(_alerts(0, 3), next_url="https://[::1")))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == 1
        assert len(out) == 3
        assert any(entry["event"] == "cisco_meraki.next_link_refused" for entry in logs)

    @pytest.mark.asyncio
    async def test_a_malformed_redirect_fails_the_poll_without_following_it(self) -> None:
        """httpx refuses an unparseable Location itself; the poll fails as a transport error."""
        vendor = Vendor(lambda request: httpx.Response(302, headers={"Location": "https://[::1"}))
        with pytest.raises(httpx.HTTPError):
            await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == 1

    @pytest.mark.asyncio
    async def test_a_next_link_on_the_organizations_shard_is_followed(self) -> None:
        vendor = Vendor(
            _serving(_page(_alerts(0, 3), next_url=_next(3, host="n149.meraki.com")), _page(_alerts(3, 2))),
        )
        out = await vendor.connector().fetch_alerts()
        assert [r.url.host for r in vendor.requests] == ["api.meraki.com", "n149.meraki.com"]
        assert len(out) == 5


class TestReadingTheWindowToTheEnd:
    @pytest.mark.asyncio
    async def test_the_window_is_asked_for_oldest_first_at_the_largest_page(self) -> None:
        vendor = Vendor()
        before = datetime.now(UTC).replace(microsecond=0)
        await vendor.connector().fetch_alerts(since_seconds=600)
        params = vendor.requests[0].url.params

        assert (params["perPage"], params["sortOrder"]) == ("1000", "ascending")
        t0 = datetime.fromisoformat(params["t0"].replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(params["t1"].replace("Z", "+00:00"))
        assert params["t1"].endswith("Z")
        assert before <= t1 <= datetime.now(UTC)
        # One interval of overlap (#1971): the window opens two intervals ago.
        assert t1 - t0 == timedelta(seconds=1200)

    @pytest.mark.asyncio
    async def test_every_page_arrives_by_following_the_next_link(self) -> None:
        vendor = Vendor(
            _serving(
                _page(_alerts(0, 1000), next_url=_next(1000)),
                _page(_alerts(1000, 1000), next_url=_next(2000)),
                _page(_alerts(2000, 7)),
            )
        )
        out = await vendor.connector().fetch_alerts()

        assert len(out) == 2007
        assert [r.url.params.get("startingAfter") for r in vendor.requests] == [None, "1000", "2000"]

    @pytest.mark.asyncio
    async def test_an_empty_page_ends_the_read_even_beside_a_next_link(self) -> None:
        vendor = Vendor(_serving(_page(_alerts(0, 2), next_url=_next(2)), _page([], next_url=_next(2))))
        out = await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == 2
        assert len(out) == 2

    @pytest.mark.asyncio
    async def test_a_failure_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        vendor = Vendor(_serving(_page(_alerts(0, 1000), next_url=_next(1000)), httpx.Response(503, text="unavailable")))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(out) == 1000
        (failed,) = [entry for entry in logs if entry["event"] == "cisco_meraki.next_page_failed"]
        assert (failed["status"], failed["events"]) == (503, 1000)

    @pytest.mark.asyncio
    async def test_a_rate_limit_on_a_later_page_keeps_the_pages_and_the_cursor_reads_on(self) -> None:
        """Oldest first: the cursor rests on the last event kept, so the next window opens there."""
        rows = _alerts(0, 1000)
        vendor = Vendor(_serving(_page(rows, next_url=_next(1000)), httpx.Response(429, headers={"Retry-After": "1"}, json={"errors": []})))
        connector = vendor.connector()
        out = await connector.fetch_alerts()
        assert len(out) == 1000
        staged = connector.get_checkpoint()
        assert staged is not None and staged["time"] == rows[-1]["ts"]

    @pytest.mark.asyncio
    async def test_a_network_failure_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def events(request: httpx.Request) -> httpx.Response:
            if "startingAfter" in request.url.params:
                raise httpx.ReadTimeout("timed out", request=request)
            return _page(_alerts(0, 3), next_url=_next(3))

        out = await Vendor(events).connector().fetch_alerts()
        assert len(out) == 3

    @pytest.mark.asyncio
    async def test_a_collection_that_never_ends_is_bounded_and_announced(self) -> None:
        counter = iter(range(10_000))

        def events(request: httpx.Request) -> httpx.Response:
            n = next(counter)
            return _page(_alerts(n * 3, 3), next_url=_next((n + 1) * 3))

        vendor = Vendor(events)
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == DEFAULT_MAX_PAGES
        assert len(out) == DEFAULT_MAX_PAGES * 3
        assert any(entry["event"] == "connector.paging.page_cap_reached" for entry in logs)

    @pytest.mark.asyncio
    async def test_a_window_read_to_the_end_announces_no_bound(self) -> None:
        vendor = Vendor(_serving(_page(_alerts(0, 3))))
        with structlog.testing.capture_logs() as logs:
            await vendor.connector().fetch_alerts()
        assert not [entry for entry in logs if entry["event"] == "connector.paging.page_cap_reached"]


class TestWhatIsReturned:
    @pytest.mark.asyncio
    async def test_unrated_events_are_skipped_and_counted_by_type(self) -> None:
        clean = {**_FILE, "disposition": "Clean", "action": "Allowed"}
        vendor = Vendor(_serving(_page([_IDS, _TLS, _FILE, clean, {**_TLS, "ts": "2026-11-12T10:36:00Z"}])))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert [row["event_type"] for row in out] == ["IDS Alert", "File Scanned"]
        (skipped,) = [entry for entry in logs if entry["event"] == "cisco_meraki.unrated_events_skipped"]
        assert (skipped["skipped"], skipped["returned"]) == (3, 2)
        assert skipped["event_types"] == {"TLS Decrypt Alert": 2, "File Scanned": 1}

    @pytest.mark.asyncio
    async def test_a_window_of_threats_logs_nothing_about_skipping(self) -> None:
        vendor = Vendor(_serving(_page([_IDS, _FILE])))
        with structlog.testing.capture_logs() as logs:
            await vendor.connector().fetch_alerts()
        assert not [entry for entry in logs if entry["event"] == "cisco_meraki.unrated_events_skipped"]

    @pytest.mark.asyncio
    async def test_each_event_carries_a_stable_digest_as_its_identity(self) -> None:
        """Meraki gives an event no id; the same record read twice digests the same."""
        first = await Vendor(_serving(_page([_IDS, _FILE]))).connector().fetch_alerts()
        again = await Vendor(_serving(_page([_FILE, _IDS]))).connector().fetch_alerts()

        ids = {row["external_id"] for row in first}
        assert len(ids) == 2
        assert all(len(value) == 32 for value in ids)
        assert ids == {row["external_id"] for row in again}

    @pytest.mark.asyncio
    async def test_the_vendor_record_is_kept_with_its_digest(self) -> None:
        (event,) = await Vendor(_serving(_page([_IDS]))).connector().fetch_alerts()
        assert event["raw_event"] == {**_IDS, "row_id": event["external_id"]}

    @pytest.mark.asyncio
    async def test_non_object_rows_are_ignored(self) -> None:
        out = await Vendor(_serving(httpx.Response(200, json=[_IDS, "noise", 7, None]))).connector().fetch_alerts()
        assert len(out) == 1


class TestFailures:
    @pytest.mark.asyncio
    async def test_a_refused_opening_request_raises_rather_than_reading_as_quiet(self) -> None:
        """An empty list means "nothing happened"; the scheduler records an exception as a failed poll."""
        vendor = Vendor(lambda request: httpx.Response(401, json={"errors": ["Invalid API key"]}))
        with pytest.raises(CiscoMerakiError, match=f"HTTP 401 to GET /organizations/{_ORG}/.*region matches"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == 1

    @pytest.mark.parametrize(
        ("status", "hint"),
        [(403, "no access to this organization"), (404, "organization ID"), (429, "rate limit")],
    )
    @pytest.mark.asyncio
    async def test_each_refusal_says_what_to_check(self, status: int, hint: str) -> None:
        vendor = Vendor(lambda request: httpx.Response(status, json={"errors": ["refused"]}))
        with pytest.raises(CiscoMerakiError, match=hint):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_opening_body_that_is_not_an_array_raises(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(200, json={"errors": ["unexpected"]}))
        with pytest.raises(CiscoMerakiError, match="not a JSON array"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_bad_credentials_are_reported_by_test_connection(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(401, json={"errors": ["Invalid API key"]}))
        result = await vendor.connector("india").test_connection()
        assert (result["success"], result["connector"]) == (False, "cisco_meraki")
        assert result["error"].startswith(f"Meraki answered HTTP 401 to GET /organizations/{_ORG}/appliance/security/events")

    @pytest.mark.asyncio
    async def test_a_network_failure_is_reported_by_test_connection(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        result = await Vendor(unreachable).connector().test_connection()
        assert result["success"] is False
        assert "connection refused" in result["error"]

    @pytest.mark.asyncio
    async def test_a_working_connection_names_the_region_and_organization(self) -> None:
        vendor = Vendor()
        result = await vendor.connector("fedramp").test_connection()
        assert result == {"success": True, "connector": "cisco_meraki", "region": "fedramp", "organization_id": _ORG}
        (request,) = vendor.requests
        assert request.url.host == "api.gov-meraki.com"
        assert dict(request.url.params) == {"perPage": "3", "timespan": "3600"}


class TestNormalize:
    def _normalize(self, base: dict[str, Any] = _IDS, **overrides: Any) -> dict[str, Any]:
        connector = CiscoMerakiConnector(region="global", organization_id=_ORG, api_key="k")
        return connector.normalize({**base, "row_id": "0" * 32, **overrides})

    def test_the_envelope_is_canonical(self) -> None:
        event = self._normalize()
        assert event["source"] == "cisco_meraki"
        assert event["external_id"] == "0" * 32
        assert event["raw_event"]["signature"] == "1:21516:9"
        assert "raw" not in event
        assert event["title"] == "IDS Alert: SERVER-WEBAPP JBoss JMX console access attempt"
        assert event["event_type"] == "IDS Alert"
        assert event["created_at"] == "2026-11-12T10:33:46.090210Z"

    def test_an_ids_alert_names_both_ends_the_rule_and_what_was_done(self) -> None:
        event = self._normalize()
        assert (event["src_ip"], event["src_port"]) == ("198.51.100.4", 34195)
        assert (event["dst_ip"], event["dst_port"]) == ("192.0.2.40", 80)
        assert event["protocol"] == "tcp/ip"
        assert event["signature"] == "1:21516:9"
        assert event["rule_id"] == "meraki:intrusion/snort/GID/1/SID/26267"
        assert event["client_mac"] == "A1:B2:C3:D4:E5:F6"
        assert event["appliance_mac"] == "00:18:0a:01:02:03"
        assert event["action"] == "blocked"
        assert self._normalize(blocked=False)["action"] == "allowed"
        assert "action" not in self._normalize(blocked=None)

    def test_a_malicious_file_carries_its_client_url_hash_and_verdict(self) -> None:
        event = self._normalize(_FILE)
        assert event["title"] == "File Scanned: PUA.Win.Dropper.Kraddare::1201"
        assert event["hostname"] == "COMPUTER-M-V78J"
        assert (event["src_ip"], event["dst_ip"], event["dst_port"]) == ("192.0.2.17", "203.0.113.48", 80)
        assert "src_port" not in event
        assert event["url"] == "http://www.example.com/program/FavoriteIconsUninstall.exe"
        assert event["malware_name"] == "PUA.Win.Dropper.Kraddare::1201"
        assert event["sha256"] == "3ec1b9a95fe62aa25fc959643a0f227b76d253094681934daaf628d3574b3463"
        assert (event["file_type"], event["disposition"], event["action"]) == ("MS_EXE", "Malicious", "blocked")
        assert event["severity"] == "high"

    @pytest.mark.parametrize(
        ("value", "address", "port"),
        [
            ("198.51.100.4:34195", "198.51.100.4", 34195),
            ("198.51.100.4", "198.51.100.4", None),
            ("2001:db8::1", "2001:db8::1", None),
            ("[2001:db8::1]:443", "2001:db8::1", 443),
            ("[2001:db8::1]", "2001:db8::1", None),
            ("198.51.100.4:0", "198.51.100.4", None),
            ("not-an-address:80", None, None),
            ("", None, None),
        ],
    )
    def test_the_source_end_is_split_into_address_and_port(self, value: str, address: str | None, port: int | None) -> None:
        event = self._normalize(srcIp=value)
        assert event.get("src_ip") == address
        assert event.get("src_port") == port

    def test_an_explicit_port_wins_over_the_one_in_the_address(self) -> None:
        event = self._normalize(srcIp="198.51.100.4:1111", sourcePort=2222, destinationPort="8080")
        assert (event["src_port"], event["dst_port"]) == (2222, 8080)

    def test_the_client_address_fills_a_missing_source(self) -> None:
        assert self._normalize(_FILE, srcIp=None)["src_ip"] == "192.0.2.17"

    def test_malformed_values_are_tolerated(self) -> None:
        event = self._normalize(srcIp=7, destIp=["x"], message=None, clientName={}, sourcePort=True, priority=None)
        assert event["title"] == "IDS Alert"
        for key in ("src_ip", "dst_ip", "hostname", "src_port", "severity"):
            assert key not in event

    def test_the_title_falls_back_to_the_event_type_then_a_placeholder(self) -> None:
        assert self._normalize(message="")["title"] == "IDS Alert"
        assert self._normalize(message=None, eventType=None)["title"] == "Cisco Meraki security event"

    @pytest.mark.parametrize(
        ("priority", "tier"),
        [("1", "high"), ("2", "medium"), ("3", "low"), ("4", "info"), (1, "high"), (" 3 ", "low")],
    )
    def test_each_snort_priority_maps_to_its_own_tier(self, priority: Any, tier: str) -> None:
        assert self._normalize(priority=priority)["severity"] == tier

    @pytest.mark.parametrize("priority", ["0", "5", "high", "", None, True, 2.0])
    def test_a_priority_outside_snorts_four_carries_no_severity(self, priority: Any) -> None:
        assert "severity" not in self._normalize(priority=priority)

    def test_nothing_is_raised_as_critical(self) -> None:
        tiers = {self._normalize(priority=p).get("severity") for p in ("1", "2", "3", "4")}
        tiers.add(self._normalize(_FILE).get("severity"))
        assert "critical" not in tiers

    @pytest.mark.parametrize("disposition", ["Clean", "Unknown", "", None])
    def test_a_file_not_judged_malicious_carries_no_severity(self, disposition: Any) -> None:
        assert "severity" not in self._normalize(_FILE, disposition=disposition)

    def test_a_tls_decryption_failure_carries_no_severity(self) -> None:
        assert "severity" not in self._normalize(_TLS)
