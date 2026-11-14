"""Cisco Secure Endpoint detections through the v1 events API.

Every host, parameter and field name below is the one Cisco documents and the
connector module cites. The payloads are synthetic: they carry the documented
field names, and addresses are RFC 5737 documentation ranges.

The properties pinned here, each a way this could be wired wrong:

1. **The credential only goes to Cisco.** The region is a select over the
   three Secure Endpoint clouds, and the following pages are built from it
   rather than from `metadata.links.next`, so no host named in a response is
   ever sent the API key.
2. **The window is read to the end.** Pages of 500 are followed by offset
   until a short one, a failed later page keeps what was read, and the bound
   is announced when it binds.
3. **Only rated events are returned.** Cisco leaves policy updates, scans and
   installs without a severity, and this connector's events are promoted
   unconditionally, so an unrated event would reach the queue as an alert.
4. **The ladder is the vendor's.** Low, Medium, High and Critical each keep
   their own tier; `Critical` is never collapsed into `high`.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import structlog
from app.connectors import _CONNECTOR_CLASSES
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.base import Capability
from app.connectors.cisco_secure_endpoint import CiscoSecureEndpointConnector, CiscoSecureEndpointError

#: One event in the shape `GET /v1/events` returns. Synthetic. The id is a
#: JSON integer wider than 53 bits, as Cisco sends it.
_EVENT: dict[str, Any] = {
    "id": 6411425813945647105,
    "timestamp": 1794400426,
    "timestamp_nanoseconds": 742000000,
    "date": "2026-11-12T10:33:46+00:00",
    "event_type": "Threat Detected",
    "event_type_id": 1090519054,
    "detection": "W32.Auto:12081e6ca3.in03.Talos",
    "detection_id": "6411425813945647105",
    "connector_guid": "5a4e5b2c-7b1e-4f0c-9a43-2c3f0b8f6c11",
    "group_guids": ["b077d6bc-bbdf-42f7-8838-a06053fbd98a"],
    "severity": "High",
    "computer": {
        "connector_guid": "5a4e5b2c-7b1e-4f0c-9a43-2c3f0b8f6c11",
        "hostname": "WKS-4219.corp.example",
        "external_ip": "203.0.113.40",
        "user": "jdoe@WKS-4219",
        "active": True,
        "network_addresses": [{"ip": "192.0.2.17", "mac": "00:00:5e:00:53:01"}],
    },
    "file": {
        "disposition": "Malicious",
        "file_name": "invoice.exe",
        "file_path": "\\\\?\\C:\\Users\\jdoe\\Downloads\\invoice.exe",
        "identity": {
            "sha256": "12081e6ca366ad7d08368fbc7d4107605a9b75d27c671e7e0a58588f94be5837",
            "sha1": "128aa78059540cf0cdae2a3cea30cd80e00f2046",
            "md5": "c877b67a5733c59d0d8ed8d519df0c91",
        },
    },
}

#: An operational record Cisco does not rate.
_POLICY_UPDATE: dict[str, Any] = {
    "id": 6533243623469744129,
    "date": "2026-11-12T10:15:29+00:00",
    "event_type": "Policy Update",
    "event_type_id": 553648130,
    "connector_guid": "5a4e5b2c-7b1e-4f0c-9a43-2c3f0b8f6c11",
    "computer": {"hostname": "WKS-4219.corp.example"},
}


def _events(start: int, count: int, **overrides: Any) -> list[dict[str, Any]]:
    return [{**_EVENT, "id": 7_000_000_000_000_000_000 + i, **overrides} for i in range(start, start + count)]


def _page(data: list[dict[str, Any]], *, offset: int = 0, total: int | None = None) -> dict[str, Any]:
    """The documented envelope, with a `next` link that points somewhere a client must not follow."""
    return {
        "version": "v1.2.0",
        "metadata": {
            "links": {
                "self": f"https://api.amp.cisco.com/v1/events?offset={offset}",
                "next": "https://attacker.example/v1/events?offset=500",
            },
            "results": {"total": total or len(data), "current_item_count": len(data), "index": offset, "items_per_page": 500},
        },
        "data": data,
    }


class Vendor:
    """The three Secure Endpoint API hosts behind one transport."""

    def __init__(self, events: Callable[[httpx.Request], httpx.Response] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._events = events or (lambda request: httpx.Response(200, json=_page([])))

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/v1/events":
            return self._events(request)
        return httpx.Response(404, json={"errors": ["no route"]})

    def connector(self, region: str = "nam") -> CiscoSecureEndpointConnector:
        return CiscoSecureEndpointConnector(
            region=region, client_id="client-id", api_key="api-key", transport=httpx.MockTransport(self.handle)
        )


class TestRegistration:
    def test_the_connector_is_in_the_registry(self) -> None:
        assert "cisco_secure_endpoint" in {cls.connector_id for cls in _CONNECTOR_CLASSES}

    def test_only_the_api_key_is_secret(self) -> None:
        assert {f.name for f in CiscoSecureEndpointConnector.schema().fields if f.type == "secret"} == {"api_key"}

    def test_every_field_is_required(self) -> None:
        required = {f.name: f.required for f in CiscoSecureEndpointConnector.schema().fields}
        assert required == {"region": True, "client_id": True, "api_key": True}

    def test_the_region_offers_the_three_secure_endpoint_clouds(self) -> None:
        (region,) = [f for f in CiscoSecureEndpointConnector.schema().fields if f.name == "region"]
        assert region.type == "select"
        assert [option["value"] for option in region.options or []] == ["nam", "eu", "apjc"]

    def test_it_is_a_read_only_edr_source(self) -> None:
        assert CiscoSecureEndpointConnector.schema().category == "edr"
        assert CiscoSecureEndpointConnector.capabilities() == (Capability.PULL_ALERTS,)

    def test_the_docs_url_matches_the_generated_slug(self) -> None:
        """The docs generator hyphenates a connector id with no existing page."""
        assert CiscoSecureEndpointConnector.schema().docs_url == "/docs/connectors/cisco-secure-endpoint"

    @pytest.mark.parametrize("region", ["", "us", "https://api.amp.cisco.com", "169.254.169.254"])
    def test_a_region_outside_the_three_is_refused_before_any_request(self, region: str) -> None:
        """There is no URL field: the host is chosen from Cisco's list or not at all."""
        with pytest.raises(ValueError, match="not a Cisco Secure Endpoint region"):
            CiscoSecureEndpointConnector(region=region, client_id="c", api_key="k")


class TestWhereTheCredentialGoes:
    @pytest.mark.parametrize(
        ("region", "host"),
        [
            ("nam", "api.amp.cisco.com"),
            ("eu", "api.eu.amp.cisco.com"),
            ("apjc", "api.apjc.amp.cisco.com"),
            (" EU ", "api.eu.amp.cisco.com"),
        ],
    )
    @pytest.mark.asyncio
    async def test_each_region_reads_its_own_host_over_https(self, region: str, host: str) -> None:
        vendor = Vendor()
        await vendor.connector(region).fetch_alerts()
        (request,) = vendor.requests
        assert (request.url.scheme, request.url.host, request.url.path) == ("https", host, "/v1/events")

    @pytest.mark.asyncio
    async def test_the_client_id_and_api_key_are_sent_as_basic_auth(self) -> None:
        vendor = Vendor()
        await vendor.connector().fetch_alerts()
        expected = base64.b64encode(b"client-id:api-key").decode()
        assert vendor.requests[0].headers["Authorization"] == f"Basic {expected}"

    @pytest.mark.asyncio
    async def test_the_next_link_in_a_response_is_never_requested(self) -> None:
        """The link names a host; the following page is built from the configured region instead."""
        calls = iter([_page(_events(0, 500)), _page(_events(500, 3), offset=500)])
        vendor = Vendor(lambda request: httpx.Response(200, json=next(calls)))
        await vendor.connector().fetch_alerts()
        assert [r.url.host for r in vendor.requests] == ["api.amp.cisco.com", "api.amp.cisco.com"]


class TestReadingTheWindowToTheEnd:
    @pytest.mark.asyncio
    async def test_every_page_arrives_by_offset_until_a_short_one(self) -> None:
        def events(request: httpx.Request) -> httpx.Response:
            offset = int(request.url.params["offset"])
            count = 500 if offset < 1000 else 7
            return httpx.Response(200, json=_page(_events(offset, count), offset=offset, total=1007))

        vendor = Vendor(events)
        out = await vendor.connector().fetch_alerts()

        assert len(out) == 1007
        assert [r.url.params["offset"] for r in vendor.requests] == ["0", "500", "1000"]
        assert {r.url.params["limit"] for r in vendor.requests} == {"500"}
        assert len({r.url.params["start_date"] for r in vendor.requests}) == 1

    @pytest.mark.asyncio
    async def test_a_row_shifted_across_a_page_boundary_is_returned_once(self) -> None:
        """Newest first: an event recorded mid-read pushes the last row of page one onto page two."""

        def events(request: httpx.Request) -> httpx.Response:
            if request.url.params["offset"] == "0":
                return httpx.Response(200, json=_page(_events(0, 500)))
            return httpx.Response(200, json=_page(_events(499, 4), offset=500))

        out = await Vendor(events).connector().fetch_alerts()
        ids = [row["external_id"] for row in out]
        assert len(ids) == len(set(ids)) == 503

    @pytest.mark.asyncio
    async def test_a_failure_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def events(request: httpx.Request) -> httpx.Response:
            if request.url.params["offset"] == "0":
                return httpx.Response(200, json=_page(_events(0, 500)))
            return httpx.Response(503, text="unavailable")

        out = await Vendor(events).connector().fetch_alerts()
        assert len(out) == 500

    @pytest.mark.asyncio
    async def test_a_collection_that_never_ends_is_bounded_and_announced(self) -> None:
        def events(request: httpx.Request) -> httpx.Response:
            offset = int(request.url.params["offset"])
            return httpx.Response(200, json=_page(_events(offset, 500), offset=offset))

        vendor = Vendor(events)
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == DEFAULT_MAX_PAGES
        assert len(out) == DEFAULT_MAX_PAGES * 500
        assert any(entry["event"] == "connector.paging.page_cap_reached" for entry in logs)

    @pytest.mark.asyncio
    async def test_the_window_opens_since_seconds_ago_in_iso_8601(self) -> None:
        vendor = Vendor()
        before = datetime.now(UTC)
        await vendor.connector().fetch_alerts(since_seconds=600)
        start = datetime.fromisoformat(vendor.requests[0].url.params["start_date"])
        assert start.utcoffset() == timedelta(0)
        assert before - timedelta(seconds=601) <= start <= datetime.now(UTC) - timedelta(seconds=599)


class TestWhatIsReturned:
    @pytest.mark.asyncio
    async def test_unrated_operational_events_are_skipped_and_counted(self) -> None:
        rows = [_EVENT, _POLICY_UPDATE, {**_POLICY_UPDATE, "id": 1, "event_type": "Scan Started"}]
        vendor = Vendor(lambda request: httpx.Response(200, json=_page(rows)))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert [row["event_type"] for row in out] == ["Threat Detected"]
        (skipped,) = [entry for entry in logs if entry["event"] == "cisco_secure_endpoint.unrated_events_skipped"]
        assert (skipped["skipped"], skipped["returned"]) == (2, 1)

    @pytest.mark.asyncio
    async def test_a_window_of_detections_logs_nothing_about_skipping(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(200, json=_page(_events(0, 3))))
        with structlog.testing.capture_logs() as logs:
            await vendor.connector().fetch_alerts()
        assert not [entry for entry in logs if entry["event"] == "cisco_secure_endpoint.unrated_events_skipped"]

    @pytest.mark.asyncio
    async def test_an_unrecognised_severity_is_treated_as_unrated(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(200, json=_page([{**_EVENT, "severity": "Severe"}])))
        assert await vendor.connector().fetch_alerts() == []


class TestFailures:
    @pytest.mark.asyncio
    async def test_a_refused_opening_request_raises_rather_than_reading_as_quiet(self) -> None:
        """An empty list means "nothing happened"; the scheduler records an exception as a failed poll."""
        vendor = Vendor(lambda request: httpx.Response(401, json={"errors": ["Unauthorized"]}))
        with pytest.raises(CiscoSecureEndpointError, match="HTTP 401 to GET /v1/events.*region matches"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.requests) == 1

    @pytest.mark.asyncio
    async def test_an_exhausted_rate_limit_says_so(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(429, json={"errors": ["Too Many Requests"]}))
        with pytest.raises(CiscoSecureEndpointError, match="HTTP 429.*rate limit"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_bad_credentials_are_reported_by_test_connection(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(401, json={"errors": ["Unauthorized"]}))
        result = await vendor.connector("eu").test_connection()
        assert (result["success"], result["connector"]) == (False, "cisco_secure_endpoint")
        assert result["error"].startswith("Cisco Secure Endpoint answered HTTP 401 to GET /v1/events")

    @pytest.mark.asyncio
    async def test_a_network_failure_is_reported_by_test_connection(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        result = await Vendor(unreachable).connector().test_connection()
        assert result["success"] is False
        assert "connection refused" in result["error"]

    @pytest.mark.asyncio
    async def test_a_working_connection_names_the_region_and_host_it_read(self) -> None:
        vendor = Vendor()
        result = await vendor.connector("apjc").test_connection()
        assert result == {
            "success": True,
            "connector": "cisco_secure_endpoint",
            "region": "apjc",
            "api_host": "https://api.apjc.amp.cisco.com",
        }
        (request,) = vendor.requests
        assert dict(request.url.params) == {"limit": "1"}


class TestNormalize:
    def _normalize(self, **overrides: Any) -> dict[str, Any]:
        return CiscoSecureEndpointConnector(region="nam", client_id="c", api_key="k").normalize({**_EVENT, **overrides})

    def test_the_envelope_is_canonical(self) -> None:
        event = self._normalize()
        assert event["source"] == "cisco_secure_endpoint"
        assert event["raw_event"] == _EVENT
        assert "raw" not in event
        assert event["title"] == "Threat Detected: W32.Auto:12081e6ca3.in03.Talos"
        assert event["event_type"] == "Threat Detected"
        assert event["detection"] == "W32.Auto:12081e6ca3.in03.Talos"
        assert event["created_at"] == "2026-11-12T10:33:46+00:00"

    def test_the_wide_integer_id_survives_as_text(self) -> None:
        assert self._normalize()["external_id"] == "6411425813945647105"
        assert self._normalize(id="abc")["external_id"] == "abc"
        assert "external_id" not in self._normalize(id=True)

    def test_the_computer_user_and_file_are_lifted(self) -> None:
        event = self._normalize()
        assert event["hostname"] == "WKS-4219.corp.example"
        assert event["actor"] == "jdoe@WKS-4219"
        assert event["src_ip"] == "192.0.2.17"
        assert event["external_ip"] == "203.0.113.40"
        assert event["endpoint_id"] == "5a4e5b2c-7b1e-4f0c-9a43-2c3f0b8f6c11"
        assert event["file_name"] == "invoice.exe"
        assert event["sha256"] == "12081e6ca366ad7d08368fbc7d4107605a9b75d27c671e7e0a58588f94be5837"
        assert event["disposition"] == "Malicious"

    def test_a_network_event_names_both_ends(self) -> None:
        event = self._normalize(network_info={"local_ip": "192.0.2.99", "remote_ip": "198.51.100.7", "remote_port": 443})
        assert (event["src_ip"], event["dst_ip"]) == ("192.0.2.99", "198.51.100.7")

    def test_an_event_without_network_detail_has_no_destination(self) -> None:
        assert "dst_ip" not in self._normalize()

    def test_malformed_nested_objects_are_tolerated(self) -> None:
        event = self._normalize(computer="not an object", file=[], network_info=None)
        assert event["title"].startswith("Threat Detected")
        for key in ("hostname", "src_ip", "file_name", "sha256"):
            assert key not in event

    def test_an_indicator_of_compromise_is_titled_by_its_short_description(self) -> None:
        event = self._normalize(
            event_type="Cloud IOC",
            detection=None,
            cloud_ioc={"short_description": "W32.WinWord.Powershell", "description": "Microsoft Word launched PowerShell."},
        )
        assert event["title"] == "Cloud IOC: W32.WinWord.Powershell"
        assert event["description"] == "Microsoft Word launched PowerShell."

    def test_a_threat_hunting_incident_carries_its_title_summary_and_techniques(self) -> None:
        event = self._normalize(
            event_type="SecureX Threat Hunting Incident",
            detection=None,
            severity="Critical",
            threat_hunting={
                "incident_title": "Valak Variant",
                "incident_summary": "The host is compromised by a Valak malware variant.",
                "techniques": [{"external_id": "T1005"}, {"external_id": "T1053"}],
            },
            techniques=[{"external_id": "T1053"}, {"external_id": "T1064"}, {"name": "no id"}],
        )
        assert event["title"] == "SecureX Threat Hunting Incident: Valak Variant"
        assert event["description"] == "The host is compromised by a Valak malware variant."
        assert event["mitre_techniques"] == ["T1053", "T1064", "T1005"]
        assert event["severity"] == "critical"

    def test_the_title_falls_back_to_the_event_type_then_a_placeholder(self) -> None:
        assert self._normalize(detection="")["title"] == "Threat Detected"
        assert self._normalize(detection=None, event_type=None)["title"] == "Cisco Secure Endpoint event"

    @pytest.mark.parametrize(
        ("vendor", "tier"),
        [("Low", "low"), ("Medium", "medium"), ("High", "high"), ("Critical", "critical"), ("critical", "critical")],
    )
    def test_each_published_severity_maps_to_its_own_tier(self, vendor: str, tier: str) -> None:
        assert self._normalize(severity=vendor)["severity"] == tier

    @pytest.mark.parametrize("vendor", ["Severe", "", None, 4])
    def test_a_value_outside_the_published_four_carries_no_severity(self, vendor: Any) -> None:
        assert "severity" not in self._normalize(severity=vendor)
