"""ESET PROTECT detections through the ESET Connect API.

Every host, path, parameter and field name below is the one the ESET Connect
documentation lists and the connector module cites. The payloads are
synthetic: they carry the documented field names, UUIDs are made up, and
addresses are RFC 5737 documentation ranges.

The properties pinned here, each a way this could be wired wrong:

1. **The credential only goes to ESET.** The region is a fixed choice, every
   request is built from it, and the page after the first is requested with
   `pageToken` rather than by any URL a response names.
2. **The window is read to the end.** `nextPageToken` is followed until it is
   empty, a failed later page keeps what was read, and the bound is
   announced when it binds.
3. **A slow answer is waited out.** A 202 is re-sent with its `response-id`
   until ESET answers, within ESET's own limit.
4. **A detection is raised once.** The exact window is applied to
   `occurTime`, closed at the moment the read began.
5. **The host is resolved from the device, within budget.** Distinct devices
   are looked up in batches, and a failed lookup never costs the detection.
6. **The ladder is the vendor's.** Each published level keeps its own tier,
   nothing is promoted to `critical`, and an unspecified level carries no
   tier.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import structlog
from app.connectors import _CONNECTOR_CLASSES
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.base import Capability
from app.connectors.eset_protect import (
    _DEVICE_BATCH,
    _MAX_DEVICE_LOOKUPS,
    _PENDING_ATTEMPTS,
    ESETProtectConnector,
    ESETProtectError,
)

_DEVICE_UUID = "5b3c6f1e-2d4a-4c8b-9e7f-0a1b2c3d4e5f"


def _ago(seconds: float) -> str:
    """An RFC 3339 timestamp ``seconds`` before now, in the `Z` form ESET sends."""
    return (datetime.now(UTC) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _uuid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


#: One detection in the shape `GET /v1/detections` returns. Synthetic.
_DETECTION: dict[str, Any] = {
    "uuid": "9f8e7d6c-5b4a-4321-8fed-cba987654321",
    "displayName": "Win32/Injector.DTLK",
    "typeName": "Trojan",
    "category": "DETECTION_CATEGORY_ANTIVIRUS",
    "severityLevel": "SEVERITY_LEVEL_HIGH",
    "occurTime": "2026-11-12T09:41:07Z",
    "objectName": "invoice.exe",
    "objectTypeName": "File",
    "objectUrl": "C:\\Users\\jdoe\\Downloads\\invoice.exe",
    "objectHashSha1": "AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D",
    "objectHashSha256": "2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE",
    "networkCommunication": {
        "direction": "NETWORK_COMMUNICATION_DIRECTION_OUTBOUND",
        "localIpAddress": "192.0.2.42",
        "localPort": 50112,
        "remoteIpAddress": "198.51.100.7",
        "remotePort": 443,
        "protocolName": "TCP",
    },
    "context": {
        "circumstances": "Event occurred on a new file created by the application: C:\\Windows\\explorer.exe",
        "deviceUuid": _DEVICE_UUID,
        "process": {"path": "C:\\Windows\\explorer.exe"},
        "userName": "CORP\\jdoe",
    },
    "responses": [
        {"displayName": "cleaned by deleting", "protectionName": "Real-time file system protection", "deviceRestartRequired": False},
        {"description": "no display name"},
    ],
}

#: The device record `GET /v1/devices:batchGet` returns for the detection's host. Synthetic.
_DEVICE: dict[str, Any] = {
    "uuid": _DEVICE_UUID,
    "displayName": "Finance laptop 12",
    "systemHostname": "WS-0142.corp.example",
    "primaryLocalIpAddress": "192.0.2.42",
    "publicIpAddress": "203.0.113.9",
    "operatingSystem": {"displayName": "Microsoft Windows 11 Pro", "version": {"name": "10.0.22631"}},
}


def _detection(detection_uuid: str, *, occurred: float | None = 60, **overrides: Any) -> dict[str, Any]:
    """A detection that occurred ``occurred`` seconds ago."""
    return {**_DETECTION, "uuid": detection_uuid, "occurTime": None if occurred is None else _ago(occurred), **overrides}


def _page(detections: list[dict[str, Any]], token: str = "") -> dict[str, Any]:
    return {"detections": detections, "nextPageToken": token, "totalSize": len(detections)}


def _token_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"access_token": "access-1", "refresh_token": "refresh-1", "token_type": "Bearer", "expires_in": 3600})


class Vendor:
    """The ESET Connect hosts of one region behind one transport."""

    def __init__(
        self,
        detections: Callable[[httpx.Request], httpx.Response] | None = None,
        devices: Callable[[httpx.Request], httpx.Response] | None = None,
        token: Callable[[httpx.Request], httpx.Response] | None = None,
    ) -> None:
        self.requests: list[httpx.Request] = []
        self._detections = detections or (lambda request: httpx.Response(200, json=_page([])))
        self._devices = devices or self._known_devices
        self._token = token or _token_response

    @staticmethod
    def _known_devices(request: httpx.Request) -> httpx.Response:
        wanted = request.url.params.get_list("devicesUuids")
        return httpx.Response(200, json={"devices": [{**_DEVICE, "uuid": uuid} for uuid in wanted]})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/oauth/token":
            return self._token(request)
        if request.url.path == "/v1/detections":
            return self._detections(request)
        if request.url.path == "/v1/devices:batchGet":
            return self._devices(request)
        return httpx.Response(404, json={"message": "no route"})

    def connector(self, region: str = "eu") -> ESETProtectConnector:
        connector = ESETProtectConnector(
            region=region, username="api@corp.example", password="api-password", transport=httpx.MockTransport(self.handle)
        )
        connector.pending_wait_seconds = 0
        return connector

    def on(self, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == path]


def _serving(*pages: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """Serve ``pages`` in order, keyed by the token each request carries."""
    by_token: dict[str, dict[str, Any]] = {}
    token = ""
    for page in pages:
        by_token[token] = page
        token = page["nextPageToken"]
    return lambda request: httpx.Response(200, json=by_token[request.url.params.get("pageToken", "")])


class TestRegistration:
    def test_the_connector_is_in_the_registry(self) -> None:
        assert "eset_protect" in {cls.connector_id for cls in _CONNECTOR_CLASSES}

    def test_only_the_password_is_secret_and_every_field_is_required(self) -> None:
        fields = {f.name: (f.type, f.required) for f in ESETProtectConnector.schema().fields}
        assert fields == {"region": ("select", True), "username": ("string", True), "password": ("secret", True)}

    def test_the_region_offers_the_five_documented_regions(self) -> None:
        (region,) = [f for f in ESETProtectConnector.schema().fields if f.name == "region"]
        assert [option["value"] for option in region.options or []] == ["eu", "de", "us", "ca", "jpn"]

    def test_it_is_a_read_only_edr_source(self) -> None:
        assert ESETProtectConnector.schema().category == "edr"
        assert ESETProtectConnector.capabilities() == (Capability.PULL_ALERTS,)

    def test_the_docs_url_matches_the_generated_slug(self) -> None:
        assert ESETProtectConnector.schema().docs_url == "/docs/connectors/eset-protect"

    @pytest.mark.parametrize("region", ["", "apac", "https://eu.incident-management.eset.systems", "attacker.example"])
    def test_a_region_outside_the_five_is_refused_at_construction(self, region: str) -> None:
        with pytest.raises(ValueError, match="not an ESET Connect region"):
            ESETProtectConnector(region=region, username="u", password="p")


class TestWhereTheCredentialGoes:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("region", ["eu", "de", "us", "ca", "jpn", " US "])
    async def test_every_request_goes_to_the_regions_eset_hosts_over_https(self, region: str) -> None:
        vendor = Vendor(_serving(_page([_detection("d-1")])))
        await vendor.connector(region).fetch_alerts()
        key = region.strip().lower()
        assert [(r.url.scheme, r.url.host, r.url.path) for r in vendor.requests] == [
            ("https", f"{key}.business-account.iam.eset.systems", "/oauth/token"),
            ("https", f"{key}.incident-management.eset.systems", "/v1/detections"),
            ("https", f"{key}.device-management.eset.systems", "/v1/devices:batchGet"),
        ]

    @pytest.mark.asyncio
    async def test_the_token_is_a_password_grant_and_is_sent_as_a_bearer(self) -> None:
        vendor = Vendor()
        await vendor.connector().fetch_alerts()
        (exchange,) = vendor.on("/oauth/token")
        assert exchange.method == "POST"
        assert exchange.headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert parse_qs(exchange.content.decode()) == {
            "grant_type": ["password"],
            "username": ["api@corp.example"],
            "password": ["api-password"],
        }
        (read,) = vendor.on("/v1/detections")
        assert read.headers["Authorization"] == "Bearer access-1"

    @pytest.mark.asyncio
    async def test_one_token_serves_the_whole_poll(self) -> None:
        vendor = Vendor(_serving(_page([_detection("d-1")], token="p2"), _page([_detection("d-2")])))
        await vendor.connector().fetch_alerts()
        assert len(vendor.on("/oauth/token")) == 1
        assert len(vendor.on("/v1/detections")) == 2

    @pytest.mark.asyncio
    async def test_a_cached_token_refused_early_is_exchanged_once_more(self) -> None:
        issued = iter(["access-1", "access-2"])

        def token(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"access_token": next(issued), "expires_in": 3600})

        def detections(request: httpx.Request) -> httpx.Response:
            if request.headers["Authorization"] == "Bearer access-1" and "pageToken" in request.url.params:
                return httpx.Response(401, json={"message": "token expired"})
            return httpx.Response(200, json=_page([_detection("d-1")], token="" if "pageToken" in request.url.params else "p2"))

        vendor = Vendor(detections, token=token)
        out = await vendor.connector().fetch_alerts()
        assert len(vendor.on("/oauth/token")) == 2
        assert [r.headers["Authorization"] for r in vendor.on("/v1/detections")] == [
            "Bearer access-1",
            "Bearer access-1",
            "Bearer access-2",
        ]
        assert [row["external_id"] for row in out] == ["d-1"]

    @pytest.mark.asyncio
    async def test_a_token_reissued_on_expiry_and_then_refused_is_not_exchanged_again(self) -> None:
        """The token used was issued for this very request, so its refusal is the credential's."""

        def token(request: httpx.Request) -> httpx.Response:
            # Expires inside the headroom, so every request exchanges anew.
            return httpx.Response(200, json={"access_token": f"access-{len(vendor.on('/oauth/token'))}", "expires_in": 30})

        def detections(request: httpx.Request) -> httpx.Response:
            if "pageToken" not in request.url.params:
                return httpx.Response(200, json=_page([_detection("d-1")], token="p2"))
            return httpx.Response(401, json={"message": "unauthorized"})

        vendor = Vendor(detections, token=token)
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["d-1"]
        # One exchange per detections request, and none more for the refusal.
        assert len(vendor.on("/v1/detections")) == 2
        assert [r.headers["Authorization"] for r in vendor.on("/v1/detections")] == ["Bearer access-1", "Bearer access-2"]
        assert len(vendor.on("/oauth/token")) == 3

    @pytest.mark.asyncio
    async def test_a_freshly_issued_token_that_is_refused_fails_instead_of_looping(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(401, json={"message": "unauthorized"}))
        with pytest.raises(ESETProtectError, match="HTTP 401 to GET /v1/detections.*Integrations"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.on("/oauth/token")) == 1
        assert len(vendor.on("/v1/detections")) == 1

    @pytest.mark.asyncio
    async def test_the_next_page_is_requested_by_token_from_the_configured_host(self) -> None:
        vendor = Vendor(_serving(_page([_detection("d-1")], token="dG9rZW4"), _page([_detection("d-2")])))
        await vendor.connector().fetch_alerts()
        reads = vendor.on("/v1/detections")
        assert [r.url.host for r in reads] == ["eu.incident-management.eset.systems"] * 2
        assert "pageToken" not in reads[0].url.params
        assert reads[1].url.params["pageToken"] == "dG9rZW4"


class TestReadingTheWindow:
    @pytest.mark.asyncio
    async def test_the_window_is_asked_for_by_start_and_end_time_at_the_documented_maximum(self) -> None:
        vendor = Vendor()
        before = datetime.now(UTC).replace(microsecond=0)
        await vendor.connector().fetch_alerts(since_seconds=600)
        after = datetime.now(UTC)
        (read,) = vendor.on("/v1/detections")
        params = dict(read.url.params)
        assert params["pageSize"] == "1000"
        start = datetime.fromisoformat(params["startTime"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(params["endTime"].replace("Z", "+00:00"))
        assert params["startTime"].endswith("Z") and params["endTime"].endswith("Z")
        assert before - timedelta(seconds=601) <= start <= after - timedelta(seconds=599)
        # `endTime` is exclusive, so it lies past the moment the read began.
        assert before < end <= after + timedelta(seconds=1)

    @pytest.mark.asyncio
    async def test_every_page_is_followed_until_the_token_is_empty(self) -> None:
        vendor = Vendor(
            _serving(
                _page([_detection(f"a-{i}") for i in range(1000)], token="p2"),
                _page([_detection(f"b-{i}") for i in range(1000)], token="p3"),
                _page([_detection(f"c-{i}") for i in range(7)]),
            )
        )
        out = await vendor.connector().fetch_alerts()
        assert len(out) == 2007
        assert [r.url.params.get("pageToken") for r in vendor.on("/v1/detections")] == [None, "p2", "p3"]

    @pytest.mark.asyncio
    async def test_an_empty_page_with_a_token_does_not_end_the_read(self) -> None:
        vendor = Vendor(_serving(_page([], token="p2"), _page([_detection("d-1")])))
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["d-1"]

    @pytest.mark.asyncio
    async def test_a_failure_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def detections(request: httpx.Request) -> httpx.Response:
            if "pageToken" not in request.url.params:
                return httpx.Response(200, json=_page([_detection("d-1"), _detection("d-2")], token="p2"))
            return httpx.Response(503, text="maintenance")

        out = await Vendor(detections).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["d-1", "d-2"]

    @pytest.mark.asyncio
    async def test_a_transport_error_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def detections(request: httpx.Request) -> httpx.Response:
            if "pageToken" not in request.url.params:
                return httpx.Response(200, json=_page([_detection("d-1")], token="p2"))
            raise httpx.ReadTimeout("timed out", request=request)

        out = await Vendor(detections).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["d-1"]

    @pytest.mark.asyncio
    async def test_a_refused_token_exchange_part_way_keeps_the_pages_already_read(self) -> None:
        exchanges: list[httpx.Request] = []

        def token(request: httpx.Request) -> httpx.Response:
            # The first exchange succeeds and every later one is refused, as
            # when the API user's password is changed part-way through a poll.
            exchanges.append(request)
            return _token_response(request) if len(exchanges) == 1 else httpx.Response(400, json={"error": "invalid_grant"})

        def detections(request: httpx.Request) -> httpx.Response:
            if "pageToken" not in request.url.params:
                return httpx.Response(200, json=_page([_detection("d-1")], token="p2"))
            return httpx.Response(401, json={"message": "token expired"})

        with structlog.testing.capture_logs() as logs:
            out = await Vendor(detections, token=token).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["d-1"]
        assert any(entry["event"] == "connector.paging.token_page_error" and "invalid_grant" in entry["error"] for entry in logs)

    @pytest.mark.asyncio
    async def test_a_collection_that_never_ends_is_bounded_and_announced(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(200, json=_page([_detection("d-1")], token="again")))
        with structlog.testing.capture_logs() as logs:
            await vendor.connector().fetch_alerts()
        assert len(vendor.on("/v1/detections")) == DEFAULT_MAX_PAGES
        assert any(entry["event"] == "connector.paging.page_cap_reached" for entry in logs)


class TestASlowAnswer:
    @pytest.mark.asyncio
    async def test_a_202_is_re_sent_with_its_response_id_until_eset_answers(self) -> None:
        answers = iter(
            [
                httpx.Response(202, json=[], headers={"response-id": "c0ffee00-0000-4000-8000-000000000001"}),
                httpx.Response(202, json=[], headers={"response-id": "c0ffee00-0000-4000-8000-000000000001"}),
                httpx.Response(200, json=_page([_detection("d-1")])),
            ]
        )
        vendor = Vendor(lambda request: next(answers))
        out = await vendor.connector().fetch_alerts()
        reads = vendor.on("/v1/detections")
        assert [r.headers.get("response-id") for r in reads] == [
            None,
            "c0ffee00-0000-4000-8000-000000000001",
            "c0ffee00-0000-4000-8000-000000000001",
        ]
        # ESET retrieves the cached result only for an identical query.
        assert len({str(r.url) for r in reads}) == 1
        assert [row["external_id"] for row in out] == ["d-1"]

    @pytest.mark.asyncio
    async def test_a_202_that_never_resolves_fails_the_poll_within_esets_limit(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(202, json=[], headers={"response-id": "c0ffee00"}))
        with pytest.raises(ESETProtectError, match="HTTP 202.*still preparing"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.on("/v1/detections")) == _PENDING_ATTEMPTS + 1

    @pytest.mark.asyncio
    async def test_a_202_without_a_response_id_is_not_retried(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(202, json=[]))
        with pytest.raises(ESETProtectError, match="HTTP 202"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.on("/v1/detections")) == 1


class TestWhatIsReturned:
    @pytest.mark.asyncio
    async def test_a_detection_after_the_read_began_is_left_for_the_next_window(self) -> None:
        """The next poll's window opens where this one closed, so raising it here would raise it twice."""
        vendor = Vendor(_serving(_page([_detection("d-1", occurred=-1), _detection("d-2", occurred=60)])))
        out = await vendor.connector().fetch_alerts(since_seconds=300)
        assert [row["external_id"] for row in out] == ["d-2"]

    @pytest.mark.asyncio
    async def test_a_detection_before_the_window_opened_is_not_raised_again(self) -> None:
        """The request opens at the start of the window's first second, so the second before it is filtered here."""
        vendor = Vendor(_serving(_page([_detection("d-1", occurred=302), _detection("d-2", occurred=60)])))
        out = await vendor.connector().fetch_alerts(since_seconds=300)
        assert [row["external_id"] for row in out] == ["d-2"]

    @pytest.mark.asyncio
    async def test_an_offset_timestamp_is_compared_as_the_instant_it_names(self) -> None:
        """A wall-clock reading in +05:30 is a minute old, not five and a half hours in the future."""
        occurred = (datetime.now(UTC) - timedelta(seconds=60)).astimezone(timezone(timedelta(hours=5, minutes=30)))
        vendor = Vendor(_serving(_page([_detection("d-1", occurTime=occurred.isoformat())])))
        assert len(await vendor.connector().fetch_alerts(since_seconds=300)) == 1

    @pytest.mark.asyncio
    async def test_a_detection_returned_on_two_pages_is_raised_once(self) -> None:
        vendor = Vendor(_serving(_page([_detection("d-1"), _detection("d-2")], token="p2"), _page([_detection("d-2"), _detection("d-3")])))
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["d-1", "d-2", "d-3"]

    @pytest.mark.asyncio
    async def test_a_detection_with_an_unreadable_time_is_kept(self) -> None:
        """ESET filtered it into the window; a time this side cannot parse is not a reason to drop it."""
        vendor = Vendor(_serving(_page([_detection("d-1", occurred=None), _detection("d-2", occurTime="yesterday")])))
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["d-1", "d-2"]


class TestTheHostBehindADetection:
    @pytest.mark.asyncio
    async def test_the_device_is_looked_up_and_its_host_lifted(self) -> None:
        vendor = Vendor(_serving(_page([_detection("d-1")])))
        (event,) = await vendor.connector().fetch_alerts()
        (lookup,) = vendor.on("/v1/devices:batchGet")
        assert lookup.url.params.get_list("devicesUuids") == [_DEVICE_UUID]
        assert lookup.headers["Authorization"] == "Bearer access-1"
        assert event["hostname"] == "WS-0142.corp.example"
        assert event["os"] == "Microsoft Windows 11 Pro"
        assert event["external_ip"] == "203.0.113.9"
        assert event["raw_event"]["device"]["uuid"] == _DEVICE_UUID

    @pytest.mark.asyncio
    async def test_distinct_devices_are_looked_up_once_in_batches(self) -> None:
        detections = [
            _detection(f"d-{i}", context={**_DETECTION["context"], "deviceUuid": _uuid(i % (_DEVICE_BATCH + 3))}) for i in range(120)
        ]
        vendor = Vendor(_serving(_page(detections)))
        out = await vendor.connector().fetch_alerts()
        batches = [r.url.params.get_list("devicesUuids") for r in vendor.on("/v1/devices:batchGet")]
        assert [len(batch) for batch in batches] == [_DEVICE_BATCH, 3]
        assert sorted(uuid for batch in batches for uuid in batch) == sorted(_uuid(i) for i in range(_DEVICE_BATCH + 3))
        assert len(out) == 120
        assert all(row["hostname"] == "WS-0142.corp.example" for row in out)

    @pytest.mark.asyncio
    async def test_the_lookups_are_bounded_and_the_bound_announced(self) -> None:
        detections = [_detection(f"d-{i}", context={"deviceUuid": _uuid(i)}) for i in range(_MAX_DEVICE_LOOKUPS + 5)]
        vendor = Vendor(_serving(_page(detections)))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        looked_up = sum(len(r.url.params.get_list("devicesUuids")) for r in vendor.on("/v1/devices:batchGet"))
        assert looked_up == _MAX_DEVICE_LOOKUPS
        assert len(out) == _MAX_DEVICE_LOOKUPS + 5
        assert sum("hostname" in row for row in out) == _MAX_DEVICE_LOOKUPS
        (capped,) = [entry for entry in logs if entry["event"] == "eset_protect.device_lookups_capped"]
        assert (capped["devices"], capped["looked_up"]) == (_MAX_DEVICE_LOOKUPS + 5, _MAX_DEVICE_LOOKUPS)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("device_uuid", ["../v1/devices", "not-a-uuid", "", None, 42])
    async def test_only_a_well_formed_uuid_reaches_a_request(self, device_uuid: Any) -> None:
        vendor = Vendor(_serving(_page([_detection("d-1", context={"deviceUuid": device_uuid})])))
        (event,) = await vendor.connector().fetch_alerts()
        assert vendor.on("/v1/devices:batchGet") == []
        assert "hostname" not in event

    @pytest.mark.asyncio
    async def test_a_device_eset_did_not_return_is_not_taken_from_another(self) -> None:
        def devices(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"devices": [{**_DEVICE, "uuid": _uuid(999)}, "not an object"]})

        vendor = Vendor(_serving(_page([_detection("d-1")])), devices=devices)
        (event,) = await vendor.connector().fetch_alerts()
        assert "hostname" not in event
        assert "device" not in event["raw_event"]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "answer",
        [
            httpx.Response(429, text="Too Many Requests"),
            httpx.Response(202, json=[], headers={"response-id": "c0ffee00"}),
        ],
        ids=["rate-limited", "still-pending"],
    )
    async def test_a_rate_limit_or_a_result_never_ready_stops_the_lookups_and_keeps_every_detection(self, answer: httpx.Response) -> None:
        detections = [_detection(f"d-{i}", context={"deviceUuid": _uuid(i)}) for i in range(_DEVICE_BATCH * 3)]
        vendor = Vendor(_serving(_page(detections)), devices=lambda request: answer)
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        # One batch, however many times a pending one was re-sent.
        assert len({str(r.url) for r in vendor.on("/v1/devices:batchGet")}) == 1
        assert len(out) == _DEVICE_BATCH * 3
        assert all("hostname" not in row for row in out)
        (stopped,) = [entry for entry in logs if entry["event"] == "eset_protect.device_lookups_stopped"]
        assert stopped["status"] == answer.status_code

    @pytest.mark.asyncio
    async def test_a_failed_lookup_costs_the_host_never_the_detection(self) -> None:
        calls = iter(["refused", "unreachable", "garbled"])

        def devices(request: httpx.Request) -> httpx.Response:
            outcome = next(calls)
            if outcome == "unreachable":
                raise httpx.ConnectError("connection reset", request=request)
            if outcome == "refused":
                return httpx.Response(404, json={"message": "not found"})
            return httpx.Response(200, text="not json")

        detections = [_detection(f"d-{i}", context={"deviceUuid": _uuid(i)}) for i in range(_DEVICE_BATCH * 3)]
        out = await Vendor(_serving(_page(detections)), devices=devices).connector().fetch_alerts()
        assert len(out) == _DEVICE_BATCH * 3
        assert all("hostname" not in row and "device" not in row["raw_event"] for row in out)


class TestFailures:
    @pytest.mark.asyncio
    async def test_a_refused_credential_says_what_to_check(self) -> None:
        vendor = Vendor(token=lambda request: httpx.Response(400, json={"error": "invalid_grant"}))
        with pytest.raises(ESETProtectError, match="HTTP 400 to POST /oauth/token.*region.*signed in"):
            await vendor.connector().fetch_alerts()
        assert vendor.on("/v1/detections") == []

    @pytest.mark.asyncio
    async def test_a_token_answer_without_a_token_is_refused(self) -> None:
        vendor = Vendor(token=lambda request: httpx.Response(200, json={"token_type": "Bearer"}))
        with pytest.raises(ESETProtectError, match="without an access_token"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_a_refused_opening_request_raises_rather_than_reading_as_quiet(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(503, json={"message": "Environment under maintenance"}))
        with pytest.raises(ESETProtectError, match="HTTP 503 to GET /v1/detections"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_unreachable_api_raises_rather_than_reading_as_quiet(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        with pytest.raises(ESETProtectError, match="could not be reached at eu.incident-management.eset.systems.*connection refused"):
            await Vendor(unreachable).connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_unreachable_token_host_raises(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        with pytest.raises(ESETProtectError, match="could not be reached at eu.business-account.iam.eset.systems"):
            await Vendor(token=unreachable).connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_a_forbidden_user_names_the_integrations_toggle(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(403, json={"message": "Access denied"}))
        with pytest.raises(ESETProtectError, match="HTTP 403.*Integrations"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_exhausted_rate_limit_says_so(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(429, json={"message": "Rate limit reached"}))
        with pytest.raises(ESETProtectError, match="HTTP 429.*next poll retries"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_a_working_connection_reads_one_detection(self) -> None:
        vendor = Vendor()
        result = await vendor.connector("us").test_connection()
        assert result == {"success": True, "connector": "eset_protect", "region": "us"}
        (read,) = vendor.on("/v1/detections")
        assert (read.url.host, read.url.params["pageSize"]) == ("us.incident-management.eset.systems", "1")
        assert {"startTime", "endTime"} <= set(read.url.params)

    @pytest.mark.asyncio
    async def test_bad_credentials_are_reported_by_test_connection(self) -> None:
        vendor = Vendor(token=lambda request: httpx.Response(401, json={"error": "unauthorized"}))
        result = await vendor.connector().test_connection()
        assert (result["success"], result["connector"]) == (False, "eset_protect")
        assert result["error"].startswith("ESET answered HTTP 401 to POST /oauth/token")

    @pytest.mark.asyncio
    async def test_a_refused_read_is_reported_by_test_connection(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(403, json={"message": "Access denied"}))
        result = await vendor.connector().test_connection()
        assert result["success"] is False
        assert result["error"].startswith("ESET answered HTTP 403 to GET /v1/detections")

    @pytest.mark.asyncio
    async def test_a_network_failure_is_reported_by_test_connection(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        result = await Vendor(unreachable).connector().test_connection()
        assert result["success"] is False
        assert "connection refused" in result["error"]


class TestNormalize:
    def _normalize(self, **overrides: Any) -> dict[str, Any]:
        return ESETProtectConnector(region="eu", username="u", password="p").normalize({**_DETECTION, **overrides})

    def test_the_envelope_is_canonical(self) -> None:
        event = self._normalize()
        assert event["source"] == "eset_protect"
        assert event["raw_event"] == _DETECTION
        assert "raw" not in event
        assert event["external_id"] == "9f8e7d6c-5b4a-4321-8fed-cba987654321"
        assert event["title"] == "Win32/Injector.DTLK"
        assert event["description"].startswith("Event occurred on a new file")
        assert event["created_at"] == "2026-11-12T09:41:07Z"

    def test_the_detection_context_is_kept(self) -> None:
        event = self._normalize()
        assert event["category"] == "antivirus"
        assert event["object_type"] == "File"
        assert event["object_name"] == "invoice.exe"
        assert event["object_url"] == "C:\\Users\\jdoe\\Downloads\\invoice.exe"
        assert event["sha1"] == _DETECTION["objectHashSha1"]
        assert event["sha256"] == _DETECTION["objectHashSha256"]
        assert event["process_path"] == "C:\\Windows\\explorer.exe"
        assert event["actor"] == "CORP\\jdoe"
        assert event["endpoint_id"] == _DEVICE_UUID
        assert event["protocol"] == "TCP"
        assert event["responses"] == ["cleaned by deleting"]

    def test_the_deprecated_type_name_titles_a_detection_without_a_display_name(self) -> None:
        assert self._normalize(displayName=None)["title"] == "Trojan"
        assert self._normalize(displayName="", typeName=None)["title"] == "ESET PROTECT detection"

    def test_an_outbound_connection_has_the_host_as_its_source(self) -> None:
        event = self._normalize()
        assert (event["src_ip"], event["src_port"], event["dst_ip"], event["dst_port"]) == ("192.0.2.42", 50112, "198.51.100.7", 443)

    def test_an_inbound_connection_has_the_peer_as_its_source(self) -> None:
        network = {**_DETECTION["networkCommunication"], "direction": "NETWORK_COMMUNICATION_DIRECTION_INBOUND"}
        event = self._normalize(networkCommunication=network)
        assert (event["src_ip"], event["src_port"], event["dst_ip"], event["dst_port"]) == ("198.51.100.7", 443, "192.0.2.42", 50112)

    def test_a_connection_without_a_direction_names_no_source_peer(self) -> None:
        network = {**_DETECTION["networkCommunication"], "direction": "NETWORK_COMMUNICATION_DIRECTION_UNSPECIFIED"}
        event = self._normalize(networkCommunication=network)
        assert (event["src_ip"], event["remote_ip"]) == ("192.0.2.42", "198.51.100.7")
        for key in ("dst_ip", "src_port", "dst_port"):
            assert key not in event

    def test_the_devices_address_stands_in_for_a_missing_local_address(self) -> None:
        event = self._normalize(networkCommunication=None, device=_DEVICE)
        assert event["src_ip"] == "192.0.2.42"
        assert "remote_ip" not in event

    def test_the_hostname_falls_back_to_the_console_name(self) -> None:
        assert self._normalize(device={**_DEVICE, "systemHostname": ""})["hostname"] == "Finance laptop 12"

    @pytest.mark.parametrize(("port", "expected"), [("443", 443), (0, None), (70000, None), (True, None), ("https", None)])
    def test_ports_are_numbers_in_range(self, port: Any, expected: int | None) -> None:
        network = {**_DETECTION["networkCommunication"], "remotePort": port}
        assert self._normalize(networkCommunication=network).get("dst_port") == expected

    def test_a_detection_without_a_device_record_has_no_host(self) -> None:
        event = self._normalize()
        for key in ("hostname", "os", "external_ip"):
            assert key not in event

    def test_malformed_fields_are_tolerated(self) -> None:
        event = self._normalize(
            uuid=7, displayName=["x"], context="not an object", networkCommunication=[], responses="cleaned", category=3, device="nope"
        )
        assert event["title"] == "Trojan"
        for key in ("external_id", "description", "actor", "src_ip", "responses", "category", "hostname"):
            assert key not in event

    @pytest.mark.parametrize("category", ["DETECTION_CATEGORY_UNSPECIFIED", "ANTIVIRUS", ""])
    def test_an_unspecified_or_unknown_category_is_left_out(self, category: str) -> None:
        assert "category" not in self._normalize(category=category)

    @pytest.mark.parametrize(
        ("vendor", "tier"),
        [
            ("SEVERITY_LEVEL_DIAGNOSTIC", "info"),
            ("SEVERITY_LEVEL_INFORMATIONAL", "info"),
            ("SEVERITY_LEVEL_LOW", "low"),
            ("SEVERITY_LEVEL_MEDIUM", "medium"),
            ("SEVERITY_LEVEL_HIGH", "high"),
            (" severity_level_high ", "high"),
        ],
    )
    def test_each_published_level_maps_to_its_own_tier(self, vendor: str, tier: str) -> None:
        assert self._normalize(severityLevel=vendor)["severity"] == tier

    @pytest.mark.parametrize("vendor", ["SEVERITY_LEVEL_UNSPECIFIED", "SEVERITY_LEVEL_CRITICAL", "high", "", None, 4])
    def test_a_level_outside_the_published_ladder_carries_no_severity(self, vendor: Any) -> None:
        assert "severity" not in self._normalize(severityLevel=vendor)
