"""WithSecure Elements Broad Context Detections through the Elements API.

Every host, path, parameter and field name below is the one the WithSecure
Elements API reference lists and the connector module cites. The payloads are
synthetic: they carry the documented field names, UUIDs are made up, and
addresses are RFC 5737 documentation ranges.

The properties pinned here, each a way this could be wired wrong:

1. **The credential only goes to WithSecure.** The host is fixed, the client
   credentials are exchanged with HTTP Basic for a read-only token, and the
   page after the first is requested with `anchor` rather than by any URL a
   response names.
2. **The window is read to the end.** `nextAnchor` is followed until it is
   absent, a failed later page keeps what was read, and the bound is
   announced when it binds.
3. **A BCD is raised once.** The window is on `createdTimestamp`, closed at
   the moment the read began, and opens at the persisted cursor.
4. **WithSecure's own duplicates and suppressions are not raised.**
5. **The context comes from the detections, within budget.** A failed lookup
   never costs the BCD, and a 429 stops the lookups.
6. **The ladder is the vendor's.** Each published level keeps its own tier,
   `critical` stays `critical`, and an undocumented level carries no tier.
"""

from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import structlog
from app.connectors import _CONNECTOR_CLASSES
from app.connectors._paging import DEFAULT_MAX_PAGES
from app.connectors.base import Capability
from app.connectors.withsecure_elements import (
    _DETECTION_PAGES,
    _MAX_DEVICE_LOOKUPS,
    _MAX_INCIDENT_LOOKUPS,
    WithSecureElementsConnector,
    WithSecureElementsError,
)

_ORGANIZATION = "ec8a0100-d313-4896-b3cb-02188e060bf3"
_DEVICE_A = "3a8f06e1-c3e8-4933-b617-e23597111644"
_DEVICE_B = "7c1d2e3f-4a5b-4c6d-8e9f-0a1b2c3d4e5f"


def _ago(seconds: float) -> str:
    """An RFC 3339 timestamp ``seconds`` before now, in the millisecond `Z` form WithSecure sends."""
    return (datetime.now(UTC) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _uuid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


#: One BCD in the shape `GET /incidents/v1/incidents` returns. Synthetic.
_INCIDENT: dict[str, Any] = {
    "incidentId": "2c902c73-e2a6-40fd-9532-257ee102e1c1",
    "incidentPublicId": "3599-4F9929A4",
    "organizationId": _ORGANIZATION,
    "name": "Incident in DESKTOP-1",
    "description": "Credential dumping followed by lateral movement",
    "status": "new",
    "severity": "high",
    "riskLevel": "high",
    "riskScore": 74.86341234,
    "resolution": "unconfirmed",
    "createdTimestamp": "2026-11-12T09:41:07.097Z",
    "updatedTimestamp": "2026-11-12T09:43:12.537Z",
    "initialReceivedTimestamp": "2026-11-12T09:41:05.000Z",
    "categories": ["CREDENTIAL_THEFT", "LATERAL_MOVEMENT"],
    "sources": ["endpoint"],
}

#: Detections `GET /incidents/v1/detections` returns for that BCD, newest first. Synthetic.
_DETECTIONS: list[dict[str, Any]] = [
    {
        "detectionId": "cc04e914-dbea-4785-83cc-60492f03b97d",
        "incidentId": _INCIDENT["incidentId"],
        "deviceId": _DEVICE_B,
        "name": "remoteServiceCreation",
        "detectionClass": "PROCESS",
        "severity": "medium",
        "riskLevel": "medium",
        "exePath": "C:\\Windows\\System32\\sc.exe",
        "exeName": "sc.exe",
        "exeHash": "C8F21EF51FA2F2033A9CA7C0CC0412C25065E2BA",
        "cmdl": "sc \\\\FS-02 create svc binPath= C:\\temp\\a.exe",
        "pid": 4321,
        "createdTimestamp": "2026-11-12T09:42:51.097Z",
        "initialReceivedTimestamp": "2026-11-12T09:42:52.000Z",
        "username": "CORP\\svc-backup",
        "mitre": ["TA0008", "T1021.002"],
    },
    {
        "detectionId": "aa11e914-dbea-4785-83cc-60492f03b97d",
        "incidentId": _INCIDENT["incidentId"],
        "deviceId": _DEVICE_A,
        "name": "credentialDumping",
        "detectionClass": "PROCESS",
        "severity": "high",
        "riskLevel": "high",
        "exePath": "C:\\Users\\jdoe\\AppData\\Local\\Temp\\procdump64.exe",
        "exeName": "procdump64.exe",
        "exeHash": "2C26B46B68FFC68FF99B453C1D30413413422D706483BFA0F98A5E886266E7AE",
        "cmdl": "procdump64.exe -ma lsass.exe out.dmp",
        "pid": 1234,
        "createdTimestamp": "2026-11-12T09:41:07.097Z",
        "initialReceivedTimestamp": "2026-11-12T09:41:08.000Z",
        "username": "CORP\\jdoe",
        "privileges": "Admin",
        "description": "A process read the memory of lsass.exe",
        "mitre": ["TA0006", "T1003", "T1003.001"],
    },
]

#: Device records `GET /devices/v1/devices` returns. Synthetic.
_DEVICES: dict[str, dict[str, Any]] = {
    _DEVICE_A: {
        "id": _DEVICE_A,
        "name": "DESKTOP-1",
        "type": "computer",
        "ipAddresses": "192.0.2.42/24, 198.51.100.4/24",
        "publicIpAddress": "203.0.113.9",
        "os": {"name": "Windows 11 Pro", "version": "10.0.22631"},
    },
    _DEVICE_B: {
        "id": _DEVICE_B,
        "name": "FS-02",
        "type": "computer",
        "ipAddresses": "192.0.2.77",
        "os": {"name": "Windows Server 2022"},
    },
}


def _incident(incident_id: str, *, created: float | None = 60, **overrides: Any) -> dict[str, Any]:
    """A BCD created ``created`` seconds ago."""
    return {**_INCIDENT, "incidentId": incident_id, "createdTimestamp": None if created is None else _ago(created), **overrides}


def _page(items: list[dict[str, Any]], anchor: str = "") -> dict[str, Any]:
    return {"items": items, **({"nextAnchor": anchor} if anchor else {})}


def _token_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"access_token": "access-1", "token_type": "Bearer", "expires_in": 1799})


class Vendor:
    """The Elements API behind one transport."""

    def __init__(
        self,
        incidents: Callable[[httpx.Request], httpx.Response] | None = None,
        detections: Callable[[httpx.Request], httpx.Response] | None = None,
        devices: Callable[[httpx.Request], httpx.Response] | None = None,
        token: Callable[[httpx.Request], httpx.Response] | None = None,
    ) -> None:
        self.requests: list[httpx.Request] = []
        self._incidents = incidents or (lambda request: httpx.Response(200, json=_page([])))
        self._detections = detections or self._known_detections
        self._devices = devices or self._known_devices
        self._token = token or _token_response

    @staticmethod
    def _known_detections(request: httpx.Request) -> httpx.Response:
        incident_id = request.url.params["incidentId"]
        return httpx.Response(200, json=_page([{**d, "incidentId": incident_id} for d in _DETECTIONS]))

    @staticmethod
    def _known_devices(request: httpx.Request) -> httpx.Response:
        device_id = request.url.params["deviceId"]
        record = _DEVICES.get(device_id)
        return httpx.Response(200, json={"items": [record] if record else []})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/as/token.oauth2":
            return self._token(request)
        if request.url.path == "/incidents/v1/incidents":
            return self._incidents(request)
        if request.url.path == "/incidents/v1/detections":
            return self._detections(request)
        if request.url.path == "/devices/v1/devices":
            return self._devices(request)
        return httpx.Response(404, json={"message": "no route"})

    def connector(self, organization_id: str = "") -> WithSecureElementsConnector:
        return WithSecureElementsConnector(
            client_id="fusion_0123456789abcdef",
            client_secret="client-secret",
            organization_id=organization_id,
            transport=httpx.MockTransport(self.handle),
        )

    def on(self, path: str) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == path]


def _serving(*pages: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """Serve ``pages`` in order, keyed by the anchor each request carries."""
    by_anchor: dict[str, dict[str, Any]] = {}
    anchor = ""
    for page in pages:
        by_anchor[anchor] = page
        anchor = page.get("nextAnchor", "")
    return lambda request: httpx.Response(200, json=by_anchor[request.url.params.get("anchor", "")])


def _no_detections(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json=_page([]))


class TestRegistration:
    def test_the_connector_is_in_the_registry(self) -> None:
        assert "withsecure_elements" in {cls.connector_id for cls in _CONNECTOR_CLASSES}

    def test_only_the_client_secret_is_secret_and_the_organization_is_optional(self) -> None:
        fields = {f.name: (f.type, f.required) for f in WithSecureElementsConnector.schema().fields}
        assert fields == {
            "client_id": ("string", True),
            "client_secret": ("secret", True),
            "organization_id": ("string", False),
        }

    def test_it_is_a_read_only_edr_source(self) -> None:
        assert WithSecureElementsConnector.schema().category == "edr"
        assert WithSecureElementsConnector.capabilities() == (Capability.PULL_ALERTS,)

    def test_the_docs_url_matches_the_generated_slug(self) -> None:
        assert WithSecureElementsConnector.schema().docs_url == "/docs/connectors/withsecure-elements"

    def test_it_resumes_from_the_created_timestamp_cursor(self) -> None:
        assert WithSecureElementsConnector.checkpoints()
        assert WithSecureElementsConnector.checkpoint_time_field == ("createdTimestamp",)
        assert WithSecureElementsConnector.checkpoint_id_field == ("incidentId",)

    @pytest.mark.parametrize("organization_id", ["acme", "https://api.connect.withsecure.com", "ec8a0100-d313-4896-b3cb"])
    def test_an_organization_that_is_not_a_uuid_is_refused_at_construction(self, organization_id: str) -> None:
        with pytest.raises(ValueError, match="not a UUID"):
            WithSecureElementsConnector(client_id="c", client_secret="s", organization_id=organization_id)

    def test_an_empty_organization_is_the_clients_own(self) -> None:
        WithSecureElementsConnector(client_id="c", client_secret="s", organization_id="  ")


class TestWhereTheCredentialGoes:
    @pytest.mark.asyncio
    async def test_every_request_goes_to_the_fixed_withsecure_host_over_https(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1))])))
        await vendor.connector().fetch_alerts()
        assert [(r.url.scheme, r.url.host, r.url.path) for r in vendor.requests] == [
            ("https", "api.connect.withsecure.com", "/as/token.oauth2"),
            ("https", "api.connect.withsecure.com", "/incidents/v1/incidents"),
            ("https", "api.connect.withsecure.com", "/incidents/v1/detections"),
            ("https", "api.connect.withsecure.com", "/devices/v1/devices"),
            ("https", "api.connect.withsecure.com", "/devices/v1/devices"),
        ]

    @pytest.mark.asyncio
    async def test_the_token_is_a_read_only_client_credentials_grant_sent_with_basic_auth(self) -> None:
        vendor = Vendor()
        await vendor.connector().fetch_alerts()
        (exchange,) = vendor.on("/as/token.oauth2")
        assert exchange.method == "POST"
        assert exchange.headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert parse_qs(exchange.content.decode()) == {"grant_type": ["client_credentials"], "scope": ["connect.api.read"]}
        expected = base64.b64encode(b"fusion_0123456789abcdef:client-secret").decode()
        assert exchange.headers["Authorization"] == f"Basic {expected}"
        (read,) = vendor.on("/incidents/v1/incidents")
        assert read.headers["Authorization"] == "Bearer access-1"

    @pytest.mark.asyncio
    async def test_every_request_carries_a_user_agent(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1))])))
        await vendor.connector().fetch_alerts()
        assert {r.headers.get("User-Agent") for r in vendor.requests} == {"AiSOC/connectors-withsecure-elements"}

    @pytest.mark.asyncio
    async def test_one_token_serves_the_whole_poll(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1))], anchor="p2"), _page([_incident(_uuid(2))])))
        await vendor.connector().fetch_alerts()
        assert len(vendor.on("/as/token.oauth2")) == 1
        assert len(vendor.on("/incidents/v1/incidents")) == 2

    @pytest.mark.asyncio
    async def test_a_cached_token_refused_early_is_exchanged_once_more(self) -> None:
        issued = iter(["access-1", "access-2"])

        def token(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"access_token": next(issued), "expires_in": 1799})

        def incidents(request: httpx.Request) -> httpx.Response:
            if request.headers["Authorization"] == "Bearer access-1" and "anchor" in request.url.params:
                return httpx.Response(401, json={"message": "Unauthorized.", "code": 401000, "transactionId": "0000-a"})
            last = "anchor" in request.url.params
            return httpx.Response(200, json=_page([_incident(_uuid(2 if last else 1))], anchor="" if last else "p2"))

        vendor = Vendor(incidents, detections=_no_detections, token=token)
        out = await vendor.connector().fetch_alerts()
        assert len(vendor.on("/as/token.oauth2")) == 2
        assert [r.headers["Authorization"] for r in vendor.on("/incidents/v1/incidents")] == [
            "Bearer access-1",
            "Bearer access-1",
            "Bearer access-2",
        ]
        assert [row["external_id"] for row in out] == [_uuid(1), _uuid(2)]

    @pytest.mark.asyncio
    async def test_a_freshly_issued_token_that_is_refused_fails_instead_of_looping(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(401, json={"message": "Unauthorized.", "code": 401000}))
        with pytest.raises(WithSecureElementsError, match="HTTP 401 to GET /incidents/v1/incidents.*API client"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.on("/as/token.oauth2")) == 1
        assert len(vendor.on("/incidents/v1/incidents")) == 1

    @pytest.mark.asyncio
    async def test_a_refused_client_credential_fails_the_poll_with_a_setup_hint(self) -> None:
        vendor = Vendor(
            token=lambda request: httpx.Response(401, json={"error": "invalid_client", "error_description": "Invalid credentials"})
        )
        with pytest.raises(WithSecureElementsError, match="HTTP 401 to POST /as/token.oauth2.*client ID and secret"):
            await vendor.connector().fetch_alerts()
        assert vendor.on("/incidents/v1/incidents") == []

    @pytest.mark.asyncio
    async def test_a_token_answer_without_an_access_token_fails_the_poll(self) -> None:
        vendor = Vendor(token=lambda request: httpx.Response(200, json={"token_type": "Bearer"}))
        with pytest.raises(WithSecureElementsError, match="without an access_token"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_the_next_page_is_requested_by_anchor_from_the_fixed_host(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1))], anchor="bmV4dA"), _page([_incident(_uuid(2))])), detections=_no_detections)
        await vendor.connector().fetch_alerts()
        reads = vendor.on("/incidents/v1/incidents")
        assert [r.url.host for r in reads] == ["api.connect.withsecure.com"] * 2
        assert "anchor" not in reads[0].url.params
        assert reads[1].url.params["anchor"] == "bmV4dA"


class TestTheOrganization:
    @pytest.mark.asyncio
    async def test_a_configured_organization_scopes_every_read(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1))])))
        await vendor.connector(organization_id=_ORGANIZATION.upper()).fetch_alerts()
        reads = [r for r in vendor.requests if r.url.path != "/as/token.oauth2"]
        assert reads
        assert {r.url.params.get("organizationId") for r in reads} == {_ORGANIZATION}

    @pytest.mark.asyncio
    async def test_without_one_the_clients_own_organization_is_read(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1))])))
        await vendor.connector().fetch_alerts()
        assert all("organizationId" not in r.url.params for r in vendor.requests)

    @pytest.mark.asyncio
    async def test_an_organization_outside_the_clients_scope_fails_with_a_hint(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(404, json={"message": "Organization not found", "code": 404000}))
        with pytest.raises(WithSecureElementsError, match="HTTP 404.*organization ID"):
            await vendor.connector(organization_id=_ORGANIZATION).fetch_alerts()


class TestReadingTheWindow:
    @pytest.mark.asyncio
    async def test_the_window_is_asked_for_by_created_time_oldest_first_at_the_documented_maximum(self) -> None:
        vendor = Vendor()
        before = datetime.now(UTC)
        await vendor.connector().fetch_alerts(since_seconds=600)
        after = datetime.now(UTC)
        (read,) = vendor.on("/incidents/v1/incidents")
        params = dict(read.url.params)
        assert params["limit"] == "50"
        assert params["order"] == "asc"
        assert "archived" not in params, "WithSecure does not document when a BCD is archived, so no BCD is filtered out by it"
        assert "updatedTimestampStart" not in params and "updatedTimestampEnd" not in params
        start = datetime.fromisoformat(params["createdTimestampStart"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(params["createdTimestampEnd"].replace("Z", "+00:00"))
        assert params["createdTimestampStart"].endswith("Z") and params["createdTimestampEnd"].endswith("Z")
        assert before - timedelta(seconds=601) <= start <= after - timedelta(seconds=599)
        assert before - timedelta(milliseconds=1) <= end <= after
        assert end - start == timedelta(seconds=600)

    @pytest.mark.asyncio
    async def test_every_page_is_followed_until_the_anchor_is_absent(self) -> None:
        vendor = Vendor(
            _serving(
                _page([_incident(_uuid(i)) for i in range(50)], anchor="p2"),
                _page([_incident(_uuid(100 + i)) for i in range(50)], anchor="p3"),
                _page([_incident(_uuid(200 + i)) for i in range(7)]),
            ),
            detections=_no_detections,
        )
        out = await vendor.connector().fetch_alerts()
        assert len(out) == 107
        assert [r.url.params.get("anchor") for r in vendor.on("/incidents/v1/incidents")] == [None, "p2", "p3"]

    @pytest.mark.asyncio
    async def test_an_empty_page_with_an_anchor_does_not_end_the_read(self) -> None:
        vendor = Vendor(_serving(_page([], anchor="p2"), _page([_incident(_uuid(1))])), detections=_no_detections)
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(1)]

    @pytest.mark.asyncio
    async def test_a_failure_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def incidents(request: httpx.Request) -> httpx.Response:
            if "anchor" not in request.url.params:
                return httpx.Response(200, json=_page([_incident(_uuid(1)), _incident(_uuid(2))], anchor="p2"))
            return httpx.Response(503, text="maintenance")

        vendor = Vendor(incidents, detections=_no_detections)
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(1), _uuid(2)]

    @pytest.mark.asyncio
    async def test_a_later_page_that_cannot_be_reached_keeps_the_pages_already_read(self) -> None:
        def incidents(request: httpx.Request) -> httpx.Response:
            if "anchor" not in request.url.params:
                return httpx.Response(200, json=_page([_incident(_uuid(1))], anchor="p2"))
            raise httpx.ConnectError("connection reset")

        vendor = Vendor(incidents, detections=_no_detections)
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(1)]

    @pytest.mark.asyncio
    async def test_a_token_exchange_refused_part_way_through_keeps_the_pages_already_read(self) -> None:
        calls = {"token": 0}

        def token(request: httpx.Request) -> httpx.Response:
            calls["token"] += 1
            if calls["token"] == 1:
                return httpx.Response(200, json={"access_token": "access-1", "expires_in": 1799})
            return httpx.Response(400, json={"error": "invalid_request"})

        def incidents(request: httpx.Request) -> httpx.Response:
            if "anchor" not in request.url.params:
                return httpx.Response(200, json=_page([_incident(_uuid(1))], anchor="p2"))
            return httpx.Response(401, json={"message": "Unauthorized."})

        vendor = Vendor(incidents, detections=_no_detections, token=token)
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(1)]

    @pytest.mark.asyncio
    async def test_the_page_bound_is_announced_when_it_binds(self) -> None:
        pages = [_page([_incident(_uuid(p * 100 + i)) for i in range(50)], anchor=f"p{p + 1}") for p in range(DEFAULT_MAX_PAGES + 1)]
        vendor = Vendor(_serving(*pages), detections=_no_detections, devices=lambda request: httpx.Response(200, json={"items": []}))
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(vendor.on("/incidents/v1/incidents")) == DEFAULT_MAX_PAGES
        assert len(out) == DEFAULT_MAX_PAGES * 50
        assert any(entry.get("feed") == "withsecure_elements.incidents" and entry["log_level"] == "warning" for entry in logs)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [400, 403, 404, 429, 500, 503])
    async def test_a_refused_opening_request_fails_the_poll(self, status: int) -> None:
        vendor = Vendor(lambda request: httpx.Response(status, json={"message": "no", "code": status * 1000}))
        with pytest.raises(WithSecureElementsError, match=f"HTTP {status} to GET /incidents/v1/incidents"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_unreachable_opening_request_fails_the_poll(self) -> None:
        def incidents(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("name resolution failed")

        vendor = Vendor(incidents)
        with pytest.raises(WithSecureElementsError, match="could not be reached at api.connect.withsecure.com"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_unreachable_token_endpoint_fails_the_poll(self) -> None:
        def token(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("name resolution failed")

        vendor = Vendor(token=token)
        with pytest.raises(WithSecureElementsError, match="could not be reached"):
            await vendor.connector().fetch_alerts()


class TestEachBCDIsRaisedOnce:
    @pytest.mark.asyncio
    async def test_a_bcd_created_before_the_window_is_not_raised_even_if_returned(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1), created=900), _incident(_uuid(2), created=60)])), detections=_no_detections)
        out = await vendor.connector().fetch_alerts(since_seconds=300)
        assert [row["external_id"] for row in out] == [_uuid(2)]

    @pytest.mark.asyncio
    async def test_a_bcd_created_after_the_read_began_is_left_for_the_next_poll(self) -> None:
        future = (datetime.now(UTC) + timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        vendor = Vendor(
            _serving(_page([_incident(_uuid(1)), {**_incident(_uuid(2)), "createdTimestamp": future}])), detections=_no_detections
        )
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(1)]

    @pytest.mark.asyncio
    async def test_a_bcd_returned_twice_in_one_read_is_raised_once(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1))], anchor="p2"), _page([_incident(_uuid(1))])), detections=_no_detections)
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(1)]
        assert len(vendor.on("/incidents/v1/detections")) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize("resolution", ["merged", "autoFalsePositive", "autoAcceptedBehavior"])
    async def test_a_bcd_withsecure_closed_by_itself_is_not_raised(self, resolution: str) -> None:
        vendor = Vendor(
            _serving(_page([_incident(_uuid(1), status="closed", resolution=resolution), _incident(_uuid(2))])), detections=_no_detections
        )
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(2)]
        assert [r.url.params["incidentId"] for r in vendor.on("/incidents/v1/detections")] == [_uuid(2)]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("resolution", ["falsePositive", "securityTest", "acceptedBehavior", "incident"])
    async def test_a_bcd_closed_by_an_analyst_is_still_raised_with_its_resolution(self, resolution: str) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1), status="closed", resolution=resolution)])), detections=_no_detections)
        (row,) = await vendor.connector().fetch_alerts()
        assert (row["status"], row["resolution"]) == ("closed", resolution)

    @pytest.mark.asyncio
    async def test_a_bcd_without_a_creation_time_is_kept(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1), created=None)])), detections=_no_detections)
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(1)]


class TestTheDetectionsBehindABCD:
    @pytest.mark.asyncio
    async def test_the_detections_of_each_bcd_are_read_at_the_documented_maximum(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1)), _incident(_uuid(2))])))
        await vendor.connector(organization_id=_ORGANIZATION).fetch_alerts()
        reads = vendor.on("/incidents/v1/detections")
        assert [dict(r.url.params) for r in reads] == [
            {"organizationId": _ORGANIZATION, "incidentId": _uuid(1), "limit": "100"},
            {"organizationId": _ORGANIZATION, "incidentId": _uuid(2), "limit": "100"},
        ]

    @pytest.mark.asyncio
    async def test_the_detections_and_devices_ride_on_the_bcd_for_replay(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1))])))
        connector = vendor.connector()
        (row,) = await connector.fetch_alerts()
        raw = row["raw_event"]
        assert [d["detectionId"] for d in raw["detections"]] == [d["detectionId"] for d in _DETECTIONS]
        assert [d["id"] for d in raw["devices"]] == [_DEVICE_B, _DEVICE_A]
        assert connector.normalize(raw) == row

    @pytest.mark.asyncio
    async def test_a_detections_open_ended_activity_context_is_not_stored(self) -> None:
        context = [{"type": "histogram", "detectionCountHistogram": list(range(500))}]

        def detections(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_page([{**d, "activityContext": context} for d in _DETECTIONS]))

        vendor = Vendor(_serving(_page([_incident(_uuid(1))])), detections=detections)
        (row,) = await vendor.connector().fetch_alerts()
        stored = row["raw_event"]["detections"]
        assert [d["detectionId"] for d in stored] == [d["detectionId"] for d in _DETECTIONS]
        assert all("activityContext" not in d for d in stored)
        assert stored[1]["mitre"] == _DETECTIONS[1]["mitre"]

    @pytest.mark.asyncio
    async def test_the_detection_pages_are_followed_within_their_bound(self) -> None:
        def detections(request: httpx.Request) -> httpx.Response:
            anchor = request.url.params.get("anchor", "")
            number = int(anchor[1:]) if anchor else 0
            return httpx.Response(200, json=_page([{**_DETECTIONS[0], "detectionId": f"d-{number}"}], anchor=f"d{number + 1}"))

        vendor = Vendor(_serving(_page([_incident(_uuid(1))])), detections=detections)
        (row,) = await vendor.connector().fetch_alerts()
        assert len(vendor.on("/incidents/v1/detections")) == _DETECTION_PAGES
        assert row["detection_count"] == _DETECTION_PAGES

    @pytest.mark.asyncio
    @pytest.mark.parametrize("status", [403, 500, 503])
    async def test_a_failed_detection_read_costs_the_context_not_the_bcd(self, status: int) -> None:
        vendor = Vendor(
            _serving(_page([_incident(_uuid(1)), _incident(_uuid(2))])),
            detections=lambda request: httpx.Response(status, json={"message": "no"}),
        )
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(1), _uuid(2)]
        assert all("hostname" not in row and "detections" not in row["raw_event"] for row in out)
        assert len(vendor.on("/incidents/v1/detections")) == 2
        assert vendor.on("/devices/v1/devices") == []

    @pytest.mark.asyncio
    async def test_an_unreachable_detection_read_costs_the_context_not_the_bcd(self) -> None:
        def detections(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection reset")

        vendor = Vendor(_serving(_page([_incident(_uuid(1))])), detections=detections)
        out = await vendor.connector().fetch_alerts()
        assert [row["external_id"] for row in out] == [_uuid(1)]

    @pytest.mark.asyncio
    async def test_a_429_on_detections_stops_the_detection_reads(self) -> None:
        vendor = Vendor(
            _serving(_page([_incident(_uuid(i)) for i in range(5)])),
            detections=lambda request: httpx.Response(429, json={"message": "Too many requests"}),
        )
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(out) == 5
        assert len(vendor.on("/incidents/v1/detections")) == 1
        assert any(entry["event"] == "withsecure_elements.detection_lookups_stopped" for entry in logs)

    @pytest.mark.asyncio
    async def test_the_detection_reads_are_bounded_per_poll(self) -> None:
        count = _MAX_INCIDENT_LOOKUPS + 5
        incidents = [_incident(_uuid(i)) for i in range(count)]
        pages = [incidents[start : start + 50] for start in range(0, count, 50)]
        vendor = Vendor(
            _serving(*[_page(rows, anchor=f"p{n + 1}" if n + 1 < len(pages) else "") for n, rows in enumerate(pages)]),
            detections=_no_detections,
        )
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(out) == count
        assert len(vendor.on("/incidents/v1/detections")) == _MAX_INCIDENT_LOOKUPS
        assert any(entry["event"] == "withsecure_elements.detection_lookups_capped" for entry in logs)

    @pytest.mark.asyncio
    async def test_when_the_bound_binds_the_most_severe_bcds_are_read_first(self) -> None:
        count = _MAX_INCIDENT_LOOKUPS + 2
        incidents = [_incident(_uuid(i), severity="low") for i in range(count - 2)]
        incidents += [_incident(_uuid(900), severity="critical"), _incident(_uuid(901), severity="high")]
        pages = [incidents[start : start + 50] for start in range(0, count, 50)]
        vendor = Vendor(
            _serving(*[_page(rows, anchor=f"p{n + 1}" if n + 1 < len(pages) else "") for n, rows in enumerate(pages)]),
            detections=_no_detections,
        )
        await vendor.connector().fetch_alerts()
        read = [r.url.params["incidentId"] for r in vendor.on("/incidents/v1/detections")]
        assert read[:2] == [_uuid(900), _uuid(901)]
        assert read[2:] == [_uuid(i) for i in range(_MAX_INCIDENT_LOOKUPS - 2)], "equally severe BCDs keep their order"

    @pytest.mark.asyncio
    async def test_a_credential_refused_part_way_through_stops_the_detection_reads(self) -> None:
        def detections(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"message": "Unauthorized.", "code": 401000})

        vendor = Vendor(_serving(_page([_incident(_uuid(i)) for i in range(5)])), detections=detections)
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(out) == 5
        # The cached token is exchanged once more, and its refusal ends the lookups.
        assert len(vendor.on("/incidents/v1/detections")) == 2
        assert len(vendor.on("/as/token.oauth2")) == 2
        assert any(entry["event"] == "withsecure_elements.detection_lookups_stopped" for entry in logs)

    @pytest.mark.asyncio
    async def test_a_token_exchange_refused_part_way_through_stops_the_lookups(self) -> None:
        exchanges = {"count": 0}

        def token(request: httpx.Request) -> httpx.Response:
            exchanges["count"] += 1
            if exchanges["count"] == 1:
                return httpx.Response(200, json={"access_token": "access-1", "expires_in": 1799})
            return httpx.Response(401, json={"error": "invalid_client"})

        def detections(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"message": "Unauthorized."})

        vendor = Vendor(_serving(_page([_incident(_uuid(i)) for i in range(5)])), detections=detections, token=token)
        out = await vendor.connector().fetch_alerts()
        assert len(out) == 5
        assert exchanges["count"] == 2, "a refused exchange was attempted again for every remaining BCD"
        assert vendor.on("/devices/v1/devices") == []

    @pytest.mark.asyncio
    async def test_a_bcd_id_that_is_not_a_uuid_is_never_put_into_a_request(self) -> None:
        vendor = Vendor(_serving(_page([_incident("../../devices/v1/devices"), _incident(_uuid(1))])), detections=_no_detections)
        out = await vendor.connector().fetch_alerts()
        assert len(out) == 2
        assert [r.url.params["incidentId"] for r in vendor.on("/incidents/v1/detections")] == [_uuid(1)]


class TestTheHostsBehindABCD:
    @pytest.mark.asyncio
    async def test_each_distinct_device_is_looked_up_once_per_poll(self) -> None:
        vendor = Vendor(_serving(_page([_incident(_uuid(1)), _incident(_uuid(2))])))
        await vendor.connector().fetch_alerts()
        # The host the BCDs are filed on first, then the other host they name.
        assert [r.url.params["deviceId"] for r in vendor.on("/devices/v1/devices")] == [_DEVICE_A, _DEVICE_B]

    @pytest.mark.asyncio
    async def test_a_device_id_that_is_not_a_uuid_is_never_put_into_a_request(self) -> None:
        def detections(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_page([{**_DETECTIONS[0], "deviceId": "x&deviceId=other"}, _DETECTIONS[1]]))

        vendor = Vendor(_serving(_page([_incident(_uuid(1))])), detections=detections)
        await vendor.connector().fetch_alerts()
        assert [r.url.params["deviceId"] for r in vendor.on("/devices/v1/devices")] == [_DEVICE_A]

    @pytest.mark.asyncio
    async def test_a_record_for_another_device_is_not_used(self) -> None:
        vendor = Vendor(
            _serving(_page([_incident(_uuid(1))])),
            devices=lambda request: httpx.Response(200, json={"items": [{**_DEVICES[_DEVICE_A], "id": _uuid(99)}]}),
        )
        (row,) = await vendor.connector().fetch_alerts()
        assert "hostname" not in row
        assert "devices" not in row["raw_event"]

    @pytest.mark.asyncio
    async def test_a_failed_device_lookup_costs_the_host_not_the_bcd(self) -> None:
        def devices(request: httpx.Request) -> httpx.Response:
            if request.url.params["deviceId"] == _DEVICE_B:
                return httpx.Response(500, json={"message": "no"})
            raise httpx.ConnectError("connection reset")

        vendor = Vendor(_serving(_page([_incident(_uuid(1))])), devices=devices)
        (row,) = await vendor.connector().fetch_alerts()
        assert row["external_id"] == _uuid(1)
        assert "hostname" not in row
        assert row["endpoint_id"] == _DEVICE_A
        assert row["actor"] == "CORP\\jdoe"

    @pytest.mark.asyncio
    async def test_a_429_on_devices_stops_the_device_lookups(self) -> None:
        vendor = Vendor(
            _serving(_page([_incident(_uuid(1))])),
            devices=lambda request: httpx.Response(429, json={"message": "Too many requests"}),
        )
        with structlog.testing.capture_logs() as logs:
            (row,) = await vendor.connector().fetch_alerts()
        assert len(vendor.on("/devices/v1/devices")) == 1
        assert row["mitre_techniques"]
        assert any(entry["event"] == "withsecure_elements.device_lookups_stopped" for entry in logs)

    @pytest.mark.asyncio
    async def test_a_credential_refused_part_way_through_stops_the_device_lookups(self) -> None:
        vendor = Vendor(
            _serving(_page([_incident(_uuid(1))])),
            devices=lambda request: httpx.Response(401, json={"message": "Unauthorized."}),
        )
        with structlog.testing.capture_logs() as logs:
            (row,) = await vendor.connector().fetch_alerts()
        assert len(vendor.on("/devices/v1/devices")) == 2, "one request, and one more after the token is exchanged again"
        assert row["endpoint_id"] == _DEVICE_A
        assert any(entry["event"] == "withsecure_elements.device_lookups_stopped" for entry in logs)

    @pytest.mark.asyncio
    async def test_the_device_lookups_are_bounded_per_poll(self) -> None:
        def detections(request: httpx.Request) -> httpx.Response:
            # Two hosts per BCD, so the device bound binds before the BCD bound.
            number = int(request.url.params["incidentId"][-12:])
            hosts = [_uuid(1000 + 2 * number), _uuid(1001 + 2 * number)]
            return httpx.Response(200, json=_page([{**_DETECTIONS[1], "deviceId": host} for host in hosts]))

        count = _MAX_DEVICE_LOOKUPS // 2 + 2
        assert count <= _MAX_INCIDENT_LOOKUPS
        vendor = Vendor(
            _serving(_page([_incident(_uuid(i)) for i in range(count)])),
            detections=detections,
            devices=lambda request: httpx.Response(200, json={"items": []}),
        )
        with structlog.testing.capture_logs() as logs:
            out = await vendor.connector().fetch_alerts()
        assert len(out) == count
        assert len(vendor.on("/devices/v1/devices")) == _MAX_DEVICE_LOOKUPS
        assert any(entry["event"] == "withsecure_elements.device_lookups_capped" for entry in logs)

    @pytest.mark.asyncio
    async def test_when_the_bound_binds_each_bcds_own_host_is_looked_up_first(self) -> None:
        def detections(request: httpx.Request) -> httpx.Response:
            # Newest first: a medium detection on a secondary host, then the
            # high one on the host the BCD is filed on.
            number = int(request.url.params["incidentId"][-12:])
            rows = [
                {**_DETECTIONS[0], "deviceId": _uuid(5000 + number)},
                {**_DETECTIONS[1], "deviceId": _uuid(1000 + number)},
            ]
            return httpx.Response(200, json=_page(rows))

        count = _MAX_DEVICE_LOOKUPS
        vendor = Vendor(
            _serving(_page([_incident(_uuid(i)) for i in range(count)])),
            detections=detections,
            devices=lambda request: httpx.Response(200, json={"items": []}),
        )
        await vendor.connector().fetch_alerts()
        looked_up = [r.url.params["deviceId"] for r in vendor.on("/devices/v1/devices")]
        assert looked_up == [_uuid(1000 + i) for i in range(count)]

    def test_a_whole_poll_stays_inside_the_edr_rate_limit(self) -> None:
        """300 requests a minute per address covers the BCD, detection and device reads alike."""
        worst = DEFAULT_MAX_PAGES + _MAX_INCIDENT_LOOKUPS * _DETECTION_PAGES + _MAX_DEVICE_LOOKUPS + 1
        assert worst < 300


class TestNormalize:
    def _row(self) -> dict[str, Any]:
        return WithSecureElementsConnector(client_id="c", client_secret="s").normalize(
            {**_INCIDENT, "detections": _DETECTIONS, "devices": [_DEVICES[_DEVICE_B], _DEVICES[_DEVICE_A]]}
        )

    def test_the_bcd_maps_to_the_canonical_envelope(self) -> None:
        row = self._row()
        assert row["source"] == "withsecure_elements"
        assert row["external_id"] == _INCIDENT["incidentId"]
        assert row["incident_public_id"] == "3599-4F9929A4"
        assert row["title"] == "Incident in DESKTOP-1"
        assert row["description"] == "Credential dumping followed by lateral movement"
        assert row["created_at"] == "2026-11-12T09:41:07.097Z"
        assert row["severity"] == "high"
        assert (row["status"], row["resolution"]) == ("new", "unconfirmed")
        assert row["risk_score"] == pytest.approx(74.86341234)
        assert row["categories"] == ["CREDENTIAL_THEFT", "LATERAL_MOVEMENT"]
        assert row["sources"] == ["endpoint"]

    def test_the_vendor_record_is_kept_under_raw_event(self) -> None:
        row = self._row()
        assert row["raw_event"]["incidentId"] == _INCIDENT["incidentId"]
        assert "raw" not in row

    def test_the_process_user_and_host_come_from_the_most_severe_detection(self) -> None:
        row = self._row()
        assert row["process_name"] == "procdump64.exe"
        assert row["process_path"] == "C:\\Users\\jdoe\\AppData\\Local\\Temp\\procdump64.exe"
        assert row["command_line"] == "procdump64.exe -ma lsass.exe out.dmp"
        assert row["sha256"] == "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        assert "sha1" not in row
        assert row["actor"] == "CORP\\jdoe"
        assert row["endpoint_id"] == _DEVICE_A
        assert row["hostname"] == "DESKTOP-1"
        assert row["src_ip"] == "192.0.2.42"
        assert row["external_ip"] == "203.0.113.9"
        assert row["os"] == "Windows 11 Pro 10.0.22631"

    def test_the_host_is_never_taken_from_a_device_other_than_the_endpoint(self) -> None:
        """The primary detection's device was not resolved; another one was."""
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize(
            {**_INCIDENT, "detections": _DETECTIONS, "devices": [_DEVICES[_DEVICE_B]]}
        )
        assert row["endpoint_id"] == _DEVICE_A
        assert "hostname" not in row and "src_ip" not in row and "os" not in row
        assert row["hostnames"] == ["FS-02"]

    def test_the_host_follows_the_detection_that_names_one(self) -> None:
        primary = {k: v for k, v in _DETECTIONS[1].items() if k != "deviceId"}
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize(
            {**_INCIDENT, "detections": [_DETECTIONS[0], primary], "devices": [_DEVICES[_DEVICE_B]]}
        )
        assert row["process_name"] == "procdump64.exe"
        assert row["endpoint_id"] == _DEVICE_B
        assert row["hostname"] == "FS-02"

    def test_among_equally_severe_detections_the_newest_wins(self) -> None:
        older = {**_DETECTIONS[1], "severity": "medium", "createdTimestamp": "2026-11-12T09:40:00.000Z"}
        newer = {**_DETECTIONS[0], "severity": "medium", "createdTimestamp": "2026-11-12T09:42:00.000Z"}
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize({**_INCIDENT, "detections": [older, newer]})
        assert row["process_name"] == "sc.exe"
        assert row["sha1"] == "c8f21ef51fa2f2033a9ca7c0cc0412c25065e2ba"

    def test_every_host_and_attack_id_across_the_detections_is_kept(self) -> None:
        row = self._row()
        assert row["hostnames"] == ["FS-02", "DESKTOP-1"]
        assert row["mitre_techniques"] == ["T1021.002", "T1003", "T1003.001"]
        assert row["mitre_tactics"] == ["TA0008", "TA0006"]
        assert row["detection_names"] == ["remoteServiceCreation", "credentialDumping"]
        assert row["detection_count"] == 2

    def test_a_hash_that_is_neither_sha1_nor_sha256_is_not_labelled_as_one(self) -> None:
        detection = {**_DETECTIONS[1], "exeHash": "d41d8cd98f00b204e9800998ecf8427e"}
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize({**_INCIDENT, "detections": [detection]})
        assert "sha1" not in row and "sha256" not in row

    def test_the_user_falls_back_to_another_detection_when_the_primary_has_none(self) -> None:
        primary = {k: v for k, v in _DETECTIONS[1].items() if k != "username"}
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize(
            {**_INCIDENT, "detections": [_DETECTIONS[0], primary]}
        )
        assert row["actor"] == "CORP\\svc-backup"

    @pytest.mark.parametrize(
        ("addresses", "first"),
        [
            ("192.0.2.42", "192.0.2.42"),
            ("192.0.2.42/24, 198.51.100.4/24", "192.0.2.42"),
            (" , not-an-address, 2001:db8::1/64", "2001:db8::1"),
            ("", None),
        ],
    )
    def test_the_hosts_first_well_formed_address_is_its_source(self, addresses: str, first: str | None) -> None:
        device = {**_DEVICES[_DEVICE_A], "ipAddresses": addresses, "publicIpAddress": "unknown"}
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize(
            {**_INCIDENT, "detections": [_DETECTIONS[1]], "devices": [device]}
        )
        assert row.get("src_ip") == first
        assert "external_ip" not in row

    def test_a_bcd_without_detections_still_normalizes(self) -> None:
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize(dict(_INCIDENT))
        assert row["external_id"] == _INCIDENT["incidentId"]
        for key in ("hostname", "actor", "process_path", "mitre_techniques", "detection_count", "hostnames"):
            assert key not in row

    def test_a_bcd_without_a_name_gets_a_generic_title(self) -> None:
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize({**_INCIDENT, "name": ""})
        assert row["title"] == "WithSecure Elements Broad Context Detection"

    def test_malformed_vendor_values_are_dropped_not_raised(self) -> None:
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize(
            {**_INCIDENT, "riskScore": True, "categories": "MALWARE", "detections": ["x", None], "devices": "nope"}
        )
        assert "risk_score" not in row and "categories" not in row and "detection_count" not in row


class TestTheSeverityLadder:
    @pytest.mark.parametrize(
        ("severity", "tier"),
        [("info", "info"), ("low", "low"), ("medium", "medium"), ("high", "high"), ("critical", "critical"), ("CRITICAL", "critical")],
    )
    def test_each_published_severity_keeps_its_own_tier(self, severity: str, tier: str) -> None:
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize(
            {**_INCIDENT, "severity": severity, "riskLevel": "info"}
        )
        assert row["severity"] == tier

    @pytest.mark.parametrize(
        ("risk_level", "tier"),
        [("info", "info"), ("low", "low"), ("medium", "medium"), ("high", "high"), ("severe", "critical")],
    )
    def test_without_a_severity_the_risk_level_is_used(self, risk_level: str, tier: str) -> None:
        raw = {k: v for k, v in _INCIDENT.items() if k != "severity"}
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize({**raw, "riskLevel": risk_level})
        assert row["severity"] == tier

    @pytest.mark.parametrize("value", ["warning", "", "SEVERITY_UNSPECIFIED", None, 3])
    def test_an_undocumented_level_carries_no_severity(self, value: Any) -> None:
        row = WithSecureElementsConnector(client_id="c", client_secret="s").normalize({**_INCIDENT, "severity": value, "riskLevel": value})
        assert "severity" not in row


class TestTestConnection:
    @pytest.mark.asyncio
    async def test_a_readable_bcd_list_is_a_success(self) -> None:
        vendor = Vendor()
        result = await vendor.connector(organization_id=_ORGANIZATION).test_connection()
        assert result == {"success": True, "connector": "withsecure_elements", "organization_id": _ORGANIZATION}
        (read,) = vendor.on("/incidents/v1/incidents")
        assert dict(read.url.params) == {"organizationId": _ORGANIZATION, "limit": "1"}

    @pytest.mark.asyncio
    async def test_a_refused_credential_is_reported_not_raised(self) -> None:
        vendor = Vendor(token=lambda request: httpx.Response(401, json={"error": "invalid_client"}))
        result = await vendor.connector().test_connection()
        assert result["success"] is False
        assert "client ID and secret" in result["error"]

    @pytest.mark.asyncio
    async def test_a_refused_read_is_reported_not_raised(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(403, json={"message": "Forbidden", "code": 403000}))
        result = await vendor.connector().test_connection()
        assert result["success"] is False
        assert "HTTP 403 to GET /incidents/v1/incidents" in result["error"]

    @pytest.mark.asyncio
    async def test_an_unreachable_api_is_reported_not_raised(self) -> None:
        def incidents(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("name resolution failed")

        vendor = Vendor(incidents)
        result = await vendor.connector().test_connection()
        assert result["success"] is False
        assert "name resolution failed" in result["error"]
