"""Vectra AI Platform detections through the v3.4 detection events API.

Every path, parameter and field name below is the one the Vectra AI Platform
API guide documents and the connector module cites. The payloads are
synthetic: they carry the documented field names, and the portal host is a
placeholder.

The properties pinned here, each a way this could be wired wrong:

1. **The credential only goes to the configured portal, over HTTPS.** The
   token is exchanged with HTTP Basic client credentials, cached, and fetched
   again once if a cached token is refused; every following page is built
   here from `next_checkpoint`.
2. **The window is read to the end.** The read opens at the window's start
   through `event_timestamp_gte` and follows `next_checkpoint` while
   `remaining_count` says there is more. A failed later page keeps what was
   read, and the bound is announced when it binds.
3. **One alert per detection.** The stream emits a detection again on every
   update, so a poll returns the newest event of each, keyed by
   `detection_id`; an event stamped after the read began is left for the
   next window, and a triaged detection is not raised.
4. **No invented severity.** Vectra does not score individual detections,
   so no `severity` key is emitted whatever `threat`, `certainty` or
   `severity` say.
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
from app.connectors.vectra_ai import VectraAIConnector, VectraAIError

_PORTAL = "https://000000000000.uw2.portal.vectra.ai"


def _ago(seconds: float) -> str:
    """An ISO 8601 timestamp ``seconds`` before now, in the `Z` form Vectra sends."""
    return (datetime.now(UTC) - timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


#: One detection event in the shape `GET /api/v3.4/events/detections` returns. Synthetic.
_EVENT: dict[str, Any] = {
    "id": 28538,
    "category": "command_and_control",
    "threat": 50,
    "certainty": 50,
    "triaged": False,
    "detection_type": "Hidden HTTPS Tunnel",
    "d_type_vname": "Hidden HTTPS Tunnel",
    "detection_id": 959,
    "detection_href": f"{_PORTAL}/detections/959?detail_id=94341",
    "url": f"{_PORTAL}/detections/959",
    "entity_id": 976,
    "entity_uid": "ws-0142",
    "src_entity": "ws-0142",
    "entity_href": f"{_PORTAL}/hosts/976",
    "type": "host",
    "event_timestamp": "2026-11-12T16:31:35Z",
    "mitre": ["T1071", "T1001"],
    "detail": {},
    "severity": 5,
}


def _event(event_id: int, *, detection_id: int | None = None, stamped: float = 60, **overrides: Any) -> dict[str, Any]:
    """An event ``stamped`` seconds ago, on its own detection unless ``detection_id`` says otherwise."""
    return {
        **_EVENT,
        "id": event_id,
        "detection_id": event_id if detection_id is None else detection_id,
        "event_timestamp": _ago(stamped),
        **overrides,
    }


def _page(events: list[dict[str, Any]], *, checkpoint: int | None = None, remaining: int = 0) -> dict[str, Any]:
    return {"events": events, "next_checkpoint": checkpoint, "remaining_count": remaining}


class Vendor:
    """The Vectra API behind one transport."""

    def __init__(
        self,
        events: Callable[[httpx.Request], httpx.Response] | None = None,
        token: Callable[[httpx.Request], httpx.Response] | None = None,
    ) -> None:
        self.requests: list[httpx.Request] = []
        self.tokens_issued = 0
        self._events = events or (lambda request: httpx.Response(200, json=_page([])))
        self._token = token or self._issue

    def _issue(self, request: httpx.Request) -> httpx.Response:
        self.tokens_issued += 1
        return httpx.Response(200, json={"access_token": f"token-{self.tokens_issued}", "expires_in": 21600, "token_type": "Bearer"})

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.method == "POST" and request.url.path == "/oauth2/token":
            return self._token(request)
        if request.method == "GET" and request.url.path == "/api/v3.4/events/detections":
            return self._events(request)
        return httpx.Response(404, json={"detail": "no route"})

    def connector(self, base_url: str = _PORTAL) -> VectraAIConnector:
        return VectraAIConnector(
            base_url=base_url, client_id="client-id", client_secret="client-secret", transport=httpx.MockTransport(self.handle)
        )

    def token_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == "/oauth2/token"]

    def event_requests(self) -> list[httpx.Request]:
        return [r for r in self.requests if r.url.path == "/api/v3.4/events/detections"]


def _serving(*pages: dict[str, Any]) -> Callable[[httpx.Request], httpx.Response]:
    """Serve ``pages`` in order, keyed by the `from` checkpoint each request carries."""
    by_checkpoint: dict[str | None, dict[str, Any]] = {}
    checkpoint: str | None = None
    for page in pages:
        by_checkpoint[checkpoint] = page
        checkpoint = str(page["next_checkpoint"])
    return lambda request: httpx.Response(200, json=by_checkpoint[request.url.params.get("from")])


class TestRegistration:
    def test_the_connector_is_in_the_registry(self) -> None:
        assert "vectra_ai" in {cls.connector_id for cls in _CONNECTOR_CLASSES}

    def test_the_secret_key_is_vaulted_and_every_field_required(self) -> None:
        fields = {f.name: (f.type, f.required) for f in VectraAIConnector.schema().fields}
        assert fields == {"base_url": ("string", True), "client_id": ("string", True), "client_secret": ("secret", True)}

    def test_it_is_a_read_only_ndr_source(self) -> None:
        assert VectraAIConnector.schema().category == "ndr"
        assert VectraAIConnector.capabilities() == (Capability.PULL_ALERTS,)

    def test_the_docs_url_matches_the_generated_slug(self) -> None:
        assert VectraAIConnector.schema().docs_url == "/docs/connectors/vectra-ai"


class TestWhereTheCredentialGoes:
    @pytest.mark.asyncio
    async def test_the_token_is_exchanged_with_basic_client_credentials(self) -> None:
        vendor = Vendor()
        await vendor.connector().fetch_alerts()
        (exchange,) = vendor.token_requests()
        assert (exchange.url.scheme, exchange.url.host) == ("https", "000000000000.uw2.portal.vectra.ai")
        assert exchange.headers["Authorization"] == "Basic " + base64.b64encode(b"client-id:client-secret").decode()
        assert exchange.headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert exchange.content == b"grant_type=client_credentials"

    @pytest.mark.asyncio
    async def test_the_events_are_read_with_the_bearer_token(self) -> None:
        vendor = Vendor()
        await vendor.connector().fetch_alerts()
        (read,) = vendor.event_requests()
        assert read.url.host == "000000000000.uw2.portal.vectra.ai"
        assert read.headers["Authorization"] == "Bearer token-1"

    @pytest.mark.asyncio
    async def test_a_bare_host_is_read_over_https_and_a_trailing_slash_dropped(self) -> None:
        vendor = Vendor()
        await vendor.connector(base_url=" 000000000000.uw2.portal.vectra.ai/ ").fetch_alerts()
        assert {str(r.url).split("?")[0] for r in vendor.requests} == {
            f"{_PORTAL}/oauth2/token",
            f"{_PORTAL}/api/v3.4/events/detections",
        }

    @pytest.mark.asyncio
    async def test_a_plain_http_portal_is_refused_before_anything_is_sent(self) -> None:
        vendor = Vendor()
        with pytest.raises(VectraAIError, match="HTTPS"):
            await vendor.connector(base_url="http://000000000000.uw2.portal.vectra.ai").fetch_alerts()
        assert vendor.requests == []

    @pytest.mark.asyncio
    async def test_the_token_is_reused_across_polls(self) -> None:
        vendor = Vendor()
        connector = vendor.connector()
        await connector.fetch_alerts()
        await connector.fetch_alerts()
        assert len(vendor.token_requests()) == 1
        assert [r.headers["Authorization"] for r in vendor.event_requests()] == ["Bearer token-1", "Bearer token-1"]

    @pytest.mark.asyncio
    async def test_a_token_near_its_expiry_is_exchanged_again(self) -> None:
        vendor = Vendor(token=lambda request: httpx.Response(200, json={"access_token": "short", "expires_in": 30}))
        connector = vendor.connector()
        await connector.fetch_alerts()
        await connector.fetch_alerts()
        assert len(vendor.token_requests()) == 2

    @pytest.mark.asyncio
    async def test_a_refused_cached_token_is_exchanged_again_once(self) -> None:
        """A token revoked before its expiry answers 401; one fresh exchange recovers the poll."""

        def events(request: httpx.Request) -> httpx.Response:
            if request.headers["Authorization"] == "Bearer token-1" and len(vendor.event_requests()) > 1:
                return httpx.Response(401, json={"detail": "Invalid token"})
            return httpx.Response(200, json=_page([_event(1)]))

        vendor = Vendor(events)
        connector = vendor.connector()
        await connector.fetch_alerts()
        out = await connector.fetch_alerts()
        assert [row["external_id"] for row in out] == ["1"]
        assert len(vendor.token_requests()) == 2
        assert vendor.event_requests()[-1].headers["Authorization"] == "Bearer token-2"

    @pytest.mark.asyncio
    async def test_a_fresh_token_that_is_refused_is_not_exchanged_again(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(401, json={"detail": "Invalid token"}))
        with pytest.raises(VectraAIError, match="HTTP 401 to GET /api/v3.4/events/detections"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.token_requests()) == 1
        assert len(vendor.event_requests()) == 1


class TestReadingTheWindow:
    @pytest.mark.asyncio
    async def test_the_read_opens_at_the_start_of_the_window(self) -> None:
        vendor = Vendor()
        before = datetime.now(UTC)
        await vendor.connector().fetch_alerts(since_seconds=600)
        (read,) = vendor.event_requests()
        assert set(read.url.params) == {"event_timestamp_gte", "limit"}
        assert read.url.params["limit"] == "500"
        opens = datetime.fromisoformat(read.url.params["event_timestamp_gte"].replace("Z", "+00:00"))
        assert timedelta(seconds=599) <= before - opens <= timedelta(seconds=602)

    @pytest.mark.asyncio
    async def test_every_page_is_followed_until_nothing_remains(self) -> None:
        vendor = Vendor(
            _serving(
                _page([_event(i) for i in range(500)], checkpoint=500, remaining=507),
                _page([_event(i) for i in range(500, 1000)], checkpoint=1000, remaining=7),
                _page([_event(i) for i in range(1000, 1007)], checkpoint=1007, remaining=0),
            )
        )
        out = await vendor.connector().fetch_alerts()
        assert len(out) == 1007
        assert [r.url.params.get("from") for r in vendor.event_requests()] == [None, "500", "1000"]
        # The window stays on every page; only the checkpoint moves.
        assert len({r.url.params["event_timestamp_gte"] for r in vendor.event_requests()}) == 1

    @pytest.mark.asyncio
    @pytest.mark.parametrize(("checkpoint", "remaining"), [(None, 3), ("12", 3), (True, 3), (12, None), (12, "3"), (12, True)])
    async def test_a_malformed_continuation_ends_the_read(self, checkpoint: Any, remaining: Any) -> None:
        vendor = Vendor(
            lambda request: httpx.Response(200, json={"events": [_event(1)], "next_checkpoint": checkpoint, "remaining_count": remaining})
        )
        out = await vendor.connector().fetch_alerts()
        assert len(vendor.event_requests()) == 1
        assert [row["external_id"] for row in out] == ["1"]

    @pytest.mark.asyncio
    async def test_a_failure_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def events(request: httpx.Request) -> httpx.Response:
            if "from" not in request.url.params:
                return httpx.Response(200, json=_page([_event(1), _event(2)], checkpoint=3, remaining=5))
            return httpx.Response(503, text="unavailable")

        out = await Vendor(events).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["1", "2"]

    @pytest.mark.asyncio
    async def test_a_transport_error_on_a_later_page_keeps_the_pages_already_read(self) -> None:
        def events(request: httpx.Request) -> httpx.Response:
            if "from" not in request.url.params:
                return httpx.Response(200, json=_page([_event(1)], checkpoint=2, remaining=5))
            raise httpx.ReadTimeout("timed out", request=request)

        out = await Vendor(events).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["1"]

    @pytest.mark.asyncio
    async def test_a_stream_that_never_ends_is_bounded_and_announced(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(200, json=_page([_event(1)], checkpoint=2, remaining=1)))
        with structlog.testing.capture_logs() as logs:
            await vendor.connector().fetch_alerts()
        assert len(vendor.event_requests()) == DEFAULT_MAX_PAGES
        assert any(entry["event"] == "connector.paging.page_cap_reached" for entry in logs)


class TestWhatIsReturned:
    @pytest.mark.asyncio
    async def test_several_events_for_one_detection_are_raised_once_as_the_newest(self) -> None:
        events = [
            _event(1, detection_id=959, stamped=240, threat=20),
            _event(2, detection_id=960, stamped=200),
            _event(3, detection_id=959, stamped=60, threat=80),
        ]
        out = await Vendor(_serving(_page(events))).connector().fetch_alerts(since_seconds=300)
        assert sorted(row["external_id"] for row in out) == ["959", "960"]
        (newest,) = [row for row in out if row["external_id"] == "959"]
        assert (newest["event_id"], newest["raw_event"]["threat"]) == ("3", 80)

    @pytest.mark.asyncio
    async def test_the_newest_event_wins_however_the_page_is_ordered(self) -> None:
        events = [_event(7, detection_id=959, stamped=60, threat=80), _event(4, detection_id=959, stamped=120, threat=20)]
        (event,) = await Vendor(_serving(_page(events))).connector().fetch_alerts()
        assert (event["event_id"], event["raw_event"]["threat"]) == ("7", 80)

    @pytest.mark.asyncio
    async def test_an_event_stamped_after_the_read_began_is_left_for_the_next_window(self) -> None:
        """The next poll's window opens where this one closed, so raising it here would raise it twice."""
        out = await Vendor(_serving(_page([_event(1, stamped=-30), _event(2, stamped=60)]))).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["2"]

    @pytest.mark.asyncio
    async def test_an_event_from_before_the_window_is_not_raised(self) -> None:
        """The request opens at the window's whole second, so an event in that second's leading edge can come back."""
        out = await Vendor(_serving(_page([_event(1, stamped=900), _event(2, stamped=60)]))).connector().fetch_alerts(since_seconds=300)
        assert [row["external_id"] for row in out] == ["2"]

    @pytest.mark.asyncio
    async def test_a_triaged_detection_is_not_raised(self) -> None:
        out = await Vendor(_serving(_page([_event(1, triaged=True), _event(2)]))).connector().fetch_alerts()
        assert [row["external_id"] for row in out] == ["2"]

    @pytest.mark.asyncio
    async def test_an_event_without_a_detection_id_is_still_raised(self) -> None:
        out = await Vendor(_serving(_page([{**_event(1), "detection_id": None}]))).connector().fetch_alerts()
        (event,) = out
        assert "external_id" not in event
        assert event["event_id"] == "1"


class TestFailures:
    @pytest.mark.asyncio
    async def test_a_refused_opening_request_raises_rather_than_reading_as_quiet(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(403, json={"detail": "Forbidden"}))
        with pytest.raises(VectraAIError, match="HTTP 403 to GET /api/v3.4/events/detections.*role"):
            await vendor.connector().fetch_alerts()
        assert len(vendor.event_requests()) == 1

    @pytest.mark.asyncio
    async def test_a_refused_token_exchange_names_the_credential(self) -> None:
        vendor = Vendor(token=lambda request: httpx.Response(401, json={"error": "invalid_client"}))
        with pytest.raises(VectraAIError, match="HTTP 401 to POST /oauth2/token.*client ID and secret key"):
            await vendor.connector().fetch_alerts()
        assert vendor.event_requests() == []

    @pytest.mark.asyncio
    async def test_a_token_response_without_a_token_raises(self) -> None:
        vendor = Vendor(token=lambda request: httpx.Response(200, json={"token_type": "Bearer"}))
        with pytest.raises(VectraAIError, match="without an access_token"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_unreachable_portal_raises_rather_than_reading_as_quiet(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        with pytest.raises(VectraAIError, match="could not be reached.*connection refused"):
            await Vendor(token=unreachable).connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_unreachable_events_endpoint_raises_rather_than_reading_as_quiet(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection reset", request=request)

        with pytest.raises(VectraAIError, match="could not be reached.*connection reset"):
            await Vendor(unreachable).connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_an_exhausted_rate_limit_says_so(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(429, text="Too Many Requests"))
        with pytest.raises(VectraAIError, match="HTTP 429.*rate limit"):
            await vendor.connector().fetch_alerts()

    @pytest.mark.asyncio
    async def test_a_working_connection_reads_one_event(self) -> None:
        vendor = Vendor()
        result = await vendor.connector().test_connection()
        assert result == {"success": True, "connector": "vectra_ai"}
        (read,) = vendor.event_requests()
        assert read.url.params["limit"] == "1"

    @pytest.mark.asyncio
    async def test_bad_credentials_are_reported_by_test_connection(self) -> None:
        vendor = Vendor(token=lambda request: httpx.Response(401, json={"error": "invalid_client"}))
        result = await vendor.connector().test_connection()
        assert (result["success"], result["connector"]) == (False, "vectra_ai")
        assert result["error"].startswith("Vectra answered HTTP 401 to POST /oauth2/token")

    @pytest.mark.asyncio
    async def test_a_forbidden_read_is_reported_by_test_connection(self) -> None:
        vendor = Vendor(lambda request: httpx.Response(403, json={"detail": "Forbidden"}))
        result = await vendor.connector().test_connection()
        assert result["success"] is False
        assert result["error"].startswith("Vectra answered HTTP 403 to GET /api/v3.4/events/detections")

    @pytest.mark.asyncio
    async def test_a_plain_http_portal_is_reported_by_test_connection(self) -> None:
        result = await Vendor().connector(base_url="http://portal.example").test_connection()
        assert result["success"] is False
        assert "HTTPS" in result["error"]

    @pytest.mark.asyncio
    async def test_a_network_failure_is_reported_by_test_connection(self) -> None:
        def unreachable(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        result = await Vendor(token=unreachable).connector().test_connection()
        assert result["success"] is False
        assert "connection refused" in result["error"]


class TestNormalize:
    def _normalize(self, **overrides: Any) -> dict[str, Any]:
        return VectraAIConnector(base_url=_PORTAL, client_id="i", client_secret="s").normalize({**_EVENT, **overrides})

    def test_the_envelope_is_canonical(self) -> None:
        event = self._normalize()
        assert event["source"] == "vectra_ai"
        assert event["raw_event"] == _EVENT
        assert "raw" not in event
        assert event["external_id"] == "959"
        assert event["event_id"] == "28538"
        assert event["title"] == "Hidden HTTPS Tunnel"
        assert event["description"] == "Vectra AI detected Hidden HTTPS Tunnel (command and control) on host ws-0142."
        assert event["created_at"] == "2026-11-12T16:31:35Z"

    def test_the_detection_context_is_kept(self) -> None:
        event = self._normalize()
        assert event["category"] == "command_and_control"
        assert event["event_type"] == "Hidden HTTPS Tunnel"
        assert event["url"] == f"{_PORTAL}/detections/959?detail_id=94341"
        assert event["entity_type"] == "host"
        assert event["entity_id"] == "976"
        assert event["mitre_techniques"] == ["T1071", "T1001"]

    def test_a_host_detection_names_the_host_and_no_actor(self) -> None:
        event = self._normalize()
        assert event["hostname"] == "ws-0142"
        assert "actor" not in event

    def test_an_account_detection_names_the_actor_and_no_host(self) -> None:
        event = self._normalize(type="account", src_entity="O365:jdoe@example.com", entity_uid="O365:jdoe@example.com")
        assert event["actor"] == "O365:jdoe@example.com"
        assert "hostname" not in event
        assert event["description"].endswith("on account O365:jdoe@example.com.")

    def test_the_entity_name_wins_over_its_uid(self) -> None:
        assert self._normalize(entity_name="WS-0142.corp.example", src_entity=None)["hostname"] == "WS-0142.corp.example"
        assert self._normalize(src_entity=None)["hostname"] == "ws-0142"

    def test_an_entity_of_another_type_fills_neither_column(self) -> None:
        event = self._normalize(type="network")
        assert "hostname" not in event
        assert "actor" not in event

    def test_only_well_formed_technique_ids_are_kept_once(self) -> None:
        event = self._normalize(mitre=["T1071", "t1001.001", "TA0011", "T1071", 7, "", None])
        assert event["mitre_techniques"] == ["T1071", "T1001.001"]

    def test_the_portal_link_falls_back_to_url(self) -> None:
        assert self._normalize(detection_href=None)["url"] == f"{_PORTAL}/detections/959"

    def test_malformed_fields_are_tolerated(self) -> None:
        event = self._normalize(d_type_vname=None, detection_type=7, detection_id=True, mitre="T1071", type=None, category=None)
        assert event["title"] == "Vectra AI detection"
        for key in ("description", "external_id", "mitre_techniques", "hostname", "event_type", "category"):
            assert key not in event

    @pytest.mark.parametrize(
        ("threat", "certainty", "severity"),
        [(0, 0, 0), (50, 50, 5), (99, 99, 10), (99, 99, "critical"), (None, None, None)],
    )
    def test_no_severity_is_invented(self, threat: Any, certainty: Any, severity: Any) -> None:
        """Vectra does not score individual detections; every number stays in raw_event, none becomes a tier."""
        event = self._normalize(threat=threat, certainty=certainty, severity=severity)
        assert "severity" not in event
        assert (event["raw_event"]["threat"], event["raw_event"]["certainty"]) == (threat, certainty)
