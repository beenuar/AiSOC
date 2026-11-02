"""ExtraHop RevealX 360 detections, and the three ways this could be wired wrong.

Depth plan wave 2, item 8.2.

Every endpoint, field name and auth shape below is read from ExtraHop's
current public reference, verified on 2026-11-01 and cited in the connector
module. The payloads are synthetic and carry the documented field names and
nothing else.

Three properties, each with a recorded way of failing in this repository:

1. **The severity ladder is the vendor's, not ours.** ExtraHop publishes
   three risk bands and no fourth, so this connector never emits `critical`.
   Inventing one would be the mirror of collapsing a real `critical` into
   `high`: both put a tier on an alert that the vendor did not assert.
2. **The connector needs an ingest profile.** Without one it hits the
   lenient fallback at `class_uid: 4001` with an empty severity map, and
   `should_promote()` requires OCSF category 2 or `severity_id >= 4`, so
   every detection would be archived to the lake and silently never
   promoted to an alert.
3. **The envelope key is `raw_event`, never `raw`.** Twenty-six connectors
   once used `raw`, missed the canonical-envelope check and were
   misattributed to a borrowed vendor profile.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from app.connectors import _CONNECTOR_CLASSES  # noqa: E402
from app.connectors.extrahop import ExtraHopConnector  # noqa: E402

#: One detection in the shape `POST /api/v1/detections/search` returns, with
#: the field names from the vendor's REST API guide. Synthetic.
_DETECTION = {
    "id": 4211,
    "title": "Suspicious SMB Session Activity",
    "description": "A device exhibited SMB session behaviour consistent with lateral movement.",
    "risk_score": 88,
    "categories": ["sec.lateral"],
    "type": "smb_lateral_movement",
    "status": "new",
    "start_time": 1793404800000,
    "end_time": 1793405400000,
    "update_time": 1793405400000,
    "mod_time": 1793405401000,
    "url": "https://example.api.cloud.extrahop.com/extrahop/#/detections/detail/4211",
    "mitre_techniques": [{"id": "T1021.002", "name": "SMB/Windows Admin Shares", "url": "https://attack.mitre.org/"}],
    "mitre_tactics": [{"id": "TA0008", "name": "Lateral Movement", "url": "https://attack.mitre.org/"}],
    "participants": [
        {"role": "offender", "object_type": "device", "object_value": "10.4.1.9", "hostname": "WKS-4219"},
        {"role": "victim", "object_type": "device", "object_value": "10.4.2.7", "hostname": "FILE-01"},
    ],
    "assignee": None,
    "resolution": None,
    "ticket_id": None,
    "is_user_created": False,
}


def _handler(detections: list[dict], *, capture: dict | None = None):  # noqa: ANN202
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/oauth2/token"):
            if capture is not None:
                capture["token_request"] = request
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600, "token_type": "Bearer"})
        if capture is not None:
            capture.setdefault("api_requests", []).append(request)
        return httpx.Response(200, json=detections)

    return httpx.MockTransport(handle)


class TestRegistration:
    def test_the_connector_is_in_the_registry(self) -> None:
        assert "extrahop" in {cls.connector_id for cls in _CONNECTOR_CLASSES}

    def test_the_credential_fields_are_declared_secret(self) -> None:
        secret = {f.name for f in ExtraHopConnector.schema().fields if f.type == "secret"}
        assert secret == {"client_secret"}

    def test_it_declares_the_ndr_category_and_a_pull_capability(self) -> None:
        from app.connectors.base import Capability

        schema = ExtraHopConnector.schema()
        assert schema.category == "ndr"
        assert Capability.PULL_ALERTS in ExtraHopConnector.capabilities()

    def test_the_docs_url_matches_the_generated_slug(self) -> None:
        """`generate_connector_docs._slug` hyphenates a connector with no
        existing page, so a `docs_url` written with the connector id would
        404 for any underscore-named connector. `extrahop` has none, which
        is exactly why this is pinned rather than assumed."""
        assert ExtraHopConnector.schema().docs_url == "/docs/connectors/extrahop"


class TestAuthShape:
    @pytest.mark.asyncio
    async def test_it_authenticates_the_way_revealx_360_documents(self) -> None:
        """Basic base64(id:secret) against /oauth2/token with
        grant_type=client_credentials. An API key, which works against a
        sensor or console, is explicitly not compatible with RevealX 360."""
        capture: dict = {}
        connector = ExtraHopConnector(
            api_host="https://example.api.cloud.extrahop.com",
            client_id="abc",
            client_secret="shh",
            transport=_handler([], capture=capture),
        )
        await connector.fetch_alerts()

        token_request = capture["token_request"]
        assert token_request.method == "POST"
        assert token_request.url.path == "/oauth2/token"
        assert token_request.headers["Authorization"].startswith("Basic ")
        assert b"grant_type=client_credentials" in token_request.content

        api_request = capture["api_requests"][0]
        assert api_request.url.path == "/api/v1/detections/search"
        assert api_request.headers["Authorization"] == "Bearer tok"


class TestSeverityLadder:
    """The vendor publishes red 80-99, orange 31-79, yellow 1-30, and no
    fourth band. The mapping follows that and stops there."""

    @pytest.mark.parametrize(
        ("risk_score", "expected"),
        [(99, "high"), (80, "high"), (79, "medium"), (31, "medium"), (30, "low"), (1, "low")],
    )
    @pytest.mark.asyncio
    async def test_each_published_band_maps_to_its_tier(self, risk_score: int, expected: str) -> None:
        detection = {**_DETECTION, "risk_score": risk_score}
        connector = ExtraHopConnector(api_host="https://h", client_id="a", client_secret="b", transport=_handler([detection]))
        assert (await connector.fetch_alerts())[0]["severity"] == expected

    @pytest.mark.asyncio
    async def test_it_never_invents_a_critical_tier(self) -> None:
        """The top band is `high`. Promoting 80-99 to `critical` would assert
        a severity ExtraHop does not publish, which is the same defect as
        collapsing a vendor's real `critical` into `high`, in the other
        direction. Promotion does not depend on it: the ingest profile files
        these at class 2001, category 2, which promotes unconditionally."""
        detection = {**_DETECTION, "risk_score": 99}
        connector = ExtraHopConnector(api_host="https://h", client_id="a", client_secret="b", transport=_handler([detection]))
        assert (await connector.fetch_alerts())[0]["severity"] != "critical"

    @pytest.mark.asyncio
    async def test_a_detection_with_no_risk_score_carries_no_severity(self) -> None:
        """A performance detection has no risk score. Emitting `info` would
        be our judgement rather than the vendor's; emitting nothing leaves
        severity_id 0 and the category-2 profile still promotes it."""
        detection = {k: v for k, v in _DETECTION.items() if k != "risk_score"}
        connector = ExtraHopConnector(api_host="https://h", client_id="a", client_secret="b", transport=_handler([detection]))
        assert "severity" not in (await connector.fetch_alerts())[0]


class TestNormalizedEnvelope:
    @pytest.mark.asyncio
    async def test_the_vendor_record_is_under_raw_event(self) -> None:
        connector = ExtraHopConnector(api_host="https://h", client_id="a", client_secret="b", transport=_handler([_DETECTION]))
        event = (await connector.fetch_alerts())[0]
        assert "raw" not in event, "the canonical envelope key is raw_event; `raw` misses the canonical check"
        assert event["raw_event"]["id"] == 4211

    @pytest.mark.asyncio
    async def test_the_canonical_keys_the_ingest_profile_reads_are_present(self) -> None:
        """The profile's field map reads these lowercase canonical keys, not
        raw vendor field names. A key the connector does not emit is a column
        the profile cannot map, and nothing fails loudly when it is absent."""
        connector = ExtraHopConnector(api_host="https://h", client_id="a", client_secret="b", transport=_handler([_DETECTION]))
        event = (await connector.fetch_alerts())[0]
        assert event["external_id"] == "4211"
        assert event["title"] == "Suspicious SMB Session Activity"
        assert event["src_ip"] == "10.4.1.9"
        assert event["hostname"] == "FILE-01"
        assert event["event_type"] == "smb_lateral_movement"
        assert event["mitre_techniques"] == ["T1021.002"]

    @pytest.mark.asyncio
    async def test_the_offender_is_the_source_and_the_victim_the_host(self) -> None:
        """Getting this backwards puts the attacker's address in the column
        an analyst reads as the asset under attack, and containment would
        then name the wrong machine."""
        connector = ExtraHopConnector(api_host="https://h", client_id="a", client_secret="b", transport=_handler([_DETECTION]))
        event = (await connector.fetch_alerts())[0]
        assert event["src_ip"] == "10.4.1.9"
        assert event["dst_ip"] == "10.4.2.7"


class TestWindowAndPaging:
    @pytest.mark.asyncio
    async def test_the_window_is_sent_as_the_documented_millisecond_epoch(self) -> None:
        capture: dict = {}
        connector = ExtraHopConnector(api_host="https://h", client_id="a", client_secret="b", transport=_handler([], capture=capture))
        await connector.fetch_alerts(since_seconds=600)
        import json

        body = json.loads(capture["api_requests"][0].content)
        assert body["until"] == 0
        # Negative milliseconds relative to now, which is the shape the
        # vendor documents for a relative window. A positive absolute epoch
        # computed here would drift against the appliance's clock.
        assert body["from"] == -600_000
        assert body["limit"] > 0

    @pytest.mark.asyncio
    async def test_a_failed_read_raises_rather_than_returning_an_empty_list(self) -> None:
        """An empty list is "the network was quiet". An exception is "we
        could not look". The scheduler records the second as a failure and
        the first as a healthy poll, and they must not be the same value."""

        def handle(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("/oauth2/token"):
                return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
            return httpx.Response(503, json={"error": "unavailable"})

        connector = ExtraHopConnector(api_host="https://h", client_id="a", client_secret="b", transport=httpx.MockTransport(handle))
        with pytest.raises(httpx.HTTPStatusError):
            await connector.fetch_alerts()
