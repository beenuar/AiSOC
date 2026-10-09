"""Depth plan 4.1 — the Pub/Sub subscription a Cloud Logging sink feeds.

The pull response under ``tests/fixtures/gcp_pubsub/`` is the wire shape
Pub/Sub returns, carrying three real ``LogEntry`` payloads base64-encoded in
``message.data``: a denied Data Access read, an IAM policy change, and a VPC
flow record. Decoding is therefore exercised end to end rather than mocked
at the point the defect would live.

The RSA key is generated per module and the token endpoint is intercepted,
so the JWT assertion is really signed — the same choice ``test_gcp_connectors``
made, for the same reason: a stubbed signer cannot fail the way a real one
does when a key field is missing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx
from app.connectors.gcp_pubsub import GCPPubSubConnector, _entry_severity
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

FIXTURES = Path(__file__).parent / "fixtures" / "gcp_pubsub"
_PROJECT = "example-logging"
_SUBSCRIPTION = "aisoc-log-sink-sub"
_SUB_PATH = f"projects/{_PROJECT}/subscriptions/{_SUBSCRIPTION}"
_PULL_URL = f"https://pubsub.googleapis.com/v1/{_SUB_PATH}:pull"
_ACK_URL = f"https://pubsub.googleapis.com/v1/{_SUB_PATH}:acknowledge"
_GET_URL = f"https://pubsub.googleapis.com/v1/{_SUB_PATH}"
_TOKEN_URL = "https://oauth2.googleapis.com/token"


@pytest.fixture(scope="module")
def service_account_json() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {
            "type": "service_account",
            "project_id": _PROJECT,
            "private_key": pem,
            "client_email": "aisoc-sink@example-logging.iam.gserviceaccount.com",
            "token_uri": _TOKEN_URL,
        }
    )


def _pull_response() -> dict[str, Any]:
    return json.loads((FIXTURES / "pull_response.json").read_text(encoding="utf-8"))


def _connector(service_account_json: str, **kwargs: Any) -> GCPPubSubConnector:
    return GCPPubSubConnector(
        project_id=_PROJECT,
        subscription_id=_SUBSCRIPTION,
        service_account_json=service_account_json,
        **kwargs,
    )


def _mock_token() -> None:
    respx.post(_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "ya29.test", "expires_in": 3599}))


class TestConfiguration:
    def test_a_key_blob_that_is_not_json_names_the_field(self, service_account_json: str) -> None:
        """`cryptography` would otherwise raise at signing time about PEM
        headers, which tells the operator nothing about what they pasted."""
        with pytest.raises(ValueError, match="service_account_json is not valid JSON"):
            _connector("not json")

    def test_a_key_missing_its_private_key_is_refused_at_construction(self) -> None:
        blob = json.dumps({"client_email": "a@b.iam.gserviceaccount.com", "token_uri": _TOKEN_URL})
        with pytest.raises(ValueError, match="private_key"):
            _connector(blob)

    def test_the_subscription_id_is_a_secret_free_schema_field(self) -> None:
        secrets = {f.name for f in GCPPubSubConnector.schema().fields if f.type == "secret"}
        assert secrets == {"service_account_json"}


class TestSeverity:
    @pytest.mark.parametrize(
        ("severity", "expected"),
        [("DEBUG", "info"), ("INFO", "info"), ("NOTICE", "low"), ("WARNING", "medium"), ("ERROR", "high")],
    )
    def test_the_vendor_ladder_maps_onto_five_tiers(self, severity: str, expected: str) -> None:
        assert _entry_severity({"severity": severity}) == expected

    @pytest.mark.parametrize("severity", ["CRITICAL", "ALERT", "EMERGENCY"])
    def test_googles_three_top_tiers_stay_critical(self, severity: str) -> None:
        """Collapsing a vendor's own top tier into `high` is the loss nobody
        notices until the one event that needed it is filed as routine."""
        assert _entry_severity({"severity": severity}) == "critical"

    def test_a_denied_call_outranks_the_severity_field(self) -> None:
        """GCP writes an IAM denial at INFO with a non-zero status code.
        Reading only `severity` files an attacker enumerating permissions at
        the same tier as a successful read."""
        assert _entry_severity({"severity": "INFO", "protoPayload": {"status": {"code": 7}}}) == "low"
        assert _entry_severity({"severity": "WARNING", "protoPayload": {"status": {"code": 7}}}) == "high"

    def test_a_zero_status_code_is_not_a_denial(self) -> None:
        assert _entry_severity({"severity": "INFO", "protoPayload": {"status": {"code": 0}}}) == "info"


class TestAPoll:
    @pytest.mark.asyncio
    @respx.mock
    async def test_the_sink_payload_is_decoded_and_normalized(self, service_account_json: str) -> None:
        _mock_token()
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))

        alerts = await _connector(service_account_json).fetch_alerts()

        assert [a["method_name"] for a in alerts] == ["storage.objects.list", "SetIamPolicy", None]
        assert alerts[0]["user_name"] == "svc-exporter@example-prod.iam.gserviceaccount.com"
        assert alerts[0]["src_ip"] == "198.51.100.24"
        assert alerts[0]["error_code"] == "7"
        assert alerts[0]["severity"] == "low", "a denied Data Access read is bumped above plain INFO"
        assert alerts[2]["gcp_resource_type"] == "gce_subnetwork"

    @pytest.mark.asyncio
    @respx.mock
    async def test_every_message_in_the_batch_is_acknowledged(self, service_account_json: str) -> None:
        _mock_token()
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        ack = respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))

        await _connector(service_account_json).fetch_alerts()

        assert ack.called
        assert json.loads(ack.calls.last.request.content)["ackIds"] == [
            "UAYWLF1GSFE3GQhoUQ5PXIz90001",
            "UAYWLF1GSFE3GQhoUQ5PXIz90002",
            "UAYWLF1GSFE3GQhoUQ5PXIz90003",
        ]

    @pytest.mark.asyncio
    @respx.mock
    async def test_nothing_is_acknowledged_when_building_the_batch_fails(
        self, service_account_json: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The ordering, pinned rather than described.

        Acknowledging a Pub/Sub message is irreversible — the subscription
        forgets it. So the acknowledgement has to come after the entries are
        in hand, and a test that only inspects the ack ids passes just as
        happily when the call is moved above the loop. This one fails if it
        is: the batch cannot be built, and the only safe outcome is that the
        messages stay on the subscription.
        """
        from app.connectors import gcp_pubsub as module

        def _explode(_message: Any) -> dict[str, Any]:
            raise RuntimeError("decoding this batch failed")

        monkeypatch.setattr(module, "_decode", _explode)
        _mock_token()
        respx.post(_PULL_URL).mock(return_value=httpx.Response(200, json=_pull_response()))
        ack = respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))

        with pytest.raises(RuntimeError, match="decoding this batch failed"):
            await _connector(service_account_json).fetch_alerts()

        assert not ack.called, "an acknowledgement before the entries are in hand loses them permanently"

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_pull_failure_leaves_the_subscription_untouched(self, service_account_json: str) -> None:
        """Nothing is acknowledged, so Pub/Sub redelivers and the poll costs a
        retry rather than the batch."""
        _mock_token()
        respx.post(_PULL_URL).mock(return_value=httpx.Response(503, json={"error": "unavailable"}))
        ack = respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))

        assert await _connector(service_account_json).fetch_alerts() == []
        assert not ack.called

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_401_drops_the_cached_token(self, service_account_json: str) -> None:
        """A rotated key otherwise presents the dead token every poll until
        someone restarts the service."""
        _mock_token()
        respx.post(_PULL_URL).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))
        connector = _connector(service_account_json)

        assert await connector.fetch_alerts() == []
        assert connector._auth._access_token is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_redelivered_message_is_suppressed_by_the_cursor(self, service_account_json: str) -> None:
        """Pub/Sub is at-least-once and a sink sets no ordering key, so the
        same entry arrives twice whenever an ack does not land."""
        _mock_token()
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))
        first = _connector(service_account_json)
        assert len(await first.fetch_alerts()) == 3
        cursor = first.get_checkpoint()
        assert cursor is not None

        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        resumed = _connector(service_account_json)
        resumed.set_checkpoint(cursor)

        assert await resumed.fetch_alerts() == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_empty_payload_is_still_acknowledged(self, service_account_json: str) -> None:
        """Leaving it unacknowledged would redeliver it forever and the
        subscription would never drain."""
        _mock_token()
        respx.post(_PULL_URL).mock(
            side_effect=[
                httpx.Response(200, json={"receivedMessages": [{"ackId": "ack-empty", "message": {"messageId": "1", "data": ""}}]}),
                httpx.Response(200, json={}),
            ]
        )
        ack = respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))

        assert await _connector(service_account_json).fetch_alerts() == []
        assert json.loads(ack.calls.last.request.content)["ackIds"] == ["ack-empty"]


class TestBackpressure:
    def test_the_budget_is_declared_and_says_where_the_remainder_goes(self) -> None:
        budget = GCPPubSubConnector.collection_budget
        assert budget is not None
        assert budget.max_batches_per_poll > 0
        assert budget.max_events_per_poll > 0
        assert "unacknowledged" in budget.backlog_stays_on_the_queue

    @pytest.mark.asyncio
    @respx.mock
    async def test_the_poll_stops_at_the_budget_rather_than_draining(
        self, service_account_json: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from app.connectors import base as base_mod

        monkeypatch.setattr(
            GCPPubSubConnector,
            "collection_budget",
            base_mod.CollectionBudget(
                max_batches_per_poll=2,
                max_events_per_poll=1,
                backlog_stays_on_the_queue="test bound; it stays unacknowledged on the subscription",
            ),
        )
        _mock_token()
        # A full page every time, so a connector that ignored the budget
        # would loop until the mock ran out rather than stopping.
        full = {"receivedMessages": _pull_response()["receivedMessages"] * 84}
        pull = respx.post(_PULL_URL).mock(return_value=httpx.Response(200, json=full))
        respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))

        await _connector(service_account_json).fetch_alerts()

        assert pull.call_count == 1, "the second batch is never requested once the event budget is spent"


class TestTestConnection:
    @pytest.mark.asyncio
    @respx.mock
    async def test_it_describes_rather_than_pulls(self, service_account_json: str) -> None:
        """A pull at setup consumes messages a half-finished configuration
        then loses."""
        _mock_token()
        described = json.loads((FIXTURES / "subscription.json").read_text(encoding="utf-8"))
        respx.get(_GET_URL).mock(return_value=httpx.Response(200, json=described))
        pull = respx.post(_PULL_URL).mock(return_value=httpx.Response(200, json={}))

        result = await _connector(service_account_json).test_connection()

        assert result["success"] is True
        assert result["topic"] == "projects/example-logging/topics/aisoc-log-sink"
        assert not pull.called

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_short_ack_deadline_is_called_out_at_setup(self, service_account_json: str) -> None:
        """The one misconfiguration that silently duplicates every message.
        Found here, or found later from the duplicates."""
        _mock_token()
        respx.get(_GET_URL).mock(return_value=httpx.Response(200, json={"topic": "t", "ackDeadlineSeconds": 10}))

        result = await _connector(service_account_json).test_connection()

        assert result["success"] is True
        assert "redeliver" in result["warning"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_push_subscription_is_called_out(self, service_account_json: str) -> None:
        _mock_token()
        respx.get(_GET_URL).mock(
            return_value=httpx.Response(200, json={"topic": "t", "ackDeadlineSeconds": 120, "pushConfig": {"pushEndpoint": "https://x"}})
        )

        result = await _connector(service_account_json).test_connection()

        assert "pull subscription" in result["warning"]
