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

import base64
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
    async def test_every_message_in_the_batch_is_eventually_acknowledged(self, service_account_json: str) -> None:
        """Every message the poll consumed is answered — once the scheduler
        commits. A connector that never acknowledges is not safe, it is a
        subscription that never drains."""
        _mock_token()
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        ack = respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))

        connector = _connector(service_account_json)
        await connector.fetch_alerts()
        await connector.commit_acknowledgements()

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

        connector = _connector(service_account_json)
        assert await connector.fetch_alerts() == []
        await connector.commit_acknowledgements()

        assert json.loads(ack.calls.last.request.content)["ackIds"] == ["ack-empty"]


def _entry(timestamp: str, insert_id: str) -> str:
    """One base64-encoded ``LogEntry``, the shape a sink publishes."""
    return base64.b64encode(
        json.dumps(
            {
                "insertId": insert_id,
                "timestamp": timestamp,
                "severity": "NOTICE",
                "logName": "projects/example-logging/logs/cloudaudit.googleapis.com%2Factivity",
                "resource": {"type": "gce_instance", "labels": {"project_id": "example-prod"}},
                "protoPayload": {"methodName": "v1.compute.instances.insert", "authenticationInfo": {"principalEmail": "a@example.com"}},
            }
        ).encode()
    ).decode()


def _received(message_id: str, ack_id: str, timestamp: str, insert_id: str) -> dict[str, Any]:
    return {"ackId": ack_id, "message": {"messageId": message_id, "publishTime": timestamp, "data": _entry(timestamp, insert_id)}}


class TestTheAckOutlivesTheFetch:
    """Phase 3, finding 4. Acknowledging is the irreversible step.

    A Pub/Sub ack makes the subscription forget the message. The existing
    tests pin that the ack comes after the entries are *decoded*, which is one
    layer short of the thing that matters: ``fetch_alerts`` returns, and only
    then does the scheduler push to ingest. Between those two points the
    messages exist nowhere but a local list.
    """

    @pytest.mark.asyncio
    @respx.mock
    async def test_nothing_is_acknowledged_while_the_entries_are_only_in_a_list(self, service_account_json: str) -> None:
        _mock_token()
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        ack = respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))

        alerts = await _connector(service_account_json).fetch_alerts()

        assert len(alerts) == 3, "the entries are decoded"
        assert not ack.called, "but nothing durable has accepted them, so the subscription must still hold them"

    @pytest.mark.asyncio
    @respx.mock
    async def test_the_ack_ids_are_staged_for_the_scheduler(self, service_account_json: str) -> None:
        _mock_token()
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))

        connector = _connector(service_account_json)
        await connector.fetch_alerts()

        assert connector.pending_acknowledgements() == [
            "UAYWLF1GSFE3GQhoUQ5PXIz90001",
            "UAYWLF1GSFE3GQhoUQ5PXIz90002",
            "UAYWLF1GSFE3GQhoUQ5PXIz90003",
        ]

    @pytest.mark.asyncio
    @respx.mock
    async def test_committing_acknowledges_exactly_what_was_staged(self, service_account_json: str) -> None:
        _mock_token()
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        ack = respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))
        connector = _connector(service_account_json)
        await connector.fetch_alerts()

        result = await connector.commit_acknowledgements()

        assert json.loads(ack.calls.last.request.content)["ackIds"] == [
            "UAYWLF1GSFE3GQhoUQ5PXIz90001",
            "UAYWLF1GSFE3GQhoUQ5PXIz90002",
            "UAYWLF1GSFE3GQhoUQ5PXIz90003",
        ]
        assert (result.requested, result.confirmed, result.failed) == (3, 3, 0)
        assert connector.pending_acknowledgements() == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_discarding_leaves_the_subscription_holding_them(self, service_account_json: str) -> None:
        _mock_token()
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        ack = respx.post(_ACK_URL).mock(return_value=httpx.Response(200, json={}))
        connector = _connector(service_account_json)
        await connector.fetch_alerts()

        connector.discard_acknowledgements()

        assert not ack.called
        assert connector.pending_acknowledgements() == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_expired_ack_deadline_is_reported_rather_than_assumed(self, service_account_json: str) -> None:
        """The bounded-hold failure mode. Pub/Sub answers 400 for an ack id
        whose deadline has passed; the message is already being redelivered,
        so the honest outcome is a counted failure, not a silent success."""
        _mock_token()
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json=_pull_response()), httpx.Response(200, json={})])
        respx.post(_ACK_URL).mock(return_value=httpx.Response(400, json={"error": "ack id expired"}))
        connector = _connector(service_account_json)
        await connector.fetch_alerts()

        result = await connector.commit_acknowledgements()

        assert (result.requested, result.confirmed, result.failed) == (3, 0, 3)

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_empty_payload_message_is_still_staged(self, service_account_json: str) -> None:
        """It produced no event, so no downstream acceptance will ever cover
        it — but leaving it unacknowledged forever is how a subscription stops
        draining. It rides along with the batch's own acknowledgement."""
        _mock_token()
        respx.post(_PULL_URL).mock(
            side_effect=[
                httpx.Response(200, json={"receivedMessages": [{"ackId": "ack-empty", "message": {"messageId": "1", "data": ""}}]}),
                httpx.Response(200, json={}),
            ]
        )
        connector = _connector(service_account_json)

        assert await connector.fetch_alerts() == []
        assert connector.pending_acknowledgements() == ["ack-empty"]


class TestAnOlderEntryArrivingLaterSurvives:
    """Phase 3, finding 5.

    The module docstring says the cursor "tolerates a late arrival by
    re-reading its own overlap", which is not what the base class does: it
    keeps a single monotonic ``(event_time, record_id)`` high-water mark and
    drops anything at or below it. A sink sets no ordering key, so a late
    entry is routine — and it is discarded the first time it is ever seen.
    """

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_entry_older_than_the_last_batch_is_still_emitted(self, service_account_json: str) -> None:
        _mock_token()
        respx.post(_PULL_URL).mock(
            side_effect=[
                httpx.Response(200, json={"receivedMessages": [_received("m-new", "ack-new", "2026-10-08T11:00:00Z", "newer")]}),
                httpx.Response(200, json={}),
            ]
        )
        first = _connector(service_account_json)
        assert len(await first.fetch_alerts()) == 1
        cursor = first.get_checkpoint()
        assert cursor is not None

        respx.post(_PULL_URL).mock(
            side_effect=[
                httpx.Response(200, json={"receivedMessages": [_received("m-old", "ack-old", "2026-10-08T09:00:00Z", "older")]}),
                httpx.Response(200, json={}),
            ]
        )
        resumed = _connector(service_account_json)
        resumed.set_checkpoint(cursor)

        assert [a["external_id"] for a in await resumed.fetch_alerts()] == ["older"], (
            "Pub/Sub gives no ordering without an ordering key, so this entry has never been seen before"
        )

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_genuine_redelivery_is_still_suppressed(self, service_account_json: str) -> None:
        """Pub/Sub is at-least-once, so the same message really does arrive
        twice whenever an ack does not land. Removing the cursor outright
        would trade a silent drop for a silent duplicate."""
        _mock_token()
        same = [_received("m-1", "ack-1", "2026-10-08T11:00:00Z", "entry-1")]
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json={"receivedMessages": same}), httpx.Response(200, json={})])
        first = _connector(service_account_json)
        assert len(await first.fetch_alerts()) == 1
        cursor = first.get_checkpoint()

        # Redelivered: same messageId, a fresh ackId, exactly as Pub/Sub does it.
        redelivered = [_received("m-1", "ack-1-again", "2026-10-08T11:00:00Z", "entry-1")]
        respx.post(_PULL_URL).mock(side_effect=[httpx.Response(200, json={"receivedMessages": redelivered}), httpx.Response(200, json={})])
        resumed = _connector(service_account_json)
        resumed.set_checkpoint(cursor)

        assert await resumed.fetch_alerts() == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_two_entries_sharing_a_timestamp_both_survive(self, service_account_json: str) -> None:
        _mock_token()
        respx.post(_PULL_URL).mock(
            side_effect=[
                httpx.Response(200, json={"receivedMessages": [_received("m-a", "ack-a", "2026-10-08T11:00:00Z", "tie-a")]}),
                httpx.Response(200, json={}),
            ]
        )
        first = _connector(service_account_json)
        await first.fetch_alerts()
        cursor = first.get_checkpoint()

        respx.post(_PULL_URL).mock(
            side_effect=[
                httpx.Response(200, json={"receivedMessages": [_received("m-b", "ack-b", "2026-10-08T11:00:00Z", "tie-b")]}),
                httpx.Response(200, json={}),
            ]
        )
        resumed = _connector(service_account_json)
        resumed.set_checkpoint(cursor)

        assert [a["external_id"] for a in await resumed.fetch_alerts()] == ["tie-b"]


class TestTheHoldIsBounded:
    @pytest.mark.asyncio
    @respx.mock
    async def test_the_poll_stops_pulling_near_the_ack_deadline(self, service_account_json: str, monkeypatch: pytest.MonkeyPatch) -> None:
        """A held ackId is only good until the deadline expires, so the poll
        stops taking new messages rather than collecting a batch whose first
        half it can no longer answer for."""
        from app.connectors import gcp_pubsub as module

        clock = {"now": 0.0}
        monkeypatch.setattr(module.time, "monotonic", lambda: clock["now"])
        _mock_token()

        def _slow_pull(_request: httpx.Request) -> httpx.Response:
            clock["now"] += 20.0
            return httpx.Response(200, json={"receivedMessages": _pull_response()["receivedMessages"] * 84})

        pull = respx.post(_PULL_URL).mock(side_effect=_slow_pull)

        await _connector(service_account_json, ack_deadline_seconds=30).fetch_alerts()

        assert pull.call_count == 1


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
