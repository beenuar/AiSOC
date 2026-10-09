"""Depth plan 4.1 — the CloudTrail organisation trail on S3, read over SQS.

Every input here is a vendor-shaped payload recorded under
``tests/fixtures/aws_cloudtrail_s3/``: a real S3 event notification, the SNS
envelope an organisation trail produces when the bucket notifies a topic, a
CloudTrail object carrying both management and data events, and a VPC flow
log object with its header line. A fixture built from the connector's own
``normalize`` would only prove the connector agrees with itself.

The fakes are deliberately *less* capable than boto3, not more. A double
that answers any ``get_object`` with the same body cannot show that the
object key decides how the body is parsed, and a double that acknowledges
every delete cannot show that an unreadable object leaves its message on the
queue — which is the behaviour the whole backpressure argument rests on.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest
from app.connectors.aws_cloudtrail_s3 import (
    KIND_FLOW,
    KIND_MANAGEMENT,
    AWSCloudTrailS3Connector,
    _classify,
    _s3_notifications,
)

FIXTURES = Path(__file__).parent / "fixtures" / "aws_cloudtrail_s3"

CLOUDTRAIL_KEY = (
    "AWSLogs/o-abc123def4/123456789012/CloudTrail/us-east-1/2026/10/08/123456789012_CloudTrail_us-east-1_20261008T1100Z_a1b2c3d4.json.gz"
)
FLOWLOG_KEY = (
    "AWSLogs/123456789012/vpcflowlogs/eu-west-1/2026/10/08/123456789012_vpcflowlogs_eu-west-1_fl-0a1b2c3d_20261008T1105Z_9f8e7d6c.log.gz"
)


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class _FakeSQS:
    """A queue that hands out exactly what it was given and records deletes."""

    def __init__(self, batches: list[list[dict[str, Any]]]):
        self._batches = list(batches)
        self.deleted: list[str] = []
        self.receive_calls = 0
        self.last_visibility: int | None = None

    def receive_message(self, **kwargs: Any) -> dict[str, Any]:
        self.receive_calls += 1
        self.last_visibility = kwargs.get("VisibilityTimeout")
        if not self._batches:
            return {}
        return {"Messages": self._batches.pop(0)}

    def delete_message(self, **kwargs: Any) -> dict[str, Any]:
        self.deleted.append(kwargs["ReceiptHandle"])
        return {}

    def get_queue_attributes(self, **kwargs: Any) -> dict[str, Any]:
        return {"Attributes": {"QueueArn": "arn:aws:sqs:us-east-1:123456789012:q", "ApproximateNumberOfMessages": "4211"}}


class _FakeS3:
    """Objects by key. A key nobody put here raises, like S3's NoSuchKey."""

    def __init__(self, objects: dict[str, bytes]):
        self._objects = objects
        self.reads: list[str] = []

    def get_object(self, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803 - boto3's parameter names
        self.reads.append(Key)
        if Key not in self._objects:
            raise KeyError(f"NoSuchKey: {Key}")

        class _Body:
            def __init__(self, data: bytes):
                self._data = data

            def read(self) -> bytes:
                return self._data

        return {"Body": _Body(self._objects[Key])}


def _connector(sqs: _FakeSQS, s3: _FakeS3, **kwargs: Any) -> AWSCloudTrailS3Connector:
    connector = AWSCloudTrailS3Connector(queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/q", **kwargs)
    connector._client = lambda service: sqs if service == "sqs" else s3  # type: ignore[method-assign]
    return connector


def _message(handle: str, body: str) -> dict[str, Any]:
    return {"ReceiptHandle": handle, "Body": body}


def _objects() -> dict[str, bytes]:
    return {
        CLOUDTRAIL_KEY: gzip.compress(_fixture("cloudtrail_object.json").encode()),
        FLOWLOG_KEY: gzip.compress(_fixture("vpcflowlogs_object.txt").encode()),
    }


class TestTheNotificationEnvelope:
    def test_a_raw_s3_notification_names_its_object(self) -> None:
        assert _s3_notifications(_fixture("sqs_s3_notification.json")) == [("example-org-trail", CLOUDTRAIL_KEY)]

    def test_an_sns_wrapped_notification_is_unwrapped(self) -> None:
        """An organisation trail fanning out through SNS is the common shape,
        and a reader that only understands the raw envelope sees an empty
        queue rather than an error."""
        assert _s3_notifications(_fixture("sqs_sns_wrapped.json")) == [("example-org-trail", FLOWLOG_KEY)]

    def test_a_percent_encoded_key_is_decoded(self) -> None:
        """S3 encodes the key in the notification and GetObject wants it
        decoded, so a prefix with a space 404s without this."""
        body = json.dumps({"Records": [{"s3": {"bucket": {"name": "b"}, "object": {"key": "AWSLogs/my+trail/CloudTrail/a%3Db.json.gz"}}}]})
        assert _s3_notifications(body) == [("b", "AWSLogs/my trail/CloudTrail/a=b.json.gz")]

    def test_the_s3_test_event_yields_nothing_and_is_not_an_error(self) -> None:
        """S3 sends one of these when the notification is configured. It is
        not a failure and must not be logged as one."""
        assert _s3_notifications(json.dumps({"Service": "Amazon S3", "Event": "s3:TestEvent"})) == []


class TestObjectClassification:
    @pytest.mark.parametrize(
        ("key", "expected"),
        [
            (CLOUDTRAIL_KEY, KIND_MANAGEMENT),
            (FLOWLOG_KEY, KIND_FLOW),
            ("AWSLogs/o-x/1/CloudTrail-Digest/us-east-1/2026/10/08/x.json.gz", None),
            ("AWSLogs/o-x/1/CloudTrail-Insight/us-east-1/2026/10/08/x.json.gz", None),
            ("AWSLogs/o-x/1/Config/us-east-1/x.json.gz", None),
        ],
    )
    def test_the_key_decides_what_is_inside(self, key: str, expected: str | None) -> None:
        """A digest is a signature over other objects, not events. Reading it
        as CloudTrail would raise on every poll."""
        assert _classify(key) == expected


class TestAPoll:
    @pytest.mark.asyncio
    async def test_management_and_data_events_arrive_from_one_object(self) -> None:
        sqs = _FakeSQS([[_message("h1", _fixture("sqs_s3_notification.json"))]])
        connector = _connector(sqs, _FakeS3(_objects()))

        alerts = await connector.fetch_alerts()

        assert [a["event_name"] for a in alerts] == ["StopLogging", "GetObject", "GetObject"]
        assert [a["event_category"] for a in alerts] == ["Management", "Data", "Data"]

    @pytest.mark.asyncio
    async def test_a_data_event_denial_outranks_the_successful_reads(self) -> None:
        """GetObject at scale is not a finding; AccessDenied on a PII bucket
        is the enumeration half of an exfiltration attempt. Scoring both the
        same is how the trail buries it."""
        sqs = _FakeSQS([[_message("h1", _fixture("sqs_s3_notification.json"))]])
        connector = _connector(sqs, _FakeS3(_objects()))

        by_id = {a["external_id"]: a for a in await connector.fetch_alerts()}

        assert by_id["22222222-2222-4222-8222-222222222222"]["severity"] == "medium"
        assert by_id["33333333-3333-4333-8333-333333333333"]["severity"] == "info"
        assert by_id["11111111-1111-4111-8111-111111111111"]["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_a_service_principal_hostname_is_not_an_ip(self) -> None:
        """CloudTrail writes `cloudtrail.amazonaws.com` into sourceIPAddress
        for internal callers. Substring-matching `amazonaws.com` would also
        accept `amazonaws.com.attacker.tld`, so the field is validated."""
        sqs = _FakeSQS([[_message("h1", _fixture("sqs_s3_notification.json"))]])
        connector = _connector(sqs, _FakeS3(_objects()))

        by_id = {a["external_id"]: a for a in await connector.fetch_alerts()}

        assert by_id["22222222-2222-4222-8222-222222222222"]["src_ip"] is None
        assert by_id["11111111-1111-4111-8111-111111111111"]["src_ip"] == "198.51.100.24"

    @pytest.mark.asyncio
    async def test_data_events_can_be_switched_off(self) -> None:
        sqs = _FakeSQS([[_message("h1", _fixture("sqs_s3_notification.json"))]])
        connector = _connector(sqs, _FakeS3(_objects()), include_data_events=False)

        assert [a["event_category"] for a in await connector.fetch_alerts()] == ["Management"]

    @pytest.mark.asyncio
    async def test_flow_logs_use_the_header_line_rather_than_a_positional_guess(self) -> None:
        """The S3 flow-log format starts with a header naming its fields —
        the one thing the CloudWatch path does not give you. Ignoring it maps
        every column one place to the left on a v5 custom layout."""
        sqs = _FakeSQS([[_message("h1", _fixture("sqs_sns_wrapped.json"))]])
        connector = _connector(sqs, _FakeS3(_objects()))

        alerts = await connector.fetch_alerts()

        assert [a["action"] for a in alerts] == ["REJECT", "ACCEPT", None]
        assert alerts[0]["src_ip"] == "198.51.100.24"
        assert alerts[0]["dst_port"] == "22"
        assert alerts[0]["severity"] == "medium"
        assert alerts[2]["severity"] == "info"

    @pytest.mark.asyncio
    async def test_flow_logs_can_be_switched_off(self) -> None:
        sqs = _FakeSQS([[_message("h1", _fixture("sqs_sns_wrapped.json"))]])
        connector = _connector(sqs, _FakeS3(_objects()), include_flow_logs=False)

        assert await connector.fetch_alerts() == []
        assert sqs.deleted == ["h1"], "a filtered-out object still consumes its notification"


class TestAcknowledgementIsTheCheckpoint:
    @pytest.mark.asyncio
    async def test_a_fully_read_object_acknowledges_its_message(self) -> None:
        sqs = _FakeSQS([[_message("h1", _fixture("sqs_s3_notification.json"))]])
        connector = _connector(sqs, _FakeS3(_objects()))

        await connector.fetch_alerts()

        assert sqs.deleted == ["h1"]

    @pytest.mark.asyncio
    async def test_an_unreadable_object_leaves_its_message_on_the_queue(self) -> None:
        """The property the whole design rests on. Deleting before the events
        are out turns one transient S3 error into a permanent hole in the
        audit trail, and the hole is invisible."""
        sqs = _FakeSQS([[_message("h1", _fixture("sqs_s3_notification.json"))]])
        connector = _connector(sqs, _FakeS3({}))  # the object is not there

        alerts = await connector.fetch_alerts()

        assert alerts == []
        assert sqs.deleted == [], "the message must redeliver, not disappear"

    @pytest.mark.asyncio
    async def test_a_redelivered_object_is_suppressed_by_the_cursor(self) -> None:
        """SQS is at-least-once by contract, so the same object arrives twice
        whenever a delete does not land. The cursor is what stops that
        becoming three copies of every alert."""
        first = _FakeSQS([[_message("h1", _fixture("sqs_s3_notification.json"))]])
        connector = _connector(first, _FakeS3(_objects()))
        assert len(await connector.fetch_alerts()) == 3
        cursor = connector.get_checkpoint()
        assert cursor is not None

        second = _FakeSQS([[_message("h2", _fixture("sqs_s3_notification.json"))]])
        resumed = _connector(second, _FakeS3(_objects()))
        resumed.set_checkpoint(cursor)

        assert await resumed.fetch_alerts() == []

    @pytest.mark.asyncio
    async def test_an_undecodable_notification_is_consumed_rather_than_looped(self) -> None:
        """A message that can never become events has to leave the queue, or
        it redelivers until its retention expires."""
        sqs = _FakeSQS([[_message("h1", "not json at all")]])
        connector = _connector(sqs, _FakeS3(_objects()))

        assert await connector.fetch_alerts() == []
        assert sqs.deleted == ["h1"]


class TestBackpressure:
    def test_the_budget_is_declared_and_says_where_the_remainder_goes(self) -> None:
        budget = AWSCloudTrailS3Connector.collection_budget
        assert budget is not None
        assert budget.max_batches_per_poll > 0
        assert budget.max_events_per_poll > 0
        assert "queue" in budget.backlog_stays_on_the_queue

    @pytest.mark.asyncio
    async def test_a_deep_queue_is_drained_over_several_polls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The reason the bound exists. A six-hour backlog read in one pass
        is an out-of-memory kill followed by a flood through ingest."""
        from app.connectors import base as base_mod

        monkeypatch.setattr(
            AWSCloudTrailS3Connector,
            "collection_budget",
            base_mod.CollectionBudget(
                max_batches_per_poll=1,
                max_events_per_poll=2,
                backlog_stays_on_the_queue="test bound; the queue keeps the rest",
            ),
        )
        batches = [[_message(f"h{i}", _fixture("sqs_s3_notification.json"))] for i in range(4)]
        sqs = _FakeSQS(batches)
        connector = _connector(sqs, _FakeS3(_objects()))

        alerts = await connector.fetch_alerts()

        # One receive call, so three of the four notifications were never
        # taken off the queue and are still there for the next poll.
        assert sqs.receive_calls == 1
        assert len(alerts) == 3, "the object is the atomic unit, so the bound overshoots by at most one object"
        assert sqs.deleted == ["h0"]

    @pytest.mark.asyncio
    async def test_the_visibility_timeout_reaches_the_receive_call(self) -> None:
        """A timeout shorter than one poll re-announces an object this poll is
        still reading, which produces duplicates that look like a vendor bug."""
        sqs = _FakeSQS([])
        connector = _connector(sqs, _FakeS3({}), visibility_timeout_seconds=600)

        await connector.fetch_alerts()

        assert sqs.last_visibility == 600


class TestTestConnection:
    @pytest.mark.asyncio
    async def test_it_reports_the_backlog_depth(self) -> None:
        """A reachable queue holding a million messages is a connector about
        to be switched on against a flood, and setup is when to say so."""
        connector = _connector(_FakeSQS([]), _FakeS3({}))

        result = await connector.test_connection()

        assert result["success"] is True
        assert result["approximate_backlog"] == 4211

    @pytest.mark.asyncio
    async def test_a_missing_queue_url_is_refused_before_any_call(self) -> None:
        connector = AWSCloudTrailS3Connector(queue_url="")

        result = await connector.test_connection()

        assert result["success"] is False
        assert "queue_url" in result["error"]
