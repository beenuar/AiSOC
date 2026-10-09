"""
AWS CloudTrail organisation trail on S3, discovered over SQS.

Why this exists beside ``aws_cloudtrail.py``
--------------------------------------------

``cloudtrail:LookupEvents`` — what the existing connector polls — is the
small-account path and AWS documents it as such. Three limits make it
unusable for an estate:

* it is rate-limited to two transactions per second per region per account,
  so one poll of a curated eighty-event allow-list already takes the better
  part of a minute, and an organisation with fifty accounts multiplies that
  by fifty;
* it returns **management events only**. S3 and Lambda *data* events — the
  ones that answer "what did they read out of the bucket" — never appear;
* VPC flow logs are not CloudTrail at all.

An organisation trail answers all three: one trail at the organisation root
writes every member account's management events, data events and (configured
separately, into the same bucket) VPC flow logs as gzipped objects in S3, and
an S3 event notification announces each object on an SQS queue. That is the
shape every large estate already runs, and it is what this connector reads.

``aws_cloudtrail.py`` stays. A single account with no trail still has ninety
days of management history in ``LookupEvents`` and needs no bucket, no queue
and no notification wiring, and telling that operator to build an
organisation trail first would be the wrong trade.

How a poll works
----------------

1. ``sqs:ReceiveMessage`` for up to ten notifications at a time. Each is
   either a raw S3 event notification or the same thing wrapped in an SNS
   envelope, which is what an organisation trail fanning out to several
   subscribers produces.
2. For each announced object, ``s3:GetObject`` and gunzip. The key says what
   is inside — CloudTrail JSON, a CloudTrail digest (skipped: it is a
   signature over other files, not events), or VPC flow-log text.
3. Every record becomes one envelope carrying its event time and a stable
   id, so the base class's checkpoint can order and de-duplicate them.
4. ``sqs:DeleteMessage`` once the object's records are out. Delete-after,
   never delete-before: a crash between the two redelivers the object, and a
   duplicate is recoverable where a silently dropped object is not.

Resumption and backpressure
---------------------------

The queue *is* the cursor. Nothing is lost while this connector is down,
because an undeleted message returns after its visibility timeout, and the
trail keeps writing to S3 regardless. The declared checkpoint is the second
layer: redelivery is normal in SQS (at-least-once), so the ``(event_time,
record_id)`` cursor suppresses the re-read of an object the previous poll
had already emitted but whose delete did not land.

``collection_budget`` bounds the poll. A queue that accumulated through a
six-hour outage holds six hours of an estate's control plane, and draining
that in one pass is an out-of-memory kill followed by a flood through
ingest. The bound is applied **between objects, never inside one**: a
partially-read object either loses its tail (if the message is deleted) or
never completes (if it is not), so the object is the atomic unit and the
budget means "stop taking new work", which can overshoot by one object's
worth of records. Whatever is left stays on the queue and the next poll
takes it.

Auth model
----------

The same dual mode as every other AWS connector: leave the key fields blank
to use the task role or instance profile, or supply a static pair. The
permissions needed are ``sqs:ReceiveMessage``, ``sqs:DeleteMessage``,
``sqs:GetQueueAttributes`` on the queue and ``s3:GetObject`` on the trail
prefix — read-only, and narrower than the existing connector's
``cloudtrail:LookupEvents`` over the whole account.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote_plus

import structlog

from app.connectors.aws_cloudtrail import _event_severity as _management_event_severity
from app.connectors.aws_vpc_flow import _parse_v2_record, _record_severity
from app.connectors.base import (
    BaseConnector,
    Capability,
    CollectionBudget,
    ConnectorSchema,
    Field,
)

logger = structlog.get_logger()


#: Key fragments that say what an object holds. AWS fixes these prefixes, so
#: classifying on the key is reading a documented contract rather than
#: guessing — and it avoids downloading a digest file to find out it was one.
_CLOUDTRAIL_MARKER = "/CloudTrail/"
_DIGEST_MARKER = "/CloudTrail-Digest/"
_INSIGHT_MARKER = "/CloudTrail-Insight/"
_FLOWLOG_MARKER = "/vpcflowlogs/"

#: Record kinds this connector emits. ``normalize`` branches on these rather
#: than sniffing the payload, so a CloudTrail record that happens to carry a
#: ``srcaddr`` key cannot be mistaken for a flow log.
KIND_MANAGEMENT = "cloudtrail_management"
KIND_DATA = "cloudtrail_data"
KIND_FLOW = "vpc_flow"

#: Data events that mutate or destroy, which read very differently from the
#: ``GetObject`` stream that makes up almost all data-event volume.
_DESTRUCTIVE_DATA_EVENTS = frozenset(
    {
        "DeleteObject",
        "DeleteObjects",
        "DeleteObjectVersion",
        "RestoreObject",
        "PutObjectAcl",
        "PutObjectLegalHold",
        "PutObjectRetention",
        "Decrypt",
        "GenerateDataKey",
    }
)

#: An uncompressed object bigger than this is refused rather than read into
#: memory. CloudTrail caps its own objects far below it; a gzip bomb or a
#: misdirected bucket does not.
MAX_OBJECT_BYTES = 256 * 1024 * 1024


def _data_event_severity(event_name: str, error_code: str | None) -> str:
    """Severity for a CloudTrail *data* event.

    The management ladder is wrong here. Data events are dominated by
    ``GetObject``, which in a busy account is millions of rows a day and is
    not by itself a finding — scoring that ``medium`` would bury the trail.
    What does carry signal is a denial (someone is probing what they can
    reach) and a destructive or crypto operation.
    """
    if error_code:
        # AccessDenied on a data event is the enumeration half of an
        # exfiltration attempt, and it is the one the account owner can act
        # on before anything leaves.
        return "medium"
    if event_name in _DESTRUCTIVE_DATA_EVENTS:
        return "medium"
    return "info"


def _classify(key: str) -> str | None:
    """Which record kind an object key announces, or ``None`` to skip it."""
    if _DIGEST_MARKER in key or _INSIGHT_MARKER in key:
        # A digest is a signed manifest over other objects and an insight
        # file is an aggregate; neither holds events.
        return None
    if _CLOUDTRAIL_MARKER in key:
        return KIND_MANAGEMENT
    if _FLOWLOG_MARKER in key:
        return KIND_FLOW
    return None


def _iso(value: Any) -> str:
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), tz=UTC).isoformat()
    return str(value or "")


def _s3_notifications(body: str) -> list[tuple[str, str]]:
    """``(bucket, key)`` pairs announced by one SQS message body.

    Handles both shapes a trail notification arrives in: the raw S3 event
    notification, and the SNS envelope an organisation trail produces when
    the bucket notifies a topic that several queues subscribe to. A test
    event (``s3:TestEvent``, sent once when the notification is configured)
    carries no ``Records`` and yields nothing, which is correct — it is not
    an error and must not be logged as one.
    """
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return []
    if not isinstance(payload, dict):
        return []

    if payload.get("Type") == "Notification" and isinstance(payload.get("Message"), str):
        try:
            payload = json.loads(payload["Message"])
        except (TypeError, ValueError):
            return []
        if not isinstance(payload, dict):
            return []

    out: list[tuple[str, str]] = []
    for record in payload.get("Records") or []:
        if not isinstance(record, dict):
            continue
        s3 = record.get("s3") or {}
        bucket = ((s3.get("bucket") or {}).get("name")) or ""
        key = ((s3.get("object") or {}).get("key")) or ""
        if bucket and key:
            # S3 percent-encodes the key in the notification and uses `+`
            # for spaces. GetObject takes the decoded form, so a prefix with
            # a space 404s without this.
            out.append((str(bucket), unquote_plus(str(key))))
    return out


class AWSCloudTrailS3Connector(BaseConnector):
    connector_id = "aws_cloudtrail_s3"
    connector_name = "AWS CloudTrail (S3 + SQS)"
    connector_category = "cloud"

    #: `record_id` is `<object key>#<index>`, stable across a redelivery of
    #: the same object, which is what makes the cursor suppress the duplicate
    #: SQS guarantees it will eventually produce.
    checkpoint_time_field = ("event_time",)
    checkpoint_id_field = ("record_id",)

    collection_budget = CollectionBudget(
        max_batches_per_poll=20,
        max_events_per_poll=20_000,
        backlog_stays_on_the_queue=(
            "Only a fully-emitted object's SQS message is deleted, so anything the budget stops short of is "
            "still on the queue and the next poll receives it. A six-hour backlog therefore drains over "
            "several polls instead of in one pass."
        ),
    )

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "AWS CloudTrail organisation trail delivered to S3 and announced on SQS. "
                "Reads management events, data events and VPC flow logs for every member "
                "account from one queue, with the queue as the cursor so nothing is lost "
                "across a restart."
            ),
            docs_url="/docs/connectors/aws-cloudtrail-s3",
            fields=[
                Field("region", "string", "AWS Region", default="us-east-1"),
                Field(
                    "queue_url",
                    "string",
                    "SQS queue URL",
                    required=True,
                    placeholder="https://sqs.us-east-1.amazonaws.com/123456789012/aisoc-cloudtrail",
                    help_text=(
                        "The queue your trail bucket's event notification publishes to. "
                        "Either S3 → SQS directly, or S3 → SNS → SQS; both envelopes are read."
                    ),
                ),
                Field(
                    "access_key",
                    "string",
                    "Access Key ID",
                    required=False,
                    help_text="Leave blank to use the runtime IAM role / instance profile.",
                ),
                Field(
                    "secret_key",
                    "secret",
                    "Secret Access Key",
                    required=False,
                    help_text="Required only when supplying a static access key above.",
                ),
                Field(
                    "include_data_events",
                    "boolean",
                    "Include data events",
                    required=False,
                    default=True,
                    help_text=(
                        "S3 / Lambda / DynamoDB data events. These answer 'what did they read', "
                        "and are the highest-volume thing in the trail — most land at info severity."
                    ),
                ),
                Field(
                    "include_flow_logs",
                    "boolean",
                    "Include VPC flow logs",
                    required=False,
                    default=True,
                    help_text="VPC flow logs published to the same bucket (key prefix .../vpcflowlogs/...).",
                ),
                Field(
                    "visibility_timeout_seconds",
                    "number",
                    "Receive visibility timeout (seconds)",
                    required=False,
                    default=300,
                    help_text=(
                        "How long a received message is hidden from other consumers. Must comfortably exceed "
                        "one poll, or an object is re-announced while this poll is still reading it."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_AUDIT, Capability.PULL_LOGS)

    def __init__(
        self,
        region: str = "us-east-1",
        queue_url: str = "",
        access_key: str = "",
        secret_key: str = "",
        include_data_events: bool = True,
        include_flow_logs: bool = True,
        visibility_timeout_seconds: int = 300,
    ):
        self._region = region
        self._queue_url = queue_url
        self._access_key = access_key
        self._secret_key = secret_key
        self._include_data_events = bool(include_data_events)
        self._include_flow_logs = bool(include_flow_logs)
        self._visibility_timeout = max(30, int(visibility_timeout_seconds or 300))

    def _client(self, service: str):
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - boto3 is a declared dependency
            raise RuntimeError("boto3 is required for the AWS CloudTrail (S3 + SQS) connector") from exc
        kwargs: dict[str, Any] = {"region_name": self._region}
        if self._access_key and self._secret_key:
            kwargs["aws_access_key_id"] = self._access_key
            kwargs["aws_secret_access_key"] = self._secret_key
        return boto3.client(service, **kwargs)

    async def test_connection(self) -> dict[str, Any]:
        """Prove the queue is reachable and report how deep it is.

        The depth is the useful half. A queue that is reachable and holds a
        million messages is a connector about to be switched on against a
        backlog, and the operator should see that at setup rather than
        discover it as a flood.
        """
        if not self._queue_url:
            return {"success": False, "connector": self.connector_id, "error": "queue_url is required"}
        try:
            sqs = self._client("sqs")
            attrs = sqs.get_queue_attributes(
                QueueUrl=self._queue_url,
                AttributeNames=["QueueArn", "ApproximateNumberOfMessages"],
            ).get("Attributes", {})
            return {
                "success": True,
                "connector": self.connector_id,
                "region": self._region,
                "queue_arn": attrs.get("QueueArn"),
                "approximate_backlog": int(attrs.get("ApproximateNumberOfMessages") or 0),
            }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """Drain up to one budget's worth of the queue.

        ``since_seconds`` is ignored, deliberately. The queue is the cursor:
        a time window would either re-read objects already consumed or skip
        objects announced while this connector was down, and the queue
        already answers the question correctly.
        """
        if not self._queue_url:
            logger.warning("cloudtrail_s3.not_configured", reason="queue_url is empty")
            return []
        try:
            sqs = self._client("sqs")
            s3 = self._client("s3")
        except RuntimeError as exc:
            logger.warning("cloudtrail_s3.client_init_failed", error=str(exc))
            return []

        budget = self.collection_budget
        assert budget is not None  # declared on the class; narrows the Optional for mypy
        rows: list[dict[str, Any]] = []
        objects_read = 0
        truncated = False

        for _ in range(budget.max_batches_per_poll):
            if len(rows) >= budget.max_events_per_poll:
                truncated = True
                break
            try:
                received = sqs.receive_message(
                    QueueUrl=self._queue_url,
                    MaxNumberOfMessages=10,
                    VisibilityTimeout=self._visibility_timeout,
                    WaitTimeSeconds=1,
                )
            except Exception as exc:
                logger.warning("cloudtrail_s3.receive_failed", error=str(exc))
                break

            messages = received.get("Messages") or []
            if not messages:
                break

            for message in messages:
                handle = message.get("ReceiptHandle")
                announced = _s3_notifications(message.get("Body") or "")
                if not announced:
                    # An s3:TestEvent, or a message this queue should not be
                    # carrying. Either way it will never become events, so
                    # delete it rather than let it redeliver forever.
                    if handle:
                        self._delete(sqs, handle)
                    continue

                emitted_all = True
                for bucket, key in announced:
                    kind = _classify(key)
                    if kind is None:
                        continue
                    if kind == KIND_FLOW and not self._include_flow_logs:
                        continue
                    try:
                        rows.extend(self._read_object(s3, bucket, key, kind))
                        objects_read += 1
                    except Exception as exc:
                        # One unreadable object must not strand the rest of
                        # the message. Leaving the message undeleted is the
                        # right call: a transient S3 error resolves on
                        # redelivery, and a permanent one is visible as a
                        # message that keeps coming back.
                        emitted_all = False
                        logger.warning("cloudtrail_s3.object_failed", bucket=bucket, key=key, error=str(exc))

                if emitted_all and handle:
                    self._delete(sqs, handle)

                if len(rows) >= budget.max_events_per_poll:
                    truncated = True
                    break

        if truncated:
            # At info, not debug: an operator reading the logs after
            # switching this on needs to see that the queue is deeper than
            # one poll, which is the difference between "catching up" and
            # "stuck".
            logger.info(
                "cloudtrail_s3.budget_reached",
                rows=len(rows),
                objects=objects_read,
                max_events_per_poll=budget.max_events_per_poll,
                detail="remainder stays on the queue for the next poll",
            )

        return [self.normalize(row) for row in self.apply_checkpoint(rows)]

    def _delete(self, sqs: Any, receipt_handle: str) -> None:
        """Acknowledge one notification.

        Failing to delete is not fatal and must not abort the poll: the
        message redelivers, the object is read again, and the checkpoint
        drops the duplicate. Logged at warning because a delete that keeps
        failing is a permissions problem that will otherwise present as a
        queue that never drains.
        """
        try:
            sqs.delete_message(QueueUrl=self._queue_url, ReceiptHandle=receipt_handle)
        except Exception as exc:
            logger.warning("cloudtrail_s3.delete_failed", error=str(exc))

    def _read_object(self, s3: Any, bucket: str, key: str, kind: str) -> list[dict[str, Any]]:
        """Fetch one object and turn it into envelopes."""
        obj = s3.get_object(Bucket=bucket, Key=key)
        body = obj["Body"].read()
        if key.endswith(".gz"):
            body = gzip.decompress(body)
        if len(body) > MAX_OBJECT_BYTES:
            raise ValueError(f"object {key} is {len(body)} bytes uncompressed, over the {MAX_OBJECT_BYTES} cap")

        if kind == KIND_FLOW:
            return self._flow_envelopes(bucket, key, body.decode("utf-8", errors="replace"))
        return self._cloudtrail_envelopes(bucket, key, body)

    def _cloudtrail_envelopes(self, bucket: str, key: str, body: bytes) -> list[dict[str, Any]]:
        payload = json.loads(body.decode("utf-8", errors="replace"))
        records = payload.get("Records") if isinstance(payload, dict) else None
        if not isinstance(records, list):
            return []

        out: list[dict[str, Any]] = []
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                continue
            # CloudTrail stamps `eventCategory` on every record since 2021.
            # Absent means an older trail, which only ever wrote management
            # events — so the default is the safe reading, not a guess.
            is_data = str(record.get("eventCategory") or "Management") == "Data"
            if is_data and not self._include_data_events:
                continue
            out.append(
                {
                    "kind": KIND_DATA if is_data else KIND_MANAGEMENT,
                    "bucket": bucket,
                    "object_key": key,
                    "record_id": f"{key}#{index}",
                    "event_time": _iso(record.get("eventTime")),
                    "record": record,
                }
            )
        return out

    def _flow_envelopes(self, bucket: str, key: str, text: str) -> list[dict[str, Any]]:
        """Parse a VPC flow-log object.

        The first line of an S3-delivered flow log is a header naming the
        fields, which is the one thing the CloudWatch path does not give
        you. Reading it means a v5 custom layout parses correctly instead of
        falling through to the v2 positional reader and silently mapping
        every column one place to the left.
        """
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            return []

        header = lines[0].split()
        has_header = bool(header) and header[0] in {"version", "account-id", "srcaddr", "start"}
        field_names = [name.replace("-", "_") for name in header] if has_header else []
        body_lines = lines[1:] if has_header else lines

        out: list[dict[str, Any]] = []
        for index, line in enumerate(body_lines):
            parts = line.split()
            if field_names and len(parts) == len(field_names):
                parsed: dict[str, Any] = {k: (None if v == "-" else v) for k, v in zip(field_names, parts, strict=True)}
            else:
                parsed = _parse_v2_record(line)
            if not parsed:
                continue
            out.append(
                {
                    "kind": KIND_FLOW,
                    "bucket": bucket,
                    "object_key": key,
                    "record_id": f"{key}#{index}",
                    "event_time": _iso(parsed.get("start") or parsed.get("end")),
                    "record": parsed,
                }
            )
        return out

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        kind = raw.get("kind")
        if kind == KIND_FLOW:
            return self._normalize_flow(raw)
        return self._normalize_cloudtrail(raw)

    def _normalize_cloudtrail(self, envelope: dict[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = envelope.get("record") or {}
        identity = record.get("userIdentity") or {}
        event_name = str(record.get("eventName") or "")
        error_code = record.get("errorCode")
        is_data = envelope.get("kind") == KIND_DATA

        severity = _data_event_severity(event_name, error_code) if is_data else _management_event_severity(event_name, error_code)

        # `sourceIPAddress` carries either a real address or an AWS service
        # principal hostname. Validating rather than substring-matching
        # `amazonaws.com` is the same choice aws_cloudtrail.py made, and for
        # the same reason: `amazonaws.com.attacker.tld` would pass a match.
        src_ip = record.get("sourceIPAddress")
        if isinstance(src_ip, str):
            try:
                ipaddress.ip_address(src_ip.strip())
            except ValueError:
                src_ip = None

        resources = record.get("resources") or []
        resource_arns = [r.get("ARN") for r in resources if isinstance(r, dict) and r.get("ARN")]

        return {
            "source": self.connector_id,
            "category": "cloud",
            "external_id": record.get("eventID") or envelope.get("record_id"),
            "title": event_name or "CloudTrail event",
            "description": (f"{event_name} on {record.get('eventSource', 'aws')}" if event_name else "CloudTrail audit event"),
            "severity": severity,
            "event_name": event_name,
            "event_source": record.get("eventSource"),
            "event_category": "Data" if is_data else "Management",
            "aws_account_id": record.get("recipientAccountId") or identity.get("accountId"),
            "aws_region": record.get("awsRegion") or self._region,
            "cloud_platform": "aws",
            "user_name": identity.get("userName") or identity.get("principalId"),
            "user_arn": identity.get("arn"),
            "user_type": identity.get("type"),
            "src_ip": src_ip,
            "error_code": error_code,
            "user_agent": record.get("userAgent"),
            "resource_arns": resource_arns,
            "delivery": {"bucket": envelope.get("bucket"), "object_key": envelope.get("object_key")},
            "raw_event": record,
            "created_at": envelope.get("event_time"),
        }

    def _normalize_flow(self, envelope: dict[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = envelope.get("record") or {}
        action = str(record.get("action") or "").upper()
        src = record.get("srcaddr") or record.get("src_ip")
        dst = record.get("dstaddr") or record.get("dst_ip")
        return {
            "source": self.connector_id,
            "category": "network",
            "external_id": envelope.get("record_id"),
            "title": f"VPC flow {action or 'record'} {src or '?'} -> {dst or '?'}",
            "description": f"VPC flow log {action or 'record'} on {record.get('interface_id') or record.get('interface-id') or 'eni'}",
            "severity": _record_severity(record),
            "cloud_platform": "aws",
            "aws_account_id": record.get("account_id") or record.get("account-id"),
            "aws_region": self._region,
            "src_ip": src,
            "dst_ip": dst,
            "src_port": record.get("srcport") or record.get("src_port"),
            "dst_port": record.get("dstport") or record.get("dst_port"),
            "protocol": record.get("protocol_name") or record.get("protocol"),
            "action": action or None,
            "delivery": {"bucket": envelope.get("bucket"), "object_key": envelope.get("object_key")},
            "raw_event": record,
            "created_at": envelope.get("event_time"),
        }
