"""
AWS VPC Flow Logs connector.

Pulls VPC Flow Log records from a CloudWatch Logs log group via
``logs.filter_log_events`` and emits normalised AiSOC alerts.

Why CloudWatch Logs and not S3?

    AWS lets you publish flow logs to either CloudWatch Logs or S3. The
    CloudWatch Logs path is the only one with a real-time, queryable
    API surface — ``filter_log_events`` supports a CloudWatch Logs
    filter pattern, returns events as JSON envelopes, and tracks a
    cursor we can resume from. The S3 path is cheaper at petabyte
    scale but requires a separate parse/dedupe layer per object and
    has 5–10 minute publish latency. For an alert-pipeline connector
    we want the lower-latency CloudWatch path.

Why default to ``?REJECT``?

    Even a tiny VPC publishes hundreds of thousands of flow records
    per minute. The vast majority are uninteresting ACCEPTed traffic
    on long-lived TCP sessions. Detection content in
    ``detections/network/`` and ``detections/cloud/`` only fires on
    rejected / unusual flows, port scans, or specific destinations.
    Defaulting the CloudWatch filter pattern to ``?REJECT`` keeps the
    poll volume sane while still surfacing every blocked flow. Operators
    can override via the ``filter_pattern`` field.

Flow log format support:

    AWS supports two field layouts:

        v2 (default) — 14 space-separated fields, version through
                       log-status. Documented at:
                       https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-logs-fields

        v5 (custom)  — operator-defined field set. The first record
                       in the log group can include a ``${header}``
                       line, but more commonly operators publish
                       custom fields in JSON or in a fixed order
                       agreed in their AWS configuration. We support
                       v2 natively and pass v5 through as-is on
                       ``raw_event`` so downstream detection content
                       can match on the JSON.

Auth model:
    Same dual-mode pattern as the other AWS connectors. Either:
      - Leave ``access_key`` / ``secret_key`` blank to use the runtime
        IAM role / instance profile (recommended for production).
      - Or supply a static IAM access-key pair scoped to read-only
        ``logs:FilterLogEvents`` and ``logs:DescribeLogGroups`` on
        the target log group.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


# v2 (default) field order. From AWS docs:
# https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html#flow-logs-fields
_V2_FIELDS: tuple[str, ...] = (
    "version",
    "account_id",
    "interface_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log_status",
)


# IANA protocol numbers we surface as a friendly name. Anything not in
# this table flows through as the raw integer so detections can still
# match on it.
_PROTOCOL_NAMES: dict[str, str] = {
    "1": "icmp",
    "6": "tcp",
    "17": "udp",
    "47": "gre",
    "50": "esp",
    "51": "ah",
    "58": "icmpv6",
}


def _parse_v2_record(message: str) -> dict[str, Any]:
    """Parse a single space-separated v2 VPC flow log line.

    Returns an empty dict for the header line (``version account-id ...``)
    or for malformed lines. We deliberately *don't* raise — flow log
    poll volume is high enough that a single garbled record should not
    abort the whole batch.
    """
    if not message or not message.strip():
        return {}

    parts = message.strip().split()
    if len(parts) != len(_V2_FIELDS):
        # Wrong column count — either a v5 custom layout or a header
        # line. Hand back empty so the caller can fall through to the
        # generic JSON pass-through path.
        return {}

    rec: dict[str, Any] = dict(zip(_V2_FIELDS, parts, strict=False))

    # AWS uses literal ``-`` for "no value" fields. Normalise to None.
    for k, v in list(rec.items()):
        if v == "-":
            rec[k] = None

    # Friendly protocol name where we know it.
    proto_raw = rec.get("protocol")
    if proto_raw:
        rec["protocol_name"] = _PROTOCOL_NAMES.get(str(proto_raw), str(proto_raw))

    return rec


def _record_severity(parsed: dict[str, Any]) -> str:
    """Pick a severity tier for a flow log record.

    Heuristic:
        - ``REJECT`` action -> medium (blocked flows are the loud
          signal we publish this connector for in the first place).
        - ``ACCEPT`` action -> low (operator opted in to ACCEPTs by
          changing the filter, so they want them, but they're not
          inherently alert-worthy).
        - log-status of ``NODATA`` / ``SKIPDATA`` -> info (collection
          gaps, useful for the pipeline-health channel).
        - Anything else -> low.
    """
    action = (parsed.get("action") or "").upper()
    log_status = (parsed.get("log_status") or "").upper()

    if log_status in {"NODATA", "SKIPDATA"}:
        return "info"
    if action == "REJECT":
        return "medium"
    if action == "ACCEPT":
        return "low"
    return "low"


class AWSVPCFlowLogsConnector(BaseConnector):
    connector_id = "aws_vpc_flow"
    connector_name = "AWS VPC Flow Logs"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "AWS VPC Flow Logs streamed from CloudWatch Logs. "
                "Defaults to surfacing rejected flows only so the "
                "ingest pipeline gets the actionable network-deny "
                "signal without drowning in steady-state ACCEPT noise."
            ),
            docs_url="/docs/connectors/aws-vpc-flow",
            fields=[
                Field("region", "string", "AWS Region", default="us-east-1"),
                Field(
                    "log_group_name",
                    "string",
                    "CloudWatch Logs log group",
                    required=True,
                    help_text=(
                        "The CloudWatch Logs log group your VPC Flow "
                        "Logs publish to (e.g. ``/aws/vpc/flowlogs``). "
                        "Configure flow logs to publish to CloudWatch "
                        "Logs in the VPC console first if you haven't."
                    ),
                ),
                Field(
                    "filter_pattern",
                    "string",
                    "CloudWatch Logs filter pattern",
                    required=False,
                    default="?REJECT",
                    help_text=(
                        "CloudWatch Logs filter pattern applied "
                        "server-side. Default ``?REJECT`` surfaces "
                        "blocked flows only. Set to empty string to "
                        "ingest every flow record (high volume warning)."
                    ),
                ),
                Field(
                    "flow_log_version",
                    "string",
                    "Flow log version (v2 or v5)",
                    required=False,
                    default="v2",
                    help_text=(
                        "AiSOC parses v2 (the AWS default 14-field "
                        "layout) natively. For v5 custom layouts the "
                        "raw record passes through on raw_event so "
                        "detection content can match on the JSON."
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
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Flow log records are passive logs, not curated alerts. We tag
        # both PULL_LOGS (true to the source) and PULL_ALERTS (since
        # downstream detections produce alerts from these records and
        # the agent layer treats them in the alert pipeline).
        return (Capability.PULL_LOGS, Capability.PULL_ALERTS)

    def __init__(
        self,
        region: str = "us-east-1",
        log_group_name: str = "",
        filter_pattern: str = "?REJECT",
        flow_log_version: str = "v2",
        access_key: str = "",
        secret_key: str = "",
    ):
        self._region = region
        self._log_group_name = log_group_name
        # Empty / whitespace = no server-side filter. Don't accidentally
        # send the literal string ``""`` to CloudWatch as a filter.
        self._filter_pattern = (filter_pattern or "").strip()
        self._flow_log_version = (flow_log_version or "v2").strip().lower()
        self._access_key = access_key
        self._secret_key = secret_key

    def _get_client(self):
        try:
            import boto3

            kwargs: dict[str, Any] = {"region_name": self._region}
            if self._access_key and self._secret_key:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            return boto3.client("logs", **kwargs)
        except ImportError as exc:
            raise RuntimeError("boto3 is required for AWS VPC Flow Logs connector. Install it with: pip install boto3") from exc

    async def test_connection(self) -> dict[str, Any]:
        if not self._log_group_name:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "log_group_name is required",
            }
        try:
            client = self._get_client()
            # ``describe_log_groups`` with a prefix is the cheapest way
            # to verify both auth and that the log group actually
            # exists. We then check the result set rather than relying
            # on an exception, because the API returns 200 + empty list
            # for "no match".
            resp = client.describe_log_groups(logGroupNamePrefix=self._log_group_name, limit=5)
            groups = resp.get("logGroups", []) or []
            match = any(g.get("logGroupName") == self._log_group_name for g in groups)
            if not match:
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": (
                        f"log group {self._log_group_name} not found in "
                        f"region {self._region}. Verify the name and that "
                        "the credentials can describe log groups."
                    ),
                }
            return {
                "success": True,
                "connector": self.connector_id,
                "region": self._region,
                "log_group": self._log_group_name,
            }
        except Exception as exc:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": str(exc),
            }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._log_group_name:
            logger.warning(
                "vpc_flow.log_group_missing",
                connector=self.connector_id,
            )
            return []

        try:
            client = self._get_client()
        except RuntimeError as exc:
            logger.warning("vpc_flow.client_init_failed", error=str(exc))
            return []

        # CloudWatch Logs takes start/end as epoch milliseconds.
        end_ms = int(datetime.now(UTC).timestamp() * 1000)
        start_ms = end_ms - (since_seconds * 1000)

        kwargs: dict[str, Any] = {
            "logGroupName": self._log_group_name,
            "startTime": start_ms,
            "endTime": end_ms,
            # 1k events / page is the API max. Cap total volume at 5k
            # per poll so a single misconfigured filter can't wedge
            # the scheduler.
            "limit": 1000,
        }
        if self._filter_pattern:
            kwargs["filterPattern"] = self._filter_pattern

        events: list[dict[str, Any]] = []
        try:
            paginator = client.get_paginator("filter_log_events")
            pages = paginator.paginate(**kwargs, PaginationConfig={"MaxItems": 5000, "PageSize": 1000})
            for page in pages:
                events.extend(page.get("events", []))
        except Exception as exc:
            logger.warning(
                "vpc_flow.filter_log_events_failed",
                log_group=self._log_group_name,
                error=str(exc),
            )
            return []

        return [self.normalize(e) for e in events]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map a CloudWatch Logs envelope to AiSOC's normalised shape.

        ``raw`` is the envelope from ``filter_log_events``:
            {
              "logStreamName": "...",
              "timestamp": 1731000000000,
              "message": "<the actual flow log line>",
              "ingestionTime": 1731000000123,
              "eventId": "..."
            }

        We try the v2 fixed-column parser first, fall back to JSON, and
        finally fall back to a passthrough so detection content always
        sees the original message body.
        """
        message = raw.get("message", "") or ""
        parsed: dict[str, Any] = {}
        record_format = "unknown"

        # Path 1: v2 fixed-column. Almost all default flow log
        # configurations land here.
        if self._flow_log_version == "v2":
            parsed = _parse_v2_record(message)
            if parsed:
                record_format = "v2"

        # Path 2: JSON line. v5 layouts can be configured to publish
        # JSON, and some operators wrap their flow logs in their own
        # structured envelope.
        if not parsed and message.strip().startswith("{"):
            try:
                parsed = json.loads(message)
                record_format = "json"
            except (TypeError, ValueError):
                parsed = {}

        severity = _record_severity(parsed) if parsed else "info"
        action = parsed.get("action") if parsed else None

        # Build a human-readable title even when parse failed, because
        # operators looking at the inbox shouldn't see a blank row.
        if parsed and parsed.get("src_ip") and parsed.get("dst_ip"):
            title = (
                f"VPC flow {action or 'event'}: "
                f"{parsed.get('src_ip')}:{parsed.get('src_port', '?')} -> "
                f"{parsed.get('dst_ip')}:{parsed.get('dst_port', '?')}"
            )
        elif action:
            title = f"VPC flow {action}"
        else:
            title = "VPC flow log event"

        # CloudWatch envelope timestamp is epoch milliseconds. Coerce
        # to ISO-8601 so the rest of the pipeline (Go + postgres) can
        # read it directly.
        ts_ms = raw.get("timestamp")
        created_at: str | None = None
        if isinstance(ts_ms, int | float):
            created_at = datetime.fromtimestamp(ts_ms / 1000.0, tz=UTC).isoformat()

        return {
            "source": self.connector_id,
            "category": "network",
            "external_id": raw.get("eventId"),
            "title": title,
            "description": message,
            "severity": severity,
            "src_ip": parsed.get("src_ip") if parsed else None,
            "dst_ip": parsed.get("dst_ip") if parsed else None,
            "src_port": parsed.get("src_port") if parsed else None,
            "dst_port": parsed.get("dst_port") if parsed else None,
            "protocol": parsed.get("protocol_name") or (parsed.get("protocol") if parsed else None),
            "action": action,
            "aws_account_id": parsed.get("account_id") if parsed else None,
            "aws_region": self._region,
            "cloud_platform": "aws",
            "cloud_resource": parsed.get("interface_id") if parsed else None,
            "log_stream": raw.get("logStreamName"),
            "log_status": parsed.get("log_status") if parsed else None,
            "record_format": record_format,
            "raw_event": parsed or {"message": message},
            "created_at": created_at,
        }
