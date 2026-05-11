"""
AWS CloudTrail connector.

Polls a curated allow-list of high-signal CloudTrail events via
``cloudtrail.lookup_events`` and emits normalized AiSOC alerts.

Why an allow-list, not a firehose?

    CloudTrail in a busy production account emits tens of thousands of
    events per minute — mostly noisy describes/lists from AWS services
    themselves. Detections in ``detections/cloud/aws-*.yaml`` only fire
    on a small, well-defined set of mutating or sensitive events (IAM
    grants, trail tampering, public-S3 changes, KMS key destruction,
    cross-account snapshot/AMI sharing, etc). We default-poll exactly
    that set so the ingest pipeline sees the events detections care
    about and nothing else.

    Operators who want a different scope can override via the
    ``event_names`` config field (comma-separated). Setting it to ``*``
    disables the filter and pulls all events in the time window.

API mechanics:

    ``lookup_events`` takes one ``LookupAttributes`` filter at a time,
    so we issue one paginated call per ``EventName`` in the allow-list
    per poll. Each call is capped at 100 results. With ~80 events in
    the default allow-list and the AWS CloudTrail rate limit of 2 TPS
    per region per account, a full poll completes in ~40 seconds in
    the worst case. Most events return zero results in a 5-minute
    window, so steady-state is much faster.

    Each event has a ``CloudTrailEvent`` field that contains the full
    record (``userIdentity``, ``requestParameters``, ``responseElements``,
    ``sourceIPAddress``, ``errorCode``, etc.) as a JSON string. We parse
    that to extract the fields detections actually filter on.

Auth model:

    Same dual-mode pattern as AWS Security Hub and GuardDuty. Either:
      - Leave ``access_key`` / ``secret_key`` blank to use the runtime
        IAM role / instance profile (recommended for production).
      - Or supply a static IAM access-key pair scoped to
        ``cloudtrail:LookupEvents`` read-only permissions.

Severity bucketing:

    CloudTrail doesn't ship intrinsic severity. We label by event
    sensitivity (trail tamper / detection tamper / KMS destruction →
    high, mutating IAM / network / public-S3 → medium, read-only recon
    → low). Events with an ``errorCode`` get bumped up one tier because
    a denied destructive action is often the loudest signal in the
    account.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


# High-severity events: trail/detection tamper, KMS destruction, root
# account use, org-level tampering. These are almost always incidents.
_HIGH_SEVERITY_EVENTS = frozenset(
    {
        "ChangeRootMail",
        "DeleteDetector",
        "DeleteFlowLogs",
        "DeleteTrail",
        "DisableKey",
        "DisableSecurityHub",
        "LeaveOrganization",
        "PutEventSelectors",
        "RemoveAccountFromOrganization",
        "ScheduleKeyDeletion",
        "StopConfigurationRecorder",
        "StopLogging",
        "TransferDomainToAnotherAwsAccount",
        "UpdateTrail",
    }
)


# Read-only / recon events. Useful for sequencing but individually low
# severity.
_LOW_SEVERITY_EVENTS = frozenset(
    {
        "GetAccountAuthorizationDetails",
        "GetAccountSummary",
        "GetObject",
        "GetSecretValue",
        "ListAccessKeys",
    }
)


# Default curated allow-list. Every entry here is referenced by at
# least one detection rule in ``detections/cloud/aws-*.yaml`` or
# ``detections/cloud/cloud-*.yaml`` — keep it tight to keep CloudTrail
# volume manageable. Sorted alphabetically for diff-friendliness.
DEFAULT_EVENT_NAMES: tuple[str, ...] = (
    "AddPermission",
    "AddUserToGroup",
    "AssumeRole",
    "AttachGroupPolicy",
    "AttachRolePolicy",
    "AttachUserPolicy",
    "AuthorizeSecurityGroupIngress",
    "ChangeRootMail",
    "ConsoleLogin",
    "CreateAccessKey",
    "CreateCluster",
    "CreateDBInstance",
    "CreateFargateProfile",
    "CreateFunction",
    "CreateFunctionUrlConfig",
    "CreateLoadBalancer",
    "CreateLoginProfile",
    "CreatePolicy",
    "CreatePolicyVersion",
    "CreateRole",
    "CreateRoute",
    "CreateSAMLProvider",
    "CreateService",
    "CreateUser",
    "CreateVpcPeeringConnection",
    "DeactivateMFADevice",
    "DeleteBucket",
    "DeleteDetector",
    "DeleteFlowLogs",
    "DeletePublicAccessBlock",
    "DeleteTrail",
    "DeleteUserPermissionsBoundary",
    "DisableKey",
    "DisableSecurityHub",
    "DisassociateWebACL",
    "GetAccountAuthorizationDetails",
    "GetAccountSummary",
    "GetSecretValue",
    "ImportKeyPair",
    "LeaveOrganization",
    "ListAccessKeys",
    "ModifyDBInstance",
    "ModifyDBSnapshotAttribute",
    "ModifyImageAttribute",
    "ModifyInstanceAttribute",
    "ModifyLoadBalancerAttributes",
    "ModifySnapshotAttribute",
    "PutBucketAcl",
    "PutBucketLogging",
    "PutBucketPolicy",
    "PutBucketPublicAccessBlock",
    "PutBucketReplication",
    "PutEventSelectors",
    "PutImageScanningConfiguration",
    "PutKeyPolicy",
    "PutObjectLockConfiguration",
    "PutObjectRetention",
    "PutParameter",
    "PutRolePolicy",
    "PutUserPolicy",
    "RegisterTaskDefinition",
    "RemoveAccountFromOrganization",
    "RunInstances",
    "ScheduleKeyDeletion",
    "SetDefaultPolicyVersion",
    "SetQueueAttributes",
    "SetRepositoryPolicy",
    "SetTopicAttributes",
    "StopConfigurationRecorder",
    "StopLogging",
    "TransferDomainToAnotherAwsAccount",
    "UpdateAssumeRolePolicy",
    "UpdateClusterConfig",
    "UpdateDistribution",
    "UpdateFunctionConfiguration",
    "UpdateSAMLProvider",
    "UpdateService",
    "UpdateTrail",
)


def _event_severity(event_name: str, error_code: str | None) -> str:
    """Bucket a CloudTrail event into AiSOC's 4-tier severity ladder.

    Heuristic:
        - HIGH if it's in ``_HIGH_SEVERITY_EVENTS`` (trail tamper,
          KMS destruction, org-level changes, etc).
        - LOW if it's a known read-only recon call.
        - MEDIUM for everything else (the default for mutating events).

    Events that failed (``errorCode`` set) get bumped up one tier on
    the theory that a denied destructive action is often the loudest
    signal we have in the account.
    """
    if event_name in _HIGH_SEVERITY_EVENTS:
        base = "high"
    elif event_name in _LOW_SEVERITY_EVENTS:
        base = "low"
    else:
        base = "medium"

    if not error_code:
        return base

    bump = {"info": "low", "low": "medium", "medium": "high", "high": "high"}
    return bump.get(base, base)


class AWSCloudTrailConnector(BaseConnector):
    connector_id = "aws_cloudtrail"
    connector_name = "AWS CloudTrail"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "AWS CloudTrail audit events. Polls a curated "
                "allow-list of high-signal management events "
                "(IAM grants, trail tampering, public-S3 changes, "
                "KMS key destruction, cross-account sharing) so "
                "detections fire without drowning in read-only noise."
            ),
            docs_url="/docs/connectors/aws-cloudtrail",
            fields=[
                Field("region", "string", "AWS Region", default="us-east-1"),
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
                    "event_names",
                    "string",
                    "Event allow-list (comma-separated)",
                    required=False,
                    default="",
                    help_text=(
                        "Override the default curated event list. "
                        "Leave blank to use AiSOC's curated list, or "
                        "set to '*' to pull every CloudTrail event in "
                        "the window (high volume — not recommended)."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        region: str = "us-east-1",
        access_key: str = "",
        secret_key: str = "",
        event_names: str = "",
    ):
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key
        self._event_names = self._parse_event_names(event_names)

    @staticmethod
    def _parse_event_names(raw: str) -> tuple[str, ...] | None:
        """Resolve the ``event_names`` config field.

        Returns:
            - ``None`` to mean "no filter, pull every event"
              (only when the operator explicitly sets ``*``).
            - A tuple of event names otherwise. Empty / blank input
              falls back to the curated default list.
        """
        if not raw:
            return DEFAULT_EVENT_NAMES
        stripped = raw.strip()
        if stripped == "*":
            return None
        parsed = tuple(sorted({e.strip() for e in stripped.split(",") if e.strip()}))
        return parsed or DEFAULT_EVENT_NAMES

    def _get_client(self):
        try:
            import boto3

            kwargs: dict[str, Any] = {"region_name": self._region}
            if self._access_key and self._secret_key:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            return boto3.client("cloudtrail", **kwargs)
        except ImportError as exc:
            raise RuntimeError("boto3 is required for AWS CloudTrail connector. Install it with: pip install boto3") from exc

    async def test_connection(self) -> dict[str, Any]:
        try:
            client = self._get_client()
            # ``describe_trails`` is the cheapest auth-only call. We don't
            # require the account to have at least one trail because
            # ``lookup_events`` works against the management-events
            # history even when no trail is configured — but if the auth
            # is wrong, this call will surface it.
            client.describe_trails()
            return {
                "success": True,
                "connector": self.connector_id,
                "region": self._region,
            }
        except Exception as exc:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": str(exc),
            }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        try:
            client = self._get_client()
        except RuntimeError as exc:
            logger.warning("cloudtrail.client_init_failed", error=str(exc))
            return []

        start_time = datetime.now(UTC) - timedelta(seconds=since_seconds)
        end_time = datetime.now(UTC)

        all_events: list[dict[str, Any]] = []

        if self._event_names is None:
            # Firehose mode — pull every event in the window. Operators
            # who set ``event_names=*`` explicitly opted in.
            all_events.extend(self._lookup_for_attribute(client, attribute=None, start=start_time, end=end_time))
        else:
            for event_name in self._event_names:
                try:
                    all_events.extend(
                        self._lookup_for_attribute(
                            client,
                            attribute=("EventName", event_name),
                            start=start_time,
                            end=end_time,
                        )
                    )
                except Exception as exc:
                    # Don't let one bad event-name shape kill the poll.
                    logger.warning(
                        "cloudtrail.lookup_failed",
                        event_name=event_name,
                        error=str(exc),
                    )
                    continue

        return [self.normalize(e) for e in all_events]

    @staticmethod
    def _lookup_for_attribute(
        client,
        attribute: tuple[str, str] | None,
        start: datetime,
        end: datetime,
    ) -> list[dict[str, Any]]:
        kwargs: dict[str, Any] = {
            "StartTime": start,
            "EndTime": end,
            "MaxResults": 50,
        }
        if attribute is not None:
            attr_key, attr_value = attribute
            kwargs["LookupAttributes"] = [{"AttributeKey": attr_key, "AttributeValue": attr_value}]

        events: list[dict[str, Any]] = []
        paginator = client.get_paginator("lookup_events")
        # Cap each event-name at 100 hits per poll. If a single event
        # is firing more than 100 times in 5 minutes the operator
        # already has a different problem.
        pages = paginator.paginate(**kwargs, PaginationConfig={"MaxItems": 100, "PageSize": 50})
        for page in pages:
            events.extend(page.get("Events", []))
        return events

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # ``CloudTrailEvent`` is the full record encoded as a JSON
        # string. The lookup envelope only carries the top-level
        # summary fields, so unpack the embedded payload for the rich
        # detection-friendly fields (sourceIPAddress, errorCode,
        # requestParameters, etc.).
        detail: dict[str, Any] = {}
        ct_event = raw.get("CloudTrailEvent")
        if isinstance(ct_event, str):
            try:
                detail = json.loads(ct_event)
            except (TypeError, ValueError):
                detail = {}
        elif isinstance(ct_event, dict):
            detail = ct_event

        user_identity = detail.get("userIdentity") or {}
        event_name = raw.get("EventName") or detail.get("eventName") or ""
        error_code = detail.get("errorCode")
        severity = _event_severity(event_name, error_code)

        event_time = raw.get("EventTime") or detail.get("eventTime")
        # ``EventTime`` from boto3 is a tz-aware datetime; coerce to
        # ISO-8601 so the rest of the pipeline (which is mostly Go and
        # postgres) can read it without type-juggling.
        if isinstance(event_time, datetime):
            event_time = event_time.astimezone(UTC).isoformat()

        src_ip = detail.get("sourceIPAddress") or raw.get("SourceIPAddress")
        # AWS populates ``sourceIPAddress`` with either a real IP (v4/v6) or an
        # AWS service principal hostname like ``cloudtrail.amazonaws.com`` for
        # internal callers. Validate as a real IP and drop anything else —
        # safer than substring-matching ``amazonaws.com``, which would also
        # accept hostile lookalikes such as ``amazonaws.com.attacker.tld``.
        if isinstance(src_ip, str):
            try:
                ipaddress.ip_address(src_ip.strip())
            except ValueError:
                src_ip = None

        return {
            "source": self.connector_id,
            "category": "cloud",
            "external_id": raw.get("EventId") or detail.get("eventID"),
            "title": event_name or "CloudTrail event",
            "description": (f"{event_name} on {detail.get('eventSource', 'aws')}" if event_name else "CloudTrail audit event"),
            "severity": severity,
            "event_name": event_name,
            "event_source": detail.get("eventSource") or raw.get("EventSource"),
            "aws_account_id": detail.get("recipientAccountId") or detail.get("userIdentity", {}).get("accountId"),
            "aws_region": detail.get("awsRegion") or self._region,
            "cloud_platform": "aws",
            "user_name": (raw.get("Username") or user_identity.get("userName") or user_identity.get("principalId")),
            "user_arn": user_identity.get("arn"),
            "user_type": user_identity.get("type"),
            "src_ip": src_ip,
            "error_code": error_code,
            "user_agent": detail.get("userAgent"),
            "raw_event": detail or raw,
            "created_at": event_time,
        }
