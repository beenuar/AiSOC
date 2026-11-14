"""
Unit tests for ``AWSCloudTrailConnector``.

Coverage:
  * schema sanity (region defaulted, optional creds, secret marking,
    ``event_names`` field present and optional)
  * ``_event_severity()`` bucketing (critical / high / medium / low + errorCode bump)
  * ``_parse_event_names()`` tri-state parsing (default / wildcard / list)
  * ``normalize()`` field extraction (CloudTrailEvent JSON unpack,
    src_ip suppression for AWS-internal callers, severity flow)
  * ``test_connection()`` happy path + auth-error soft failure
  * ``fetch_alerts()`` round-trip with mocked boto3 client across
    multiple event-name allow-list entries, plus per-name failure
    isolation, plus firehose mode
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from app.connectors.aws_cloudtrail import (
    DEFAULT_EVENT_NAMES,
    AWSCloudTrailConnector,
    _event_severity,
)
from app.connectors.base import Capability

# ===========================================================================
# Schema
# ===========================================================================


def test_cloudtrail_schema_defaults_region_and_marks_secret():
    schema = AWSCloudTrailConnector.schema()
    field_map = {f.name: f for f in schema.fields}

    assert field_map["region"].default == "us-east-1"
    # IAM role fallback — both keys must be optional so the operator
    # can just leave them blank when running on EC2 / EKS / ECS.
    assert field_map["access_key"].required is False
    assert field_map["secret_key"].required is False
    assert field_map["secret_key"].type == "secret"
    # Allow-list override field exists and is optional (default empty
    # → use curated list).
    assert field_map["event_names"].required is False


def test_cloudtrail_schema_declares_pull_alerts():
    assert AWSCloudTrailConnector.capabilities() == (Capability.PULL_ALERTS,)


def test_cloudtrail_schema_category_is_cloud():
    assert AWSCloudTrailConnector.schema().category == "cloud"


# ===========================================================================
# _parse_event_names
# ===========================================================================


def test_parse_event_names_blank_uses_curated_default():
    assert AWSCloudTrailConnector._parse_event_names("") == DEFAULT_EVENT_NAMES
    # Whitespace-only input must also fall back to the curated list,
    # not collapse to an empty tuple (which would stop polling).
    parsed = AWSCloudTrailConnector._parse_event_names("   ")
    assert parsed == DEFAULT_EVENT_NAMES


def test_parse_event_names_wildcard_disables_filter():
    # ``None`` is the firehose sentinel — fetch_alerts will skip the
    # per-name iteration and pull every event in the window.
    assert AWSCloudTrailConnector._parse_event_names("*") is None


def test_parse_event_names_explicit_list_overrides_default():
    parsed = AWSCloudTrailConnector._parse_event_names(" ConsoleLogin , CreateAccessKey , PutBucketPolicy ")
    # Whitespace tolerant + de-duplicated + sorted (deterministic
    # iteration order across runs makes test_fetch_alerts call_count
    # predictable).
    assert parsed == ("ConsoleLogin", "CreateAccessKey", "PutBucketPolicy")


def test_parse_event_names_strips_empty_segments():
    parsed = AWSCloudTrailConnector._parse_event_names("ConsoleLogin,,CreateAccessKey,")
    assert parsed == ("ConsoleLogin", "CreateAccessKey")


# ===========================================================================
# _event_severity
# ===========================================================================


@pytest.mark.parametrize(
    "event_name,expected",
    [
        # Visibility kill switches / irreversible takeover → critical (P1)
        ("DeleteTrail", "critical"),
        ("StopLogging", "critical"),
        ("DisableSecurityHub", "critical"),
        ("ScheduleKeyDeletion", "critical"),
        # Trail/detection tamper, root mail change, org-level changes → high
        ("UpdateTrail", "high"),
        ("DeleteFlowLogs", "high"),
        ("ChangeRootMail", "high"),
        # Mutating but not catastrophic → medium
        ("CreateAccessKey", "medium"),
        ("AttachUserPolicy", "medium"),
        ("PutBucketPolicy", "medium"),
        ("AuthorizeSecurityGroupIngress", "medium"),
        ("ConsoleLogin", "medium"),
        # Read-only recon → low
        ("ListAccessKeys", "low"),
        ("GetSecretValue", "low"),
    ],
)
def test_event_severity_buckets(event_name, expected):
    assert _event_severity(event_name, error_code=None) == expected


def test_event_severity_bumps_on_error_code():
    # A denied destructive action is often the loudest signal we have
    # — bump the severity one tier when ``errorCode`` is present.
    assert _event_severity("CreateAccessKey", "AccessDenied") == "high"
    assert _event_severity("ListAccessKeys", "AccessDenied") == "medium"
    # Already-high stays high (no overflow tier on the high baseline).
    assert _event_severity("UpdateTrail", "AccessDenied") == "high"
    # Already-critical stays critical — no escalation past P1.
    assert _event_severity("DeleteTrail", "AccessDenied") == "critical"


def test_event_severity_unknown_event_defaults_to_medium():
    # Any mutating event we haven't classified explicitly gets
    # ``medium`` so it stays visible in the inbox without being noisy.
    assert _event_severity("SomeFuturePrivilegedCall", None) == "medium"


# ===========================================================================
# normalize
# ===========================================================================


def _wrap_event(detail: dict, event_id: str = "evt-1") -> dict:
    """CloudTrail's lookup_events envelope: top-level summary fields
    plus the full record encoded as a JSON string under
    ``CloudTrailEvent``. Match that shape exactly so normalize() is
    exercised against the real wire format."""
    return {
        "EventId": event_id,
        "EventName": detail.get("eventName"),
        "EventTime": datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
        "Username": (detail.get("userIdentity") or {}).get("userName"),
        "EventSource": detail.get("eventSource"),
        "CloudTrailEvent": json.dumps(detail),
    }


def test_normalize_console_login_extracts_user_and_ip():
    connector = AWSCloudTrailConnector(region="us-east-1")
    detail = {
        "eventName": "ConsoleLogin",
        "eventSource": "signin.amazonaws.com",
        "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "sourceIPAddress": "203.0.113.5",
        "userAgent": "Mozilla/5.0",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "alice",
            "arn": "arn:aws:iam::123456789012:user/alice",
            "accountId": "123456789012",
        },
        "responseElements": {"ConsoleLogin": "Success"},
    }
    raw = _wrap_event(detail, event_id="login-1")

    out = connector.normalize(raw)

    assert out["source"] == "aws_cloudtrail"
    assert out["category"] == "cloud"
    assert out["external_id"] == "login-1"
    assert out["title"] == "ConsoleLogin"
    assert out["event_name"] == "ConsoleLogin"
    assert out["event_source"] == "signin.amazonaws.com"
    assert out["aws_account_id"] == "123456789012"
    assert out["aws_region"] == "us-east-1"
    assert out["cloud_platform"] == "aws"
    assert out["user_name"] == "alice"
    assert out["user_arn"] == "arn:aws:iam::123456789012:user/alice"
    assert out["user_type"] == "IAMUser"
    assert out["src_ip"] == "203.0.113.5"
    # Successful ConsoleLogin (no errorCode) → medium
    assert out["severity"] == "medium"
    # The unpacked detail should land on raw_event so detection rules
    # can branch on requestParameters / responseElements.
    assert out["raw_event"]["eventName"] == "ConsoleLogin"


def test_normalize_failed_destructive_call_bumps_severity_to_high():
    connector = AWSCloudTrailConnector(region="us-east-1")
    detail = {
        "eventName": "CreateAccessKey",
        "eventSource": "iam.amazonaws.com",
        "awsRegion": "us-east-1",
        "errorCode": "AccessDenied",
        "errorMessage": "User is not authorized",
        "sourceIPAddress": "198.51.100.7",
        "userIdentity": {"type": "IAMUser", "userName": "bob"},
    }
    raw = _wrap_event(detail, event_id="iam-fail-1")

    out = connector.normalize(raw)

    # CreateAccessKey is medium baseline; errorCode bumps to high.
    assert out["severity"] == "high"
    assert out["error_code"] == "AccessDenied"


def test_normalize_suppresses_aws_internal_caller_ip():
    # CloudTrail records "AWS Internal" or service-domain values like
    # "cloudtrail.amazonaws.com" in sourceIPAddress for AWS-originated
    # calls. Those are not actionable IPs — surfacing them as src_ip
    # would poison detections like "block this IP".
    connector = AWSCloudTrailConnector(region="us-east-1")
    detail = {
        "eventName": "PutEventSelectors",
        "eventSource": "cloudtrail.amazonaws.com",
        "awsRegion": "us-east-1",
        "sourceIPAddress": "cloudtrail.amazonaws.com",
        "userIdentity": {"type": "AWSService"},
    }
    raw = _wrap_event(detail, event_id="svc-1")

    out = connector.normalize(raw)
    assert out["src_ip"] is None


def test_normalize_handles_missing_cloudtrail_event_payload():
    # If lookup_events returns a stripped envelope (rare, but happens
    # under throttling / partial responses), normalize must still
    # produce a usable alert from the top-level fields.
    connector = AWSCloudTrailConnector(region="us-east-1")
    raw = {
        "EventId": "stripped-1",
        "EventName": "DeleteTrail",
        "EventSource": "cloudtrail.amazonaws.com",
        "EventTime": datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
    }

    out = connector.normalize(raw)
    assert out["external_id"] == "stripped-1"
    assert out["event_name"] == "DeleteTrail"
    # DeleteTrail silences the audit trail itself — classified as P1 critical.
    assert out["severity"] == "critical"
    # Fallback region from the connector instance config when the
    # detail payload is absent.
    assert out["aws_region"] == "us-east-1"


def test_normalize_handles_malformed_cloudtrail_event_json():
    # A malformed JSON string in CloudTrailEvent must not crash the
    # poll loop — degrade to top-level fields only.
    connector = AWSCloudTrailConnector(region="us-east-1")
    raw = {
        "EventId": "bad-json-1",
        "EventName": "ConsoleLogin",
        "EventTime": datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
        "CloudTrailEvent": "{not valid json",
    }
    out = connector.normalize(raw)
    assert out["external_id"] == "bad-json-1"
    assert out["event_name"] == "ConsoleLogin"
    assert out["src_ip"] is None


# ===========================================================================
# test_connection
# ===========================================================================


@pytest.mark.asyncio
async def test_test_connection_happy_path_reports_region():
    connector = AWSCloudTrailConnector(region="eu-west-1")
    mock_client = MagicMock()
    mock_client.describe_trails.return_value = {"trailList": []}
    with patch.object(connector, "_get_client", return_value=mock_client):
        result = await connector.test_connection()
    assert result["success"] is True
    assert result["region"] == "eu-west-1"
    assert result["connector"] == "aws_cloudtrail"


@pytest.mark.asyncio
async def test_test_connection_swallows_boto_errors():
    # AccessDenied / throttling on describe_trails must surface as
    # success=False rather than crashing the scheduler poll cycle.
    connector = AWSCloudTrailConnector(region="us-east-1")
    mock_client = MagicMock()
    mock_client.describe_trails.side_effect = RuntimeError("AccessDenied")
    with patch.object(connector, "_get_client", return_value=mock_client):
        result = await connector.test_connection()
    assert result["success"] is False
    assert "AccessDenied" in result["error"]


# ===========================================================================
# fetch_alerts
# ===========================================================================


@pytest.mark.asyncio
async def test_fetch_alerts_iterates_allow_list_one_call_per_event_name():
    """Custom 3-event allow-list → exactly 3 paginator calls,
    one per EventName attribute."""
    connector = AWSCloudTrailConnector(
        region="us-east-1",
        event_names="ConsoleLogin,CreateAccessKey,DeleteTrail",
    )
    mock_client = MagicMock()

    # One paginator instance per get_paginator call; configure
    # paginate() to return one event per name so we can verify each
    # ran.
    def make_paginator(events):
        p = MagicMock()
        p.paginate.return_value = iter([{"Events": events}])
        return p

    mock_client.get_paginator.side_effect = [
        make_paginator(
            [
                {
                    "EventId": "console-1",
                    "EventName": "ConsoleLogin",
                    "EventTime": datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
                    "CloudTrailEvent": json.dumps({"eventName": "ConsoleLogin"}),
                }
            ]
        ),
        make_paginator(
            [
                {
                    "EventId": "key-1",
                    "EventName": "CreateAccessKey",
                    "EventTime": datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
                    "CloudTrailEvent": json.dumps({"eventName": "CreateAccessKey"}),
                }
            ]
        ),
        make_paginator(
            [
                {
                    "EventId": "trail-1",
                    "EventName": "DeleteTrail",
                    "EventTime": datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
                    "CloudTrailEvent": json.dumps({"eventName": "DeleteTrail"}),
                }
            ]
        ),
    ]

    with patch.object(connector, "_get_client", return_value=mock_client):
        results = await connector.fetch_alerts(since_seconds=300)

    # One paginator per event-name in the allow-list.
    assert mock_client.get_paginator.call_count == 3
    assert {r["external_id"] for r in results} == {
        "console-1",
        "key-1",
        "trail-1",
    }
    # Severity flowed through end-to-end.
    severities = {r["external_id"]: r["severity"] for r in results}
    assert severities["console-1"] == "medium"
    assert severities["key-1"] == "medium"
    # DeleteTrail is a visibility kill switch — P1 critical.
    assert severities["trail-1"] == "critical"


@pytest.mark.asyncio
async def test_fetch_alerts_per_event_name_failure_does_not_break_others():
    """One bad EventName lookup must not halt the entire poll."""
    connector = AWSCloudTrailConnector(
        region="us-east-1",
        event_names="ConsoleLogin,CreateAccessKey",
    )
    mock_client = MagicMock()

    bad_paginator = MagicMock()
    bad_paginator.paginate.side_effect = RuntimeError("ThrottlingException")
    ok_paginator = MagicMock()
    ok_paginator.paginate.return_value = iter(
        [
            {
                "Events": [
                    {
                        "EventId": "ok-1",
                        "EventName": "ConsoleLogin",
                        "EventTime": datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
                        "CloudTrailEvent": json.dumps({"eventName": "ConsoleLogin"}),
                    }
                ]
            }
        ]
    )

    # Allow-list is sorted alphabetically: ConsoleLogin first, then
    # CreateAccessKey. Make ConsoleLogin succeed, CreateAccessKey blow up.
    mock_client.get_paginator.side_effect = [ok_paginator, bad_paginator]

    with patch.object(connector, "_get_client", return_value=mock_client):
        results = await connector.fetch_alerts()

    # We still got the surviving event-name's hit.
    assert {r["external_id"] for r in results} == {"ok-1"}


@pytest.mark.asyncio
async def test_fetch_alerts_firehose_mode_skips_event_name_filter():
    """``event_names=*`` → one paginator call, no LookupAttributes."""
    connector = AWSCloudTrailConnector(region="us-east-1", event_names="*")
    mock_client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = iter(
        [
            {
                "Events": [
                    {
                        "EventId": "any-1",
                        "EventName": "DescribeInstances",
                        "EventTime": datetime(2026, 5, 10, 12, 0, 0, tzinfo=UTC),
                        "CloudTrailEvent": json.dumps({"eventName": "DescribeInstances"}),
                    }
                ]
            }
        ]
    )
    mock_client.get_paginator.return_value = paginator

    with patch.object(connector, "_get_client", return_value=mock_client):
        results = await connector.fetch_alerts()

    # Exactly one paginator call regardless of allow-list size.
    assert mock_client.get_paginator.call_count == 1
    # Verify LookupAttributes was NOT supplied (firehose, not filtered).
    paginate_kwargs = paginator.paginate.call_args.kwargs
    assert "LookupAttributes" not in paginate_kwargs
    assert {r["external_id"] for r in results} == {"any-1"}


@pytest.mark.asyncio
async def test_fetch_alerts_client_init_failure_returns_empty_not_raise():
    # If boto3 isn't importable, fetch_alerts must collapse to [] so
    # the scheduler's per-instance poll doesn't crash.
    connector = AWSCloudTrailConnector(region="us-east-1")
    with patch.object(
        connector,
        "_get_client",
        side_effect=RuntimeError("boto3 is required"),
    ):
        result = await connector.fetch_alerts()
    assert result == []
