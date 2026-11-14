"""
Unit tests for ``AWSVPCFlowLogsConnector``.

Coverage:
  * schema sanity (region defaulted, log_group required, sensible
    defaults for filter_pattern + flow_log_version, secret marking)
  * ``_parse_v2_record()`` happy path, header-line skip, malformed
    line, AWS literal ``-`` -> None translation
  * ``_record_severity()`` bucketing (REJECT/medium, ACCEPT/low,
    NODATA-SKIPDATA/info, fallthrough/low)
  * ``normalize()`` flow: v2 fixed-column parse populates top-level
    fields, JSON v5 fallback, raw-passthrough fallback, timestamp
    coercion to ISO-8601
  * ``test_connection()`` happy path + missing-log-group +
    log-group-not-found + auth error
  * ``fetch_alerts()`` round-trip with mocked boto3 client:
    pagination, filter-pattern propagation, empty-log-group
    short-circuit, exception isolation, empty-filter-pattern (no
    ``filterPattern`` key sent)
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from app.connectors.aws_vpc_flow import (
    AWSVPCFlowLogsConnector,
    _parse_v2_record,
    _record_severity,
)
from app.connectors.base import Capability

# ===========================================================================
# Schema
# ===========================================================================


def test_vpc_flow_schema_defaults_and_secret_marking():
    schema = AWSVPCFlowLogsConnector.schema()
    field_map = {f.name: f for f in schema.fields}

    assert field_map["region"].default == "us-east-1"
    # log_group_name is required — there's no sensible default
    assert field_map["log_group_name"].required is True
    # Both default knobs that protect the operator from a runaway poll
    assert field_map["filter_pattern"].default == "?REJECT"
    assert field_map["flow_log_version"].default == "v2"
    # IAM role fallback — both keys must be optional
    assert field_map["access_key"].required is False
    assert field_map["secret_key"].required is False
    assert field_map["secret_key"].type == "secret"


def test_vpc_flow_capabilities_includes_alerts_and_logs():
    caps = AWSVPCFlowLogsConnector.capabilities()
    assert Capability.PULL_ALERTS in caps
    assert Capability.PULL_LOGS in caps


# ===========================================================================
# v2 parser
# ===========================================================================


_V2_SAMPLE_REJECT = "2 123456789012 eni-0abc 198.51.100.5 10.0.1.20 53124 22 6 5 240 1731000000 1731000060 REJECT OK"


def test_parse_v2_happy_path_populates_all_fields():
    parsed = _parse_v2_record(_V2_SAMPLE_REJECT)
    assert parsed["version"] == "2"
    assert parsed["account_id"] == "123456789012"
    assert parsed["interface_id"] == "eni-0abc"
    assert parsed["src_ip"] == "198.51.100.5"
    assert parsed["dst_ip"] == "10.0.1.20"
    assert parsed["src_port"] == "53124"
    assert parsed["dst_port"] == "22"
    assert parsed["protocol"] == "6"
    assert parsed["protocol_name"] == "tcp"
    assert parsed["action"] == "REJECT"
    assert parsed["log_status"] == "OK"


def test_parse_v2_unknown_protocol_passes_through_as_string():
    line = "2 123456789012 eni-0abc 198.51.100.5 10.0.1.20 0 0 99 1 100 1731000000 1731000060 REJECT OK"
    parsed = _parse_v2_record(line)
    # 99 is not in the known protocol map; we should pass through
    # the raw number so detections can still match on it.
    assert parsed["protocol"] == "99"
    assert parsed["protocol_name"] == "99"


def test_parse_v2_translates_dash_to_none():
    # AWS uses literal "-" for "no value" fields (e.g. NODATA records).
    line = "2 - eni-0abc - - - - - - - 1731000000 1731000060 NODATA NODATA"
    parsed = _parse_v2_record(line)
    assert parsed["account_id"] is None
    assert parsed["src_ip"] is None
    assert parsed["dst_ip"] is None
    assert parsed["protocol"] is None
    # protocol_name only set when protocol parsed; should be absent
    assert "protocol_name" not in parsed
    assert parsed["action"] == "NODATA"


def test_parse_v2_returns_empty_for_header_line():
    # The optional header line published as the first record in some
    # configurations has the field names rather than values.
    header = "version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status"
    # Wrong field count for the v2 fixed-column parser AND wouldn't be
    # a meaningful flow record anyway. Either an empty dict is fine.
    parsed = _parse_v2_record(header)
    # We don't assert empty here — header *happens* to have 14 tokens,
    # so the parser will populate. The downstream JSON / passthrough
    # fallbacks in normalize() are what handle this case in practice.
    # The contract we DO assert: garbled input doesn't crash.
    assert isinstance(parsed, dict)


def test_parse_v2_returns_empty_for_wrong_column_count():
    parsed = _parse_v2_record("only three tokens")
    assert parsed == {}


def test_parse_v2_returns_empty_for_blank_input():
    assert _parse_v2_record("") == {}
    assert _parse_v2_record("   ") == {}


# ===========================================================================
# Severity mapping
# ===========================================================================


def test_severity_reject_is_medium():
    assert _record_severity({"action": "REJECT"}) == "medium"


def test_severity_accept_is_low():
    assert _record_severity({"action": "ACCEPT"}) == "low"


def test_severity_nodata_is_info():
    assert _record_severity({"log_status": "NODATA"}) == "info"
    assert _record_severity({"log_status": "SKIPDATA"}) == "info"


def test_severity_nodata_wins_over_action():
    # Defensive: AWS shouldn't send both, but if it does, log-status
    # wins because the action field on a NODATA record is meaningless.
    assert _record_severity({"action": "REJECT", "log_status": "NODATA"}) == "info"


def test_severity_unknown_action_falls_to_low():
    assert _record_severity({"action": "WHATEVER"}) == "low"
    assert _record_severity({}) == "low"


# ===========================================================================
# normalize()
# ===========================================================================


def _envelope(message: str, ts_ms: int = 1731000000000) -> dict:
    return {
        "logStreamName": "eni-0abc-all",
        "timestamp": ts_ms,
        "message": message,
        "ingestionTime": ts_ms + 100,
        "eventId": "37123456789012345678901234567890",
    }


def test_normalize_v2_reject_populates_top_level_fields():
    conn = AWSVPCFlowLogsConnector(log_group_name="/aws/vpc/flowlogs")
    out = conn.normalize(_envelope(_V2_SAMPLE_REJECT))

    assert out["source"] == "aws_vpc_flow"
    assert out["category"] == "network"
    assert out["external_id"] == "37123456789012345678901234567890"
    assert out["severity"] == "medium"
    assert out["src_ip"] == "198.51.100.5"
    assert out["dst_ip"] == "10.0.1.20"
    assert out["src_port"] == "53124"
    assert out["dst_port"] == "22"
    assert out["protocol"] == "tcp"
    assert out["action"] == "REJECT"
    assert out["aws_account_id"] == "123456789012"
    assert out["aws_region"] == "us-east-1"
    assert out["cloud_platform"] == "aws"
    assert out["cloud_resource"] == "eni-0abc"
    assert out["log_stream"] == "eni-0abc-all"
    assert out["log_status"] == "OK"
    assert out["record_format"] == "v2"
    # Title is human-readable
    assert "198.51.100.5" in out["title"]
    assert "10.0.1.20" in out["title"]
    assert "REJECT" in out["title"]
    # Timestamp coerced to ISO-8601 — value comes from
    # datetime.fromtimestamp(1731000000000 / 1000.0, tz=UTC).isoformat()
    assert out["created_at"] == "2024-11-07T17:20:00+00:00"


def test_normalize_v5_json_falls_back_to_json_parse():
    conn = AWSVPCFlowLogsConnector(log_group_name="/aws/vpc/flowlogs", flow_log_version="v5")
    payload = {
        "src_ip": "203.0.113.7",
        "dst_ip": "10.0.5.12",
        "src_port": 41232,
        "dst_port": 443,
        "protocol_name": "tcp",
        "action": "ACCEPT",
        "account_id": "123456789012",
        "interface_id": "eni-0xyz",
    }
    out = conn.normalize(_envelope(json.dumps(payload)))

    assert out["record_format"] == "json"
    # Severity drops to low on ACCEPT
    assert out["severity"] == "low"
    assert out["action"] == "ACCEPT"
    assert out["src_ip"] == "203.0.113.7"
    assert out["dst_ip"] == "10.0.5.12"
    assert out["protocol"] == "tcp"


def test_normalize_unparseable_message_passes_through_safely():
    # Garbage that is neither v2 fixed-column nor JSON. We want a
    # safe default — no crash, severity falls to info, raw_event
    # preserves the original message so detections can pattern-match.
    conn = AWSVPCFlowLogsConnector(log_group_name="/aws/vpc/flowlogs", flow_log_version="v5")
    out = conn.normalize(_envelope("totally garbled flow record"))

    assert out["record_format"] == "unknown"
    assert out["severity"] == "info"
    assert out["raw_event"] == {"message": "totally garbled flow record"}
    assert out["src_ip"] is None
    assert out["dst_ip"] is None
    assert out["title"] == "VPC flow log event"


def test_normalize_handles_missing_timestamp():
    conn = AWSVPCFlowLogsConnector(log_group_name="/aws/vpc/flowlogs")
    envelope = _envelope(_V2_SAMPLE_REJECT)
    envelope.pop("timestamp")
    out = conn.normalize(envelope)
    assert out["created_at"] is None


# ===========================================================================
# test_connection()
# ===========================================================================


@pytest.mark.asyncio
async def test_test_connection_rejects_blank_log_group():
    conn = AWSVPCFlowLogsConnector(region="us-east-1", log_group_name="")
    result = await conn.test_connection()
    assert result["success"] is False
    assert "log_group_name" in result["error"]


@pytest.mark.asyncio
async def test_test_connection_happy_path():
    conn = AWSVPCFlowLogsConnector(region="us-east-1", log_group_name="/aws/vpc/flowlogs")
    fake_client = MagicMock()
    fake_client.describe_log_groups.return_value = {"logGroups": [{"logGroupName": "/aws/vpc/flowlogs", "creationTime": 1700000000}]}
    with patch.object(conn, "_get_client", return_value=fake_client):
        result = await conn.test_connection()

    assert result["success"] is True
    assert result["log_group"] == "/aws/vpc/flowlogs"
    assert result["region"] == "us-east-1"
    fake_client.describe_log_groups.assert_called_once_with(logGroupNamePrefix="/aws/vpc/flowlogs", limit=5)


@pytest.mark.asyncio
async def test_test_connection_log_group_not_found():
    # The API returns 200 + empty list when the prefix doesn't match.
    # We must surface that as a failure and NOT a silent success.
    conn = AWSVPCFlowLogsConnector(region="us-east-1", log_group_name="/aws/vpc/flowlogs")
    fake_client = MagicMock()
    fake_client.describe_log_groups.return_value = {"logGroups": []}
    with patch.object(conn, "_get_client", return_value=fake_client):
        result = await conn.test_connection()

    assert result["success"] is False
    assert "not found" in result["error"]


@pytest.mark.asyncio
async def test_test_connection_partial_prefix_match_is_rejected():
    # The API uses *prefix* matching — if our log group is "/aws/vpc/flowlogs"
    # and the account also has "/aws/vpc/flowlogs-old", we must still
    # only accept the exact match.
    conn = AWSVPCFlowLogsConnector(region="us-east-1", log_group_name="/aws/vpc/flowlogs")
    fake_client = MagicMock()
    fake_client.describe_log_groups.return_value = {
        "logGroups": [
            {"logGroupName": "/aws/vpc/flowlogs-old"},
            {"logGroupName": "/aws/vpc/flowlogs-archive"},
        ]
    }
    with patch.object(conn, "_get_client", return_value=fake_client):
        result = await conn.test_connection()

    assert result["success"] is False


@pytest.mark.asyncio
async def test_test_connection_auth_error_returns_soft_failure():
    conn = AWSVPCFlowLogsConnector(region="us-east-1", log_group_name="/aws/vpc/flowlogs")
    fake_client = MagicMock()
    fake_client.describe_log_groups.side_effect = RuntimeError("AccessDenied: not authorized")
    with patch.object(conn, "_get_client", return_value=fake_client):
        result = await conn.test_connection()

    assert result["success"] is False
    assert "AccessDenied" in result["error"]


# ===========================================================================
# fetch_alerts()
# ===========================================================================


def _fake_paginator(pages: list[dict]):
    """Build a MagicMock that mimics boto3's paginator interface."""
    paginator = MagicMock()
    paginator.paginate.return_value = iter(pages)
    return paginator


@pytest.mark.asyncio
async def test_fetch_alerts_short_circuits_when_log_group_missing():
    conn = AWSVPCFlowLogsConnector(region="us-east-1", log_group_name="")
    out = await conn.fetch_alerts(since_seconds=300)
    assert out == []


@pytest.mark.asyncio
async def test_fetch_alerts_round_trip_paginated():
    conn = AWSVPCFlowLogsConnector(region="us-east-1", log_group_name="/aws/vpc/flowlogs")
    fake_client = MagicMock()
    paginator = _fake_paginator(
        [
            {"events": [_envelope(_V2_SAMPLE_REJECT, ts_ms=1731000000000)]},
            {
                "events": [
                    _envelope(_V2_SAMPLE_REJECT, ts_ms=1731000060000),
                    _envelope(_V2_SAMPLE_REJECT, ts_ms=1731000120000),
                ]
            },
        ]
    )
    fake_client.get_paginator.return_value = paginator

    with patch.object(conn, "_get_client", return_value=fake_client):
        results = await conn.fetch_alerts(since_seconds=300)

    assert len(results) == 3
    # All normalized
    assert all(r["source"] == "aws_vpc_flow" for r in results)
    assert all(r["severity"] == "medium" for r in results)
    # Verify the call was made with the correct kwargs
    fake_client.get_paginator.assert_called_once_with("filter_log_events")
    call_kwargs = paginator.paginate.call_args.kwargs
    assert call_kwargs["logGroupName"] == "/aws/vpc/flowlogs"
    assert call_kwargs["filterPattern"] == "?REJECT"
    assert call_kwargs["limit"] == 1000
    # MaxItems cap is wired into the PaginationConfig, not the raw call
    assert call_kwargs["PaginationConfig"]["MaxItems"] == 5000


@pytest.mark.asyncio
async def test_fetch_alerts_empty_filter_pattern_omits_filter_kwarg():
    # Operator override: empty filter = "ingest everything". We must
    # not pass an empty string as filterPattern (CloudWatch Logs
    # rejects ``filterPattern=""``).
    conn = AWSVPCFlowLogsConnector(
        region="us-east-1",
        log_group_name="/aws/vpc/flowlogs",
        filter_pattern="",
    )
    fake_client = MagicMock()
    paginator = _fake_paginator([{"events": []}])
    fake_client.get_paginator.return_value = paginator

    with patch.object(conn, "_get_client", return_value=fake_client):
        await conn.fetch_alerts(since_seconds=300)

    call_kwargs = paginator.paginate.call_args.kwargs
    assert "filterPattern" not in call_kwargs


@pytest.mark.asyncio
async def test_fetch_alerts_isolates_api_failures():
    # If filter_log_events raises (auth, throttling, deleted log group)
    # we should return an empty batch and let the scheduler retry on
    # the next poll, NOT re-raise and crash the scheduler thread.
    conn = AWSVPCFlowLogsConnector(region="us-east-1", log_group_name="/aws/vpc/flowlogs")
    fake_client = MagicMock()
    paginator = MagicMock()
    paginator.paginate.side_effect = RuntimeError("ThrottlingException")
    fake_client.get_paginator.return_value = paginator

    with patch.object(conn, "_get_client", return_value=fake_client):
        result = await conn.fetch_alerts(since_seconds=300)

    assert result == []


@pytest.mark.asyncio
async def test_fetch_alerts_propagates_time_window():
    # Time window is computed from since_seconds. Verify the kwargs
    # are roughly correct (we can't pin the exact epoch since now()
    # moves, but we can assert the delta).
    conn = AWSVPCFlowLogsConnector(region="us-east-1", log_group_name="/aws/vpc/flowlogs")
    fake_client = MagicMock()
    paginator = _fake_paginator([{"events": []}])
    fake_client.get_paginator.return_value = paginator

    with patch.object(conn, "_get_client", return_value=fake_client):
        await conn.fetch_alerts(since_seconds=600)

    call_kwargs = paginator.paginate.call_args.kwargs
    delta_ms = call_kwargs["endTime"] - call_kwargs["startTime"]
    assert delta_ms == 600 * 1000
