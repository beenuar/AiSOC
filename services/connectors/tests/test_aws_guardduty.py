"""
Unit tests for ``AWSGuardDutyConnector``.

Coverage:
  * schema sanity (required region, optional creds, secret marking)
  * ``_severity_label()`` across the full 0-10 score range
  * ``normalize()`` field extraction (src_ip across action shapes, cloud_resource)
  * ``test_connection()`` soft failure when no detector exists
  * ``fetch_alerts()`` round-trip with mocked boto3 client (list+get findings)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from app.connectors.aws_guardduty import AWSGuardDutyConnector, _severity_label
from app.connectors.base import Capability

# ===========================================================================
# Schema
# ===========================================================================


def test_guardduty_schema_required_and_optional_fields():
    schema = AWSGuardDutyConnector.schema()
    field_map = {f.name: f for f in schema.fields}
    # Region is implicitly required (no required=False override) so the
    # operator must always tell us which region the detector lives in.
    # Keys are optional so the operator can plug in an IAM role at the
    # runtime layer instead.
    assert field_map["access_key"].required is False
    assert field_map["secret_key"].required is False
    # Secret key must be marked as ``secret`` so the UI redacts it and
    # the CredentialVault encrypts it at rest.
    assert field_map["secret_key"].type == "secret"


def test_guardduty_schema_declares_pull_alerts():
    assert AWSGuardDutyConnector.capabilities() == (Capability.PULL_ALERTS,)


def test_guardduty_schema_category_is_cloud():
    assert AWSGuardDutyConnector.schema().category == "cloud"


# ===========================================================================
# Severity mapping
# ===========================================================================


@pytest.mark.parametrize(
    "score,expected",
    [
        (9.5, "high"),  # GuardDuty's "critical" tier collapses to high
        (8.0, "high"),
        (7.0, "high"),
        (6.9, "medium"),
        (5.0, "medium"),
        (4.0, "medium"),
        (3.9, "low"),
        (1.0, "low"),
        (0.5, "info"),
        (0.0, "info"),
    ],
)
def test_severity_label_buckets(score, expected):
    assert _severity_label(score) == expected


def test_severity_label_rejects_garbage_safely():
    # A garbage severity must not crash the polling loop. ``medium`` is
    # the safest neutral fallback when we cannot interpret the upstream
    # signal — it preserves alert visibility instead of silently
    # downgrading to ``info``.
    assert _severity_label("nope") == "medium"
    assert _severity_label(None) == "medium"


# ===========================================================================
# Normalize
# ===========================================================================


def test_normalize_extracts_src_ip_from_network_connection_action():
    connector = AWSGuardDutyConnector(region="us-east-1")
    raw = {
        "Id": "gd-1",
        "Type": "UnauthorizedAccess:EC2/SSHBruteForce",
        "Title": "SSH brute force",
        "Description": "Inbound SSH brute force",
        "Severity": 5.0,
        "AccountId": "123456789012",
        "Region": "us-east-1",
        "CreatedAt": "2026-05-10T12:00:00Z",
        "Service": {"Action": {"NetworkConnectionAction": {"RemoteIpDetails": {"IpAddressV4": "203.0.113.5"}}}},
        "Resource": {
            "ResourceType": "Instance",
            "InstanceDetails": {"InstanceId": "i-0abc"},
        },
    }
    out = connector.normalize(raw)
    assert out["source"] == "aws_guardduty"
    assert out["external_id"] == "gd-1"
    assert out["src_ip"] == "203.0.113.5"
    assert out["cloud_resource"] == "i-0abc"
    assert out["cloud_platform"] == "aws"
    assert out["aws_account_id"] == "123456789012"
    assert out["aws_region"] == "us-east-1"
    assert out["severity"] == "medium"
    assert out["rule_name"] == "UnauthorizedAccess:EC2/SSHBruteForce"
    # Raw payload must be preserved verbatim for forensics / replay.
    assert out["raw_event"] is raw


def test_normalize_falls_back_to_aws_api_call_action_for_src_ip():
    # Console-call findings (e.g. IAM brute-force from a stolen access
    # key) put the remote IP under AwsApiCallAction, not under
    # NetworkConnectionAction. Both shapes must yield src_ip.
    connector = AWSGuardDutyConnector(region="us-east-1")
    raw = {
        "Id": "gd-2",
        "Severity": 7.5,
        "Service": {"Action": {"AwsApiCallAction": {"RemoteIpDetails": {"IpAddressV4": "198.51.100.7"}}}},
        "Resource": {
            "AccessKeyDetails": {"AccessKeyId": "AKIAEXAMPLE"},
        },
    }
    out = connector.normalize(raw)
    assert out["src_ip"] == "198.51.100.7"
    assert out["severity"] == "high"
    # When there is no EC2 instance, cloud_resource should fall back to
    # the access key — that is the "thing" the finding is about.
    assert out["cloud_resource"] == "AKIAEXAMPLE"


def test_normalize_port_probe_action_yields_src_ip():
    connector = AWSGuardDutyConnector(region="us-east-1")
    raw = {
        "Id": "gd-pp",
        "Severity": 2.0,
        "Service": {"Action": {"PortProbeAction": {"PortProbeDetails": [{"RemoteIpDetails": {"IpAddressV4": "10.0.0.99"}}]}}},
        "Resource": {},
    }
    out = connector.normalize(raw)
    assert out["src_ip"] == "10.0.0.99"


def test_normalize_no_action_shape_does_not_explode():
    # Some findings carry no remote IP at all; we must default to None
    # rather than raise.
    connector = AWSGuardDutyConnector(region="us-east-1")
    raw = {"Id": "gd-3", "Severity": 2.0, "Service": {}, "Resource": {}}
    out = connector.normalize(raw)
    assert out["src_ip"] is None
    assert out["cloud_resource"] is None
    assert out["severity"] == "low"


def test_normalize_falls_back_to_type_when_title_missing():
    # GuardDuty's older finding shapes occasionally omit Title. We must
    # not produce a blank-titled alert in the inbox — fall back to the
    # finding Type, then a constant.
    connector = AWSGuardDutyConnector(region="us-east-1")
    raw = {
        "Id": "gd-4",
        "Type": "Recon:EC2/Portscan",
        "Severity": 4.0,
        "Service": {},
        "Resource": {},
    }
    out = connector.normalize(raw)
    assert out["title"] == "Recon:EC2/Portscan"


# ===========================================================================
# test_connection
# ===========================================================================


@pytest.mark.asyncio
async def test_test_connection_no_detector_returns_soft_failure():
    connector = AWSGuardDutyConnector(region="us-east-1")
    mock_client = MagicMock()
    mock_client.list_detectors.return_value = {"DetectorIds": []}
    with patch.object(connector, "_get_client", return_value=mock_client):
        result = await connector.test_connection()
    # Soft failure with an actionable error string. We do NOT raise —
    # the operator can re-enable GuardDuty and the polling loop will
    # pick up findings automatically once a detector exists.
    assert result["success"] is False
    assert "no detector" in result["error"].lower()


@pytest.mark.asyncio
async def test_test_connection_with_detector_reports_count():
    connector = AWSGuardDutyConnector(region="us-east-1")
    mock_client = MagicMock()
    mock_client.list_detectors.return_value = {"DetectorIds": ["d-1", "d-2"]}
    with patch.object(connector, "_get_client", return_value=mock_client):
        result = await connector.test_connection()
    assert result["success"] is True
    assert result["detector_count"] == 2
    assert result["region"] == "us-east-1"


@pytest.mark.asyncio
async def test_test_connection_swallows_boto_errors():
    # ``AccessDenied`` and friends must surface as success=False, not
    # propagate up to the scheduler and crash the poll cycle.
    connector = AWSGuardDutyConnector(region="us-east-1")
    mock_client = MagicMock()
    mock_client.list_detectors.side_effect = RuntimeError("AccessDenied")
    with patch.object(connector, "_get_client", return_value=mock_client):
        result = await connector.test_connection()
    assert result["success"] is False
    assert "AccessDenied" in result["error"]


# ===========================================================================
# fetch_alerts round-trip
# ===========================================================================


@pytest.mark.asyncio
async def test_fetch_alerts_paginates_and_batches_get_findings():
    """End-to-end: list_detectors -> list_findings paginator -> get_findings."""
    connector = AWSGuardDutyConnector(region="us-east-1")
    mock_client = MagicMock()

    # One detector in this region.
    mock_client.list_detectors.return_value = {"DetectorIds": ["d-1"]}

    # ListFindings paginator yields two pages of IDs — 50 then 25.
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = iter(
        [
            {"FindingIds": [f"f-{i}" for i in range(50)]},
            {"FindingIds": [f"f-{i}" for i in range(50, 75)]},
        ]
    )
    mock_client.get_paginator.return_value = mock_paginator

    # GetFindings called in batches of 50, so we expect 2 calls
    # (50 IDs then 25 IDs).
    mock_client.get_findings.side_effect = [
        {
            "Findings": [
                {
                    "Id": "f-0",
                    "Severity": 8.0,
                    "Service": {},
                    "Resource": {"ResourceType": "Instance"},
                }
            ]
        },
        {
            "Findings": [
                {
                    "Id": "f-50",
                    "Severity": 3.0,
                    "Service": {},
                    "Resource": {"ResourceType": "Instance"},
                }
            ]
        },
    ]

    with patch.object(connector, "_get_client", return_value=mock_client):
        results = await connector.fetch_alerts(since_seconds=300)

    # Sanity: paginator was used (not a single list_findings call).
    assert mock_client.get_paginator.called
    # 2 batches → 2 calls to get_findings.
    assert mock_client.get_findings.call_count == 2
    assert {r["external_id"] for r in results} == {"f-0", "f-50"}
    # Severity mapping flowed through end-to-end.
    assert {r["severity"] for r in results} == {"high", "low"}


@pytest.mark.asyncio
async def test_fetch_alerts_no_detector_returns_empty_not_raise():
    connector = AWSGuardDutyConnector(region="eu-north-1")
    mock_client = MagicMock()
    mock_client.list_detectors.return_value = {"DetectorIds": []}
    with patch.object(connector, "_get_client", return_value=mock_client):
        result = await connector.fetch_alerts()
    assert result == []
    # Critical: get_findings must NOT have been called against a
    # non-existent detector. That would 400 on every poll cycle.
    mock_client.get_findings.assert_not_called()


@pytest.mark.asyncio
async def test_fetch_alerts_per_detector_failure_does_not_break_others():
    """One detector blowing up must not halt the whole region's poll."""
    connector = AWSGuardDutyConnector(region="us-east-1")
    mock_client = MagicMock()
    mock_client.list_detectors.return_value = {"DetectorIds": ["d-1", "d-2"]}

    # Detector d-1 raises mid-paginate; d-2 succeeds with one finding.
    bad_paginator = MagicMock()
    bad_paginator.paginate.side_effect = RuntimeError("throttled")
    ok_paginator = MagicMock()
    ok_paginator.paginate.return_value = iter([{"FindingIds": ["f-ok"]}])

    mock_client.get_paginator.side_effect = [bad_paginator, ok_paginator]
    mock_client.get_findings.return_value = {
        "Findings": [
            {
                "Id": "f-ok",
                "Severity": 5.0,
                "Service": {},
                "Resource": {"ResourceType": "Instance"},
            }
        ]
    }

    with patch.object(connector, "_get_client", return_value=mock_client):
        result = await connector.fetch_alerts()

    # We still got the surviving detector's finding.
    assert {r["external_id"] for r in result} == {"f-ok"}


@pytest.mark.asyncio
async def test_fetch_alerts_list_detectors_failure_returns_empty():
    # A blanket AccessDenied / throttle on list_detectors must collapse
    # to an empty list, not crash the scheduler loop.
    connector = AWSGuardDutyConnector(region="us-east-1")
    mock_client = MagicMock()
    mock_client.list_detectors.side_effect = RuntimeError("AccessDenied")
    with patch.object(connector, "_get_client", return_value=mock_client):
        result = await connector.fetch_alerts()
    assert result == []
