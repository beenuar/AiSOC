"""Wave 6 - CSPM scanner (W6.2), compliance mapping + auto-evidence (W6.1),
and notification/SOAR destinations (W6.3)."""

from __future__ import annotations

import httpx
import pytest
from app.services import destinations
from app.services.compliance_mapping import (
    build_evidence,
    evidence_for_cspm_finding,
    evidence_for_detection,
    map_mitre_to_controls,
)
from app.services.cspm import scan_resources, summarize
from app.services.destinations import (
    DestinationError,
    build_email_payload,
    build_opsgenie_payload,
    build_soar_handoff_payload,
    dispatch,
)

# ── W6.2 CSPM ──────────────────────────────────────────────────────────────

_SNAPSHOT = [
    {"type": "s3_bucket", "id": "public-bucket", "public_acl": True, "encrypted": False},
    {"type": "security_group", "id": "sg-1", "ingress": [{"cidr": "0.0.0.0/0", "from_port": 22, "to_port": 22}]},
    {"type": "iam_user", "id": "svc", "console_enabled": True, "mfa_enabled": False, "access_key_age_days": 200},
    {"type": "rds_instance", "id": "db-1", "publicly_accessible": True, "storage_encrypted": True},
    {"type": "ebs_volume", "id": "vol-ok", "encrypted": True},  # clean
]


def test_scan_flags_the_real_misconfigurations():
    findings = scan_resources(_SNAPSHOT)
    ids = {f.check_id for f in findings}
    assert "cspm.s3.public" in ids
    assert "cspm.s3.unencrypted" in ids
    assert "cspm.sg.world_open" in ids
    assert "cspm.iam.no_mfa" in ids
    assert "cspm.iam.stale_key" in ids
    assert "cspm.rds.public" in ids


def test_scan_is_quiet_on_clean_resources():
    clean = [
        {"type": "s3_bucket", "id": "ok", "public_acl": False, "encrypted": True},
        {"type": "security_group", "id": "sg-ok", "ingress": [{"cidr": "10.0.0.0/8", "from_port": 22, "to_port": 22}]},
        {"type": "iam_user", "id": "u", "console_enabled": True, "mfa_enabled": True, "access_key_age_days": 10},
    ]
    assert scan_resources(clean) == []


def test_findings_carry_control_refs_and_severity():
    findings = scan_resources(_SNAPSHOT)
    s3_public = next(f for f in findings if f.check_id == "cspm.s3.public")
    assert s3_public.severity == "critical"
    assert "CIS-AWS-2.1.5" in s3_public.control_refs


def test_summarize_counts_by_severity():
    counts = summarize(scan_resources(_SNAPSHOT))
    assert counts["critical"] >= 1
    assert counts["high"] >= 2


# ── W6.1 compliance mapping + evidence ─────────────────────────────────────


def test_mitre_maps_to_controls():
    controls = map_mitre_to_controls(["T1078.004", "T1046"])
    assert "SOC2-CC6.1" in controls
    assert "CIS-AWS-5.2" in controls


def test_detection_auto_evidence():
    records = evidence_for_detection("rule-1", ["T1078"], "valid-account anomaly fired")
    assert records
    assert all(r.source_type == "detection" for r in records)
    assert any(r.framework == "SOC 2" for r in records)


def test_cspm_finding_auto_evidence():
    finding = scan_resources(_SNAPSHOT)[0].as_dict()
    records = evidence_for_cspm_finding(finding)
    assert records
    assert all(r.source_type == "cspm" for r in records)


def test_build_evidence_skips_unknown_controls():
    records = build_evidence(["NOPE-999", "SOC2-CC6.1"], source_type="alert", source_id="a1", detail="x")
    assert len(records) == 1
    assert records[0].control_id == "SOC2-CC6.1"


# ── W6.3 destinations ──────────────────────────────────────────────────────

_ALERT = {"id": "al-1", "title": "Root login", "severity": "critical", "source": "cloudtrail", "description": "root used"}


def test_opsgenie_priority_mapping():
    payload = build_opsgenie_payload(_ALERT)
    assert payload["priority"] == "P1"
    assert "critical" in payload["tags"]


def test_email_payload_subject_and_recipients():
    payload = build_email_payload(_ALERT, ["soc@corp.com"])
    assert payload["to"] == ["soc@corp.com"]
    assert "[AiSOC][CRITICAL]" in payload["subject"]


def test_soar_handoff_schema():
    payload = build_soar_handoff_payload(_ALERT)
    assert payload["schema"] == "aisoc.handoff.v1"
    assert payload["alert"]["id"] == "al-1"


def test_guard_blocks_bad_scheme_and_private():
    with pytest.raises(DestinationError):
        destinations._guard_url("file:///etc/passwd")
    with pytest.raises(DestinationError):
        destinations._guard_url("http://localhost:9000/hook")


async def test_dispatch_email_returns_formatted():
    result = await dispatch("email", {"recipients": ["a@b.com"]}, _ALERT)
    assert result.ok and result.kind == "email"
    assert result.payload["to"] == ["a@b.com"]


async def test_dispatch_webhook_posts(monkeypatch):
    captured = {}

    class _Resp:
        status_code = 202

    class _Client:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None):
            captured["url"] = url
            captured["json"] = json
            return _Resp()

    monkeypatch.setattr(destinations, "_guard_url", lambda url: None)
    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    result = await dispatch("webhook", {"url": "https://soar.example.com/hook"}, _ALERT)
    assert result.ok
    assert captured["json"]["schema"] == "aisoc.handoff.v1"
