"""Unit tests for the Phase 3.1 raw-event → RawAlert promotion bridge.

These cover the deterministic mapping logic. The gate that proves the bridge
works against real containers is `.github/workflows/integration.yml`
(scripts/integration/spine_test.py) — these tests never mock Kafka/Postgres
and never claim to.
"""

from __future__ import annotations

import uuid

from app.models.alert import AlertSeverity
from app.services.promoter import promote_normalized_event, should_promote

TENANT = "00000000-0000-0000-0000-000000000001"


def _message(ocsf_overrides: dict | None = None) -> dict:
    ocsf = {
        "class_uid": 2001,
        "class_name": "Security Finding",
        "category_uid": 2,
        "severity_id": 5,
        "severity": "Critical",
        "message": "Credential dumping via LSASS access",
        "time": "2026-07-12T08:00:00Z",
        "tenant_uid": TENANT,
        "metadata": {"product": {"name": "Falcon", "vendor_name": "CrowdStrike"}},
        "device": {"name": "WIN-DC01"},
        "actor": {"user": {"name": "svc-backup"}},
        "src_endpoint": {"ip": "10.20.30.40"},
        "file": {"fingerprints": [{"value": "a" * 64}]},
        "mitre_attck": [
            {
                "technique_id": "T1003",
                "technique_name": "OS Credential Dumping",
                "tactic_names": ["Credential Access"],
            }
        ],
        "raw_data": '{"event_simpleName":"CredentialDump"}',
    }
    if ocsf_overrides:
        ocsf.update(ocsf_overrides)
    return {
        "id": str(uuid.uuid4()),
        "connector_id": "conn-1",
        "tenant_id": TENANT,
        "ocsf_event": ocsf,
        "normalization_version": "1.1.0",
    }


class TestShouldPromote:
    def test_findings_category_always_promotes(self):
        assert should_promote({"class_uid": 2004, "severity_id": 1})

    def test_high_severity_non_finding_promotes(self):
        assert should_promote({"class_uid": 3002, "severity_id": 4})

    def test_critical_non_finding_promotes(self):
        assert should_promote({"class_uid": 4001, "severity_id": 5})

    def test_medium_non_finding_does_not_promote(self):
        assert not should_promote({"class_uid": 4001, "severity_id": 3})

    def test_unknown_severity_non_finding_does_not_promote(self):
        assert not should_promote({"class_uid": 6003, "severity_id": 0})

    def test_missing_fields_do_not_promote(self):
        assert not should_promote({})


class TestPromoteNormalizedEvent:
    def test_full_mapping(self):
        alert = promote_normalized_event(_message())
        assert alert is not None
        assert str(alert.tenant_id) == TENANT
        assert alert.title == "Credential dumping via LSASS access"
        assert alert.severity == AlertSeverity.CRITICAL
        assert alert.source == "CrowdStrike Falcon"
        assert alert.hostname == "WIN-DC01"
        assert alert.username == "svc-backup"
        assert alert.src_ip == "10.20.30.40"
        assert alert.file_hash == "a" * 64
        assert alert.mitre_techniques == ["T1003"]
        assert alert.mitre_tactics == ["Credential Access"]
        assert alert.event_time is not None
        assert alert.raw_event["class_uid"] == 2001

    def test_severity_ladder(self):
        for sev_id, expected in [
            (5, AlertSeverity.CRITICAL),
            (4, AlertSeverity.HIGH),
            (3, AlertSeverity.MEDIUM),
            (2, AlertSeverity.LOW),
            (1, AlertSeverity.INFO),
        ]:
            alert = promote_normalized_event(_message({"severity_id": sev_id}))
            assert alert is not None, f"severity_id={sev_id} (finding) must promote"
            assert alert.severity == expected

    def test_below_threshold_non_finding_returns_none(self):
        msg = _message({"class_uid": 4001, "category_uid": 4, "severity_id": 2})
        assert promote_normalized_event(msg) is None

    def test_title_falls_back_to_class_and_product(self):
        msg = _message()
        del msg["ocsf_event"]["message"]
        alert = promote_normalized_event(msg)
        assert alert is not None
        assert alert.title == "Security Finding from Falcon"

    def test_non_uuid_tenant_returns_none(self):
        msg = _message()
        msg["tenant_id"] = "acme-corp"
        msg["ocsf_event"]["tenant_uid"] = "acme-corp"
        assert promote_normalized_event(msg) is None

    def test_malformed_message_returns_none(self):
        assert promote_normalized_event({"nope": True}) is None
        assert promote_normalized_event({"ocsf_event": "not-a-dict"}) is None

    def test_fingerprint_stable_across_promotions(self):
        # The same source event promoted twice must dedup downstream.
        a = promote_normalized_event(_message())
        b = promote_normalized_event(_message())
        assert a is not None and b is not None
        assert a.fingerprint() == b.fingerprint()
