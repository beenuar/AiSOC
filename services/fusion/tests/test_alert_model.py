"""Unit tests for fusion alert models — pure, no infra needed."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from app.models.alert import AlertSeverity, RawAlert


def _alert(**overrides) -> RawAlert:
    base = {
        "tenant_id": UUID("11111111-1111-1111-1111-111111111111"),
        "source": "test-source",
        "title": "Suspicious login",
    }
    base.update(overrides)
    return RawAlert(**base)


class TestRawAlertFingerprint:
    def test_fingerprint_is_stable_across_calls(self) -> None:
        a = _alert(src_ip="10.0.0.1", mitre_techniques=["T1078", "T1110"])
        assert a.fingerprint() == a.fingerprint()

    def test_fingerprint_is_stable_across_instances(self) -> None:
        a = _alert(src_ip="10.0.0.1", mitre_techniques=["T1078", "T1110"])
        b = _alert(src_ip="10.0.0.1", mitre_techniques=["T1078", "T1110"])
        # Different ids/timestamps must NOT change fingerprint
        assert a.id != b.id
        assert a.fingerprint() == b.fingerprint()

    def test_fingerprint_ignores_volatile_fields(self) -> None:
        """`description`, `risk_score`, `tags`, `raw_event` aren't part of the fingerprint."""
        a = _alert(src_ip="10.0.0.1", description="first", risk_score=0.1, tags=["a"])
        b = _alert(src_ip="10.0.0.1", description="second", risk_score=0.9, tags=["b"])
        assert a.fingerprint() == b.fingerprint()

    def test_fingerprint_changes_when_entity_changes(self) -> None:
        a = _alert(src_ip="10.0.0.1")
        b = _alert(src_ip="10.0.0.2")
        assert a.fingerprint() != b.fingerprint()

    def test_fingerprint_changes_when_tenant_changes(self) -> None:
        a = _alert(tenant_id=uuid4(), src_ip="10.0.0.1")
        b = _alert(tenant_id=uuid4(), src_ip="10.0.0.1")
        assert a.fingerprint() != b.fingerprint()

    def test_fingerprint_is_order_independent_for_techniques(self) -> None:
        a = _alert(src_ip="10.0.0.1", mitre_techniques=["T1078", "T1110"])
        b = _alert(src_ip="10.0.0.1", mitre_techniques=["T1110", "T1078"])
        assert a.fingerprint() == b.fingerprint()

    def test_fingerprint_is_64_char_hex(self) -> None:
        a = _alert()
        fp = a.fingerprint()
        assert len(fp) == 64
        int(fp, 16)  # raises if not hex


class TestRawAlertCorrelationKey:
    def test_correlation_key_prefers_src_ip(self) -> None:
        a = _alert(
            src_ip="10.0.0.1",
            hostname="host1",
            username="alice",
            mitre_tactics=["initial-access"],
        )
        key = a.correlation_key()
        assert "10.0.0.1" in key
        assert "host1" not in key
        assert key.endswith(":initial-access")

    def test_correlation_key_falls_through_to_hostname(self) -> None:
        a = _alert(hostname="server-42", mitre_tactics=["execution"])
        key = a.correlation_key()
        assert "server-42" in key
        assert key.endswith(":execution")

    def test_correlation_key_unknown_when_no_entity_or_tactic(self) -> None:
        a = _alert()
        assert a.correlation_key().endswith(":unknown:unknown")

    def test_correlation_key_includes_tenant(self) -> None:
        tenant = UUID("22222222-2222-2222-2222-222222222222")
        a = _alert(tenant_id=tenant, src_ip="1.1.1.1", mitre_tactics=["impact"])
        assert a.correlation_key().startswith(str(tenant))


class TestAlertSeverityEnum:
    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("CRITICAL", "critical"),
            ("HIGH", "high"),
            ("MEDIUM", "medium"),
            ("LOW", "low"),
            ("INFO", "info"),
        ],
    )
    def test_severity_values(self, name: str, value: str) -> None:
        assert AlertSeverity[name].value == value
