"""A second occurrence of a known-benign alert must actually be suppressed.

The compounding loop shipped as "auto-triage outcomes persist as per-signature
institutional memory, and a repeat alert matching a trusted benign prior is
auto-resolved without re-triage", measured as `repeat_alerts_suppressed` on
`/metrics/funnel`.

It could never fire. The signature was `evidence_fingerprint(tenant,
state.raw_alert)`, and `raw_alert` carries the alert row id, the source event
ids and the raw event payload — all unique per alert. So every alert hashed to
a unique fingerprint: the dedup cache never hit, and each outcome prior was
written under a key nothing would ever look up again. The metric could only
ever report zero.

`test_outcome_memory.py` did not catch it because it calls `record_outcome`
and `lookup_prior` with the same literal signature string, which is true of
any key scheme including a broken one. The gap was that no test ever asked
whether two *alerts* produce the same signature.

These tests work in that unit: alert in, alert out.
"""

from __future__ import annotations

import pytest
from app.core.cost_governor import CostGovernor, canonical_evidence
from app.workers.fused_alert_consumer import build_state

TENANT = "11111111-1111-1111-1111-111111111111"


def _fused(**overrides):
    """A fused-alert envelope as the worker receives it off Kafka."""
    alert = {
        "id": "alert-row-1",
        "title": "Suspicious PowerShell encoded command",
        "rule_id": "rule-ps-enc",
        "rule_name": "Encoded PowerShell",
        "severity": "high",
        "hostname": "WIN-DC01",
        "username": "svc_backup",
        "src_ip": "10.0.0.5",
        "connector_type": "crowdstrike",
        "mitre_techniques": ["T1059.001"],
        "source_event_ids": ["evt-1", "evt-2"],
        "raw_event": {"_time": "2026-09-01T10:00:00Z", "cmd": "powershell -enc AAA"},
    }
    alert.update(overrides.pop("alert", {}))
    envelope = {
        "tenant_id": TENANT,
        "alert_row_id": alert["id"],
        "id": alert["id"],
        "alert": alert,
        "confidence_score": 0.81,
    }
    envelope.update(overrides)
    return envelope


def _fingerprint(envelope) -> str:
    state = build_state(envelope)
    assert state is not None
    return CostGovernor.evidence_fingerprint(str(state.tenant_id), state.raw_alert)


# ── the regression ────────────────────────────────────────────────────────


def test_the_same_alert_arriving_twice_has_the_same_signature():
    """Two separate deliveries of the same condition.

    Different row id, different source events, different raw-event timestamp
    — everything an alert store legitimately varies between two occurrences.
    """
    first = _fused()
    second = _fused(
        alert={
            "id": "alert-row-2",
            "source_event_ids": ["evt-7", "evt-8"],
            "raw_event": {"_time": "2026-09-02T11:30:00Z", "cmd": "powershell -enc AAA"},
        },
        alert_row_id="alert-row-2",
        id="alert-row-2",
        confidence_score=0.79,
    )
    assert _fingerprint(first) == _fingerprint(second)


def test_a_different_detection_on_the_same_host_does_not_collide():
    """The dangerous direction.

    If rule identity were dropped from the fingerprint, a benign prior for
    encoded PowerShell would auto-close an unrelated detection on the same
    host — a false negative, far worse than a missed suppression.
    """
    powershell = _fused()
    exfil = _fused(
        alert={
            "title": "Large outbound transfer to unknown ASN",
            "rule_id": "rule-exfil",
            "rule_name": "Possible exfiltration",
        }
    )
    assert _fingerprint(powershell) != _fingerprint(exfil)


def test_the_same_detection_on_a_different_host_does_not_collide():
    assert _fingerprint(_fused()) != _fingerprint(_fused(alert={"hostname": "WIN-WS42"}))


def test_the_same_detection_for_a_different_user_does_not_collide():
    assert _fingerprint(_fused()) != _fingerprint(_fused(alert={"username": "alice"}))


def test_two_tenants_never_share_a_signature():
    """One tenant's benign verdict must not suppress another tenant's alert."""
    other = _fused()
    other["tenant_id"] = "22222222-2222-2222-2222-222222222222"
    assert _fingerprint(_fused()) != _fingerprint(other)


# ── canonicalisation rules ────────────────────────────────────────────────


def test_volatile_fields_are_excluded():
    evidence = canonical_evidence(
        {
            "id": "x",
            "hostname": "HOST-1",
            "raw_event": {"t": 1},
            "source_event_ids": ["a"],
            "confidence": 0.9,
            "risk_score": 42,
        }
    )
    assert set(evidence) == {"hostname"}


def test_entity_casing_and_technique_order_are_not_evidence():
    a = canonical_evidence({"hostname": "WIN-DC01", "mitre_techniques": ["T1059", "T1078"]})
    b = canonical_evidence({"hostname": "win-dc01", "mitre_techniques": ["T1078", "T1059"]})
    assert a == b


def test_an_unrecognised_alert_shape_stays_distinct(monkeypatch: pytest.MonkeyPatch):
    """Unknown shapes must not all collapse into one bucket.

    An allow-list that misses every field on some caller's alert would hash
    them all identically, which would suppress unrelated alerts wholesale.
    The fallback keeps them distinct while still stripping known volatile keys.
    """
    one = canonical_evidence({"weird_vendor_field": "a", "id": "1"})
    two = canonical_evidence({"weird_vendor_field": "b", "id": "2"})
    assert one != two
    assert "id" not in one


def test_an_empty_alert_is_handled():
    assert canonical_evidence({}) == {}


# ── the cache half of the same bug ────────────────────────────────────────


def test_a_repeat_alert_now_hits_the_dedup_cache():
    """Dedup was broken by the same root cause, costing an LLM call per repeat."""
    gov = CostGovernor()
    first = _fingerprint(_fused())
    gov.record_verdict(TENANT, first, {"verdict": "false_positive"}, usd=0.01, tokens=500)

    second = _fingerprint(
        _fused(
            alert={"id": "alert-row-9", "source_event_ids": ["evt-99"]},
            alert_row_id="alert-row-9",
            id="alert-row-9",
        )
    )
    decision = gov.check(TENANT, second)
    assert decision.cached_verdict is not None
    assert decision.cached_verdict["verdict"] == "false_positive"
