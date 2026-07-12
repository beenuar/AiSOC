"""Phase 5 — versioned event-schema registry tests."""

from __future__ import annotations

from app.services.event_schema import (
    KNOWN_SCHEMA_VERSIONS,
    validate_event,
    validate_raw_alert,
    validate_raw_event,
)

TENANT = "00000000-0000-0000-0000-000000000001"


def _raw_event(**overrides) -> dict:
    base = {"tenant_id": TENANT, "ocsf_event": {"class_uid": 2001, "metadata": {"uid": "ev-1"}}}
    base.update(overrides)
    return base


def test_valid_raw_event_passes_and_carries_lineage():
    v = validate_raw_event(_raw_event())
    assert v.ok
    assert v.schema_version == "v1"
    assert v.source_event_id == "ev-1"
    assert v.tenant_id == TENANT


def test_non_object_payload_is_rejected():
    v = validate_raw_event("not a dict")
    assert not v.ok
    assert "not a JSON object" in v.reason


def test_missing_ocsf_event_is_rejected():
    v = validate_raw_event({"tenant_id": TENANT})
    assert not v.ok
    assert "ocsf_event" in v.reason


def test_unknown_schema_version_is_rejected():
    v = validate_raw_event(_raw_event(schema_version="v99"))
    assert not v.ok
    assert "unknown schema_version" in v.reason


def test_non_uuid_tenant_is_rejected_with_lineage():
    v = validate_raw_event(_raw_event(tenant_id="not-a-uuid"))
    assert not v.ok
    assert "tenant_id is not a UUID" in v.reason
    # Lineage is still captured so an operator can find the offending event.
    assert v.source_event_id == "ev-1"


def test_tenant_uid_fallback_inside_ocsf():
    payload = {"ocsf_event": {"tenant_uid": TENANT, "class_uid": 2001}}
    v = validate_raw_event(payload)
    assert v.ok
    assert v.tenant_id == TENANT


def test_raw_alert_structural_check():
    assert validate_raw_alert({"tenant_id": TENANT, "title": "x"}).ok
    bad = validate_raw_alert([1, 2, 3])
    assert not bad.ok


def test_dispatch_by_topic():
    ev = validate_event("aisoc.raw_events", _raw_event(), raw_events_topic="aisoc.raw_events", alerts_raw_topic="aisoc.alerts.raw")
    assert ev.ok
    al = validate_event("aisoc.alerts.raw", {"tenant_id": TENANT}, raw_events_topic="aisoc.raw_events", alerts_raw_topic="aisoc.alerts.raw")
    assert al.ok


def test_registered_schema_set_is_stable_drift_guard():
    """The wire contract must not move unnoticed. If you intentionally add or
    bump an envelope version, update this expected set in the same commit."""
    assert KNOWN_SCHEMA_VERSIONS == {
        "aisoc.raw_events": frozenset({"v1"}),
        "aisoc.alerts.raw": frozenset({"v1"}),
    }
