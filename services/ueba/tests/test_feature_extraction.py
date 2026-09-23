"""UEBA must be able to score the events the platform actually publishes.

The consumer's input topic used to default to ``security.events``, which no
service writes, so every test of the scorer passed while the scorer never ran
on a real message. These tests are written against the envelope
``services/ingest`` publishes on ``aisoc.raw_events`` — the same shape the
fusion detection engines consume — so a change to that envelope breaks them
here rather than silently in production.
"""

from __future__ import annotations

import json

from app.services.feature_extraction import extract, flat_fields

TENANT = "11111111-1111-1111-1111-111111111111"


def _envelope(raw_event: dict | None = None, **ocsf) -> dict:
    """An ingest envelope, with the vendor payload nested where connectors put it."""
    event: dict = {"class_uid": 3002, "severity_id": 3, **ocsf}
    if raw_event is not None:
        event["raw_event"] = raw_event
    return {"tenant_id": TENANT, "ocsf_event": event}


class TestFlatFields:
    def test_recovers_vendor_fields_nested_under_raw_event(self):
        # The bug this guards: connectors nest the untouched vendor payload one
        # level down, so a consumer reading the envelope flat sees None for
        # every vendor field.
        msg = _envelope(raw_event={"user": "alice", "src_ip": "10.0.0.5"})
        assert flat_fields(msg)["user"] == "alice"
        assert flat_fields(msg)["src_ip"] == "10.0.0.5"

    def test_connector_normalized_keys_win_over_raw_vendor_values(self):
        # A connector that mapped a vendor ladder onto AiSOC's five tiers must
        # not have that undone by the raw value underneath.
        msg = _envelope(raw_event={"severity_id": 99}, severity_id=4)
        assert flat_fields(msg)["severity_id"] == 4

    def test_parses_raw_data_when_it_is_a_json_string(self):
        msg = {
            "tenant_id": TENANT,
            "ocsf_event": {"raw_data": json.dumps({"user": "bob", "outcome": "failure"})},
        }
        assert flat_fields(msg)["user"] == "bob"

    def test_non_dict_envelope_yields_nothing(self):
        assert flat_fields({"ocsf_event": "not-a-dict"}) == {}
        assert flat_fields({}) == {}


class TestEntitySelection:
    def test_prefers_user_over_host_and_ip(self):
        msg = _envelope(raw_event={"user": "alice", "hostname": "web-1", "src_ip": "10.0.0.5", "time": 0})
        event = extract(msg)
        assert event is not None
        assert (event.entity_type, event.entity_id) == ("user", "alice")

    def test_falls_back_to_host_then_ip(self):
        host = extract(_envelope(raw_event={"hostname": "web-1", "time": 0}))
        assert host is not None and (host.entity_type, host.entity_id) == ("device", "web-1")

        ip = extract(_envelope(raw_event={"src_ip": "10.0.0.5", "time": 0}))
        assert ip is not None and (ip.entity_type, ip.entity_id) == ("ip", "10.0.0.5")

    def test_unwraps_ocsf_nested_identity(self):
        msg = _envelope(raw_event={"actor": {"name": "svc-deploy"}, "time": 0})
        event = extract(msg)
        assert event is not None
        assert event.entity_id == "svc-deploy"

    def test_event_with_no_identity_is_skipped(self):
        # Not an error. Most telemetry names nobody, and something with no
        # baseline cannot deviate from one.
        assert extract(_envelope(raw_event={"message": "disk usage 61%"})) is None


class TestFeatures:
    def test_derives_hour_and_weekday_from_epoch_millis(self):
        # 2026-09-23T18:30:00Z is a Wednesday (weekday 2).
        msg = _envelope(raw_event={"user": "alice", "time": 1790188200000})
        event = extract(msg)
        assert event is not None
        assert event.features["hour_of_day"] == 18.0
        assert event.features["day_of_week"] == 2.0

    def test_accepts_iso8601_timestamps(self):
        msg = _envelope(raw_event={"user": "alice", "time": "2026-09-23T06:15:00Z"})
        event = extract(msg)
        assert event is not None
        assert event.features["hour_of_day"] == 6.0

    def test_outcome_becomes_a_failure_indicator(self):
        failed = extract(_envelope(raw_event={"user": "alice", "outcome": "Denied", "time": 0}))
        assert failed is not None and failed.features["is_failure"] == 1.0

        ok = extract(_envelope(raw_event={"user": "alice", "outcome": "success", "time": 0}))
        assert ok is not None and ok.features["is_failure"] == 0.0

    def test_numeric_vendor_magnitudes_are_carried_through(self):
        msg = _envelope(raw_event={"user": "alice", "bytes_out": "1048576", "duration_ms": 250, "time": 0})
        event = extract(msg)
        assert event is not None
        assert event.features["bytes_out"] == 1048576.0
        assert event.features["duration_ms"] == 250.0

    def test_booleans_are_not_treated_as_numbers(self):
        # bool is a subclass of int in Python, so an unguarded float() turns
        # True into a 1.0 magnitude that means nothing.
        msg = _envelope(raw_event={"user": "alice", "bytes_out": True, "time": 0})
        event = extract(msg)
        assert event is not None
        assert "bytes_out" not in event.features

    def test_no_scoreable_feature_means_no_event(self):
        # An entity with nothing measurable about it must not reach the scorer,
        # which would log it as unscoreable on every single message. Built by
        # hand rather than via _envelope, which always stamps a severity.
        msg = {"tenant_id": TENANT, "ocsf_event": {"raw_event": {"user": "alice", "note": "hello"}}}
        assert extract(msg) is None


class TestEventType:
    def test_uses_the_vendor_event_type_when_present(self):
        msg = _envelope(raw_event={"user": "a", "event_type": "Authentication", "time": 0})
        event = extract(msg)
        assert event is not None and event.event_type == "authentication"

    def test_falls_back_to_the_ocsf_class(self):
        msg = _envelope(raw_event={"user": "a", "time": 0}, class_uid=3002)
        event = extract(msg)
        assert event is not None and event.event_type == "class_3002"


class TestPreExtractedShape:
    def test_the_documented_security_events_shape_still_works(self):
        event = extract(
            {
                "event_id": "evt-1",
                "tenant_id": TENANT,
                "entity_type": "user",
                "entity_id": "alice@example.com",
                "event_type": "login",
                "peer_group_id": "dept:engineering",
                "features": {"hour_of_day": 3, "login_count": "7", "label": "ignored"},
            }
        )
        assert event is not None
        assert event.entity_id == "alice@example.com"
        assert event.peer_group_id == "dept:engineering"
        assert event.source_event_id == "evt-1"
        # Non-numeric values are dropped rather than failing the whole message.
        assert event.features == {"hour_of_day": 3.0, "login_count": 7.0}

    def test_missing_tenant_is_rejected(self):
        assert extract({"entity_id": "alice", "features": {"hour_of_day": 3}}) is None


class TestTenantScoping:
    def test_tenant_comes_from_the_envelope(self):
        event = extract(_envelope(raw_event={"user": "alice", "time": 0}))
        assert event is not None and event.tenant_id == TENANT

    def test_untenanted_event_is_refused(self):
        # Scoring an event into no tenant's baseline, or every tenant's, are
        # both wrong. Refusing is the only safe option.
        msg = {"ocsf_event": {"raw_event": {"user": "alice", "time": 0}}}
        assert extract(msg) is None
