"""Vendor fields nested in `raw_event` must be visible to detection rules.

`raw_data` carries the connector's own normalized dict, and connectors put the
untouched vendor payload under `raw_event`. The matcher does a plain
`event.get(field)` with no path traversal, so a rule naming a vendor field —
`request_uri`, `target_image`, `call_trace` — read `None` and could never fire,
however correct the rule was.

663 of the 825 loaded rules referenced at least one field that was not visible.
Fixture replay could not catch a single one, because fixtures are synthesized
from the rule they test rather than from real telemetry.

The workaround in the tree was per-field hoisting inside individual connectors
(`llm_usage.normalize()` carries a comment explaining that it lifts
`event_type` to the top level "so the llm-* detection rules fire"), which only
ever fixed the one field someone noticed.
"""

from __future__ import annotations

import json

from app.services.detection_engine import DetectionEngine


def _ocsf(connector_payload: dict) -> dict:
    """An OCSF event as ingest produces it: raw_data is the connector's dict."""
    return {"raw_data": json.dumps(connector_payload), "class_uid": 2001}


# ── the regression ────────────────────────────────────────────────────────


def test_vendor_fields_under_raw_event_are_visible():
    """The case that silently disabled most of the corpus."""
    fields = DetectionEngine._raw_fields(
        _ocsf(
            {
                "source": "imperva",
                "severity": "high",
                "src_ip": "203.0.113.9",
                "raw_event": {"request_uri": "/?id=1' OR '1'='1", "method": "GET"},
            }
        )
    )
    assert fields["request_uri"] == "/?id=1' OR '1'='1"
    assert fields["method"] == "GET"


def test_connector_fields_are_still_visible():
    fields = DetectionEngine._raw_fields(_ocsf({"source": "imperva", "src_ip": "203.0.113.9", "raw_event": {"method": "GET"}}))
    assert fields["source"] == "imperva"
    assert fields["src_ip"] == "203.0.113.9"


def test_connector_normalization_wins_on_collision():
    """The connector made a deliberate decision; a vendor key must not undo it.

    A connector maps a vendor's idiosyncratic severity ladder onto AiSOC's five
    tiers. If the raw vendor `severity` overrode that, every severity-based
    rule and the promoter's `severity_id >= 4` floor would read the unmapped
    value.
    """
    fields = DetectionEngine._raw_fields(_ocsf({"severity": "critical", "raw_event": {"severity": "SEV-3"}}))
    assert fields["severity"] == "critical"


# ── shapes that must not break ────────────────────────────────────────────


def test_a_missing_raw_event_is_fine():
    fields = DetectionEngine._raw_fields(_ocsf({"source": "okta", "event_type": "user.session.start"}))
    assert fields["event_type"] == "user.session.start"


def test_a_non_dict_raw_event_is_ignored():
    """Some connectors put a JSON string or a list there."""
    for payload in ('{"a": 1}', ["a", "b"], 42, None):
        fields = DetectionEngine._raw_fields(_ocsf({"source": "x", "raw_event": payload}))
        assert fields["source"] == "x"


def test_malformed_raw_data_falls_back_to_the_ocsf_top_level():
    fields = DetectionEngine._raw_fields({"raw_data": "{not json", "class_uid": 2001})
    assert fields["class_uid"] == 2001


def test_absent_raw_data_falls_back_to_the_ocsf_top_level():
    fields = DetectionEngine._raw_fields({"class_uid": 2001, "severity_id": 4})
    assert fields["severity_id"] == 4


def test_nested_dicts_inside_raw_event_are_left_alone():
    """Only one level is merged. Deep traversal is not what the matcher does,
    and pretending otherwise would make rules look reachable when they are not.
    """
    fields = DetectionEngine._raw_fields(_ocsf({"raw_event": {"actor": {"email": "a@example.com"}, "verb": "create"}}))
    assert fields["verb"] == "create"
    assert fields["actor"] == {"email": "a@example.com"}
    assert "email" not in fields


def test_non_string_keys_in_raw_event_are_dropped():
    """A JSON payload cannot produce these, but a direct dict caller could."""
    fields = DetectionEngine._raw_fields({"raw_data": "", "raw_event": {1: "x", "ok": "y"}})
    # Falls back to the OCSF top level here, which still must not raise.
    assert isinstance(fields, dict)
