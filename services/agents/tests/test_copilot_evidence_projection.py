"""Copilot evidence must fit the real tool channel and the input contract."""

from __future__ import annotations

import copy
import json
import uuid

import pytest
from app.llm.contract import LLMContractViolation, LLMInputContract
from app.prompting.tool_results import MAX_TOOL_MESSAGE_CHARS, render_tool_message
from app.tools.copilot import MAX_EVIDENCE_BYTES, CopilotReads

ALERT = "00000000-0000-0000-0000-000000000222"


def test_ocsf_record_projects_facts_without_forwarding_raw_payloads():
    row = {
        "id": ALERT,
        "title": "AWS WAF - Multiple blocked requests.",
        "severity": "high",
        "event_time": "2026-01-01T00:00:00Z",
        "rule_id": "100001",
        "raw_event": {
            "class_uid": 2001,
            "activity_id": 1,
            "raw_data": "opaque-vendor-body",
            "full_log": "opaque-full-log",
            "device": {"name": "edge-01", "credentials": "device-secret"},
            "src_endpoint": {"ip": "198.51.100.42", "port": 443, "headers": {"Authorization": "header-secret"}},
            "finding": {"uid": "finding-1", "title": "Blocked requests"},
            "activity": {
                "action": "http_request",
                "outcome": "blocked",
                "actor": {"kind": "user", "name": "analyst", "token": "actor-secret"},
                "resource": {"type": "web_acl", "id": "acl-1"},
                "location": {"country_code": "TW", "ip": "198.51.100.42"},
            },
        },
    }
    original = copy.deepcopy(row)
    reads = CopilotReads()
    result = reads._records("copilot_record", "alert", [row])
    rendered = render_tool_message(result)
    LLMInputContract.validate([{"role": "tool", "content": rendered}])
    record = json.loads(rendered)["records"][0]
    assert record["ref"] == f"alert:{ALERT}"
    assert record["rule_id"] == "100001"
    assert record["event_summary"]["src_endpoint.ip"] == "198.51.100.42"
    assert record["event_summary"]["device.name"] == "edge-01"
    assert record["event_summary"]["activity.outcome"] == "blocked"
    assert record["event_summary"]["activity.resource.id"] == "acl-1"
    for omitted in ("raw_event", "class_uid", "activity_id", "opaque-", "device-secret", "header-secret", "actor-secret"):
        assert omitted not in rendered
        assert omitted not in reads.sources[0].text
    assert row == original


def test_nested_record_fields_use_declared_shapes():
    reads = CopilotReads()
    result = reads._records(
        "copilot_entity_risk",
        "entity_risk",
        [
            {
                "entity_type": "host",
                "entity_value": "edge-01",
                "score": 42,
                "entities": [{"type": "host", "value": "edge-01", "raw_data": "hidden-entity"}],
                "contributors": [{"alert_id": ALERT, "severity": "high", "points": 42, "raw_event": {"class_uid": 2001}}],
                "contributing_alerts": [ALERT, {"raw_data": "hidden-id"}],
                "severities": {"high": 1, "unexpected": {"raw_data": "hidden-severity"}},
                "summary": {"class_uid": 2001, "raw_data": "hidden-summary"},
            }
        ],
    )
    rendered = render_tool_message(result)
    LLMInputContract.validate([{"role": "tool", "content": rendered}])
    record = result["records"][0]
    assert record["entities"] == [{"type": "host", "value": "edge-01"}]
    assert record["contributors"] == [{"alert_id": ALERT, "severity": "high", "points": 42}]
    assert record["contributing_alerts"] == [ALERT]
    assert record["severities"] == {"high": 1}
    assert "summary" not in record
    assert "hidden-" not in rendered


@pytest.mark.parametrize("text", ["long narrative " * 300, "很長的事件摘要" * 400])
def test_whole_tool_message_retains_coverage_and_only_cites_visible_records(text):
    reads = CopilotReads()
    rows = [
        {"id": str(uuid.UUID(int=index + 1)), "title": text, "description": text, "affected_ips": [f"198.51.100.{index + 1}"]}
        for index in range(20)
    ]
    result = reads._records(
        "copilot_alerts",
        "alert",
        rows,
        total=42,
        page=1,
        next_page=2,
        window={"field": "event_time", "since": "2026-01-01", "until": "2026-01-02"},
        coverage="One page of ingested alerts.",
    )
    rendered = render_tool_message(result)
    decoded = json.loads(rendered)
    assert decoded == result
    assert len(json.dumps(result, default=str)) <= MAX_TOOL_MESSAGE_CHARS
    assert decoded["truncated"] is True
    assert decoded["total"] == 42 and decoded["next_page"] == 2
    assert decoded["window"]["field"] == "event_time"
    assert decoded["coverage"] == "One page of ingested alerts."
    assert decoded["records"], "an oversized narrative must not discard the entire first record"
    assert [source.ref for source in reads.sources] == [record["ref"] for record in decoded["records"]]
    for source, record in zip(reads.sources, decoded["records"], strict=True):
        assert json.loads(source.text) == {key: value for key, value in record.items() if key != "ref"}
    assert reads.calls[-1]["records"] == len(decoded["records"])
    assert reads.calls[-1]["truncated"] is True
    assert reads._evidence_bytes <= MAX_EVIDENCE_BYTES


def test_raw_logs_and_secret_text_still_fail_the_contract():
    with pytest.raises(LLMContractViolation):
        LLMInputContract.validate([{"role": "tool", "content": json.dumps({"class_uid": 2001})}])
    reads = CopilotReads()
    result = reads._records("copilot_record", "alert", [{"id": ALERT, "description": "-----BEGIN PRIVATE KEY-----"}])
    with pytest.raises(LLMContractViolation):
        LLMInputContract.validate([{"role": "tool", "content": render_tool_message(result)}])
