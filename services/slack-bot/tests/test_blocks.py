"""
Tests for ``app.blocks``.

The goals here are deliberately structural rather than visual:

* every builder must always return a non-empty list of dicts (Slack rejects
  empty ``blocks`` arrays)
* every block must declare a ``type`` (Block Kit hard requirement)
* deep-link URLs are absolute (Slack rejects relative URLs in buttons)
* the approval card carries the action and case ids inside button ``value``
  fields so the interactive handler can decode them without a DB lookup
* truncation kicks in for long titles and rationale strings (defence in
  depth — we never want to ship a 4kB Slack message)
"""

from __future__ import annotations

from typing import Any

import pytest
from app.blocks import (
    action_decision_blocks,
    approval_card_blocks,
    case_card_blocks,
    case_explanation_blocks,
    case_list_blocks,
    error_blocks,
    help_blocks,
    investigation_started_blocks,
    rich_approval_card_blocks,
)

WEB_BASE = "https://app.aisoc.test"


def _all_have_type(blocks: list[dict[str, Any]]) -> bool:
    return bool(blocks) and all(isinstance(b, dict) and "type" in b for b in blocks)


# ────────────────────────────────────────────────────────────────────────────
# case_list_blocks
# ────────────────────────────────────────────────────────────────────────────


def test_case_list_blocks_empty_renders_friendly_message():
    blocks = case_list_blocks([], web_base=WEB_BASE)
    assert _all_have_type(blocks)
    text = blocks[0]["text"]["text"]
    assert "nothing to triage" in text.lower()


def test_case_list_blocks_renders_each_case_with_deep_link():
    cases = [
        {
            "id": "c-1",
            "case_number": "AISOC-1",
            "title": "Suspicious login burst",
            "severity": "high",
            "status": "investigating",
        },
        {
            "id": "c-2",
            "case_number": "AISOC-2",
            "title": "Phish mail flagged",
            "severity": "medium",
            "status": "new",
        },
    ]
    blocks = case_list_blocks(cases, web_base=WEB_BASE)
    assert _all_have_type(blocks)
    rendered = "\n".join(b["text"]["text"] for b in blocks if b["type"] == "section" and isinstance(b.get("text"), dict))
    assert "AISOC-1" in rendered and "Suspicious login burst" in rendered
    assert "AISOC-2" in rendered
    assert f"{WEB_BASE}/cases/c-1" in rendered
    assert f"{WEB_BASE}/cases/c-2" in rendered


def test_case_list_blocks_caps_at_ten_and_shows_overflow_hint():
    cases = [
        {
            "id": f"c-{i}",
            "case_number": f"AISOC-{i}",
            "title": f"Case {i}",
            "severity": "low",
            "status": "new",
        }
        for i in range(15)
    ]
    blocks = case_list_blocks(cases, web_base=WEB_BASE)
    section_blocks = [b for b in blocks if b["type"] == "section"]
    assert len(section_blocks) == 10
    context_blocks = [b for b in blocks if b["type"] == "context"]
    assert context_blocks, "expected an overflow context block"
    assert "15" in context_blocks[-1]["elements"][0]["text"]


# ────────────────────────────────────────────────────────────────────────────
# case_card_blocks
# ────────────────────────────────────────────────────────────────────────────


def test_case_card_blocks_includes_open_in_aisoc_button():
    case = {
        "id": "abc",
        "case_number": "AISOC-42",
        "title": "Possible ransomware",
        "severity": "critical",
        "status": "containment",
        "alert_count": 7,
    }
    blocks = case_card_blocks(case, web_base=WEB_BASE)
    assert _all_have_type(blocks)
    button_section = next(b for b in blocks if b.get("type") == "section" and "accessory" in b)
    assert button_section["accessory"]["type"] == "button"
    assert button_section["accessory"]["url"] == f"{WEB_BASE}/cases/abc"


def test_case_card_blocks_truncates_long_titles_and_descriptions():
    case = {
        "id": "abc",
        "case_number": "AISOC-99",
        "title": "x" * 200,
        "description": "y" * 1000,
        "severity": "low",
        "status": "new",
    }
    blocks = case_card_blocks(case, web_base=WEB_BASE)
    serialized = str(blocks)
    # truncation marker present, no 1000-char y-string
    assert "…" in serialized
    assert "y" * 500 not in serialized


# ────────────────────────────────────────────────────────────────────────────
# investigation_started_blocks / case_explanation_blocks
# ────────────────────────────────────────────────────────────────────────────


def test_investigation_started_blocks_surfaces_run_id():
    case = {"id": "c-1", "case_number": "AISOC-1"}
    investigation = {"run_id": "run-abcdef"}
    blocks = investigation_started_blocks(case, investigation, web_base=WEB_BASE)
    assert _all_have_type(blocks)
    assert "run-abcdef" in str(blocks)
    assert f"{WEB_BASE}/cases/c-1" in str(blocks)


def test_case_explanation_blocks_renders_summary_and_recommendations():
    case = {
        "id": "c-1",
        "case_number": "AISOC-1",
        "title": "Outbound DNS spike",
        "severity": "high",
        "status": "investigating",
    }
    summary = {
        "summary": "Likely DNS tunnelling from host h-12.",
        "recommendations": ["Isolate h-12", "Block 1.2.3.4"],
    }
    blocks = case_explanation_blocks(case, summary, web_base=WEB_BASE)
    assert _all_have_type(blocks)
    rendered = str(blocks)
    assert "Likely DNS tunnelling" in rendered
    assert "Isolate h-12" in rendered
    assert "Block 1.2.3.4" in rendered


def test_case_explanation_blocks_handles_empty_summary_gracefully():
    case = {"id": "c-1", "case_number": "AISOC-1", "title": "t", "severity": "low", "status": "new"}
    blocks = case_explanation_blocks(case, {}, web_base=WEB_BASE)
    assert _all_have_type(blocks)
    # No "AI summary" header should be added when the model returned nothing.
    assert "AI summary" not in str(blocks)


# ────────────────────────────────────────────────────────────────────────────
# approval_card_blocks
# ────────────────────────────────────────────────────────────────────────────


def test_approval_card_includes_approve_and_deny_buttons_with_routing_value():
    action = {
        "id": "act-1",
        "action_type": "isolate_host",
        "target": "host-42",
        "blast_radius": "high",
        "rationale": "confirmed beacon",
    }
    case = {"id": "case-7", "case_number": "AISOC-7"}
    blocks = approval_card_blocks(
        action=action,
        case=case,
        requested_by_slack_id="U123",
        web_base=WEB_BASE,
    )
    assert _all_have_type(blocks)

    actions_block = next(b for b in blocks if b["type"] == "actions")
    action_ids = [el["action_id"] for el in actions_block["elements"]]
    assert "aisoc_action_approve" in action_ids
    assert "aisoc_action_deny" in action_ids

    # routing tokens carry both ids so the handler can avoid a DB hit
    approve = next(el for el in actions_block["elements"] if el["action_id"] == "aisoc_action_approve")
    assert approve["value"] == "act-1|case-7"
    assert approve.get("confirm"), "approve must always show a confirm dialog"


def test_approval_card_uses_action_id_fallback_when_id_missing():
    action = {
        "action_id": "act-2",
        "action_type": "block_ip",
        "target": "1.2.3.4",
        "blast_radius": "medium",
    }
    case = {"id": "case-9"}
    blocks = approval_card_blocks(
        action=action,
        case=case,
        requested_by_slack_id="U999",
        web_base=WEB_BASE,
    )
    actions_block = next(b for b in blocks if b["type"] == "actions")
    deny = next(el for el in actions_block["elements"] if el["action_id"] == "aisoc_action_deny")
    assert deny["value"].startswith("act-2|case-9")


# ────────────────────────────────────────────────────────────────────────────
# action_decision_blocks / help / error
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "decision, expected_emoji",
    [("approved", "✅"), ("rejected", "🛑")],
)
def test_action_decision_blocks_render_correct_emoji(decision: str, expected_emoji: str):
    action = {"id": "act-1", "action_type": "isolate_host", "target": "h-1"}
    blocks = action_decision_blocks(decision=decision, action=action, decided_by_slack_id="U777")
    assert _all_have_type(blocks)
    assert expected_emoji in blocks[0]["text"]["text"]
    assert "<@U777>" in blocks[0]["text"]["text"]
    # No interactive elements in post-decision state
    assert all(b["type"] != "actions" for b in blocks)


def test_help_blocks_lists_every_supported_subcommand():
    blocks = help_blocks()
    assert _all_have_type(blocks)
    rendered = str(blocks)
    for cmd in ("list", "investigate", "explain", "isolate", "block", "help"):
        assert f"`/aisoc {cmd}" in rendered or f"/aisoc {cmd}" in rendered


def test_error_blocks_truncate_and_carry_x_emoji():
    blocks = error_blocks("z" * 1000)
    assert _all_have_type(blocks)
    text = blocks[0]["text"]["text"]
    assert text.startswith("❌")
    # ensure truncation happened
    assert text.count("z") < 1000


# ────────────────────────────────────────────────────────────────────────────
# T3.6 — Block Kit v2: Need-Info button, timeout footer, rich card
# ────────────────────────────────────────────────────────────────────────────


def _action_ids(blocks: list[dict[str, Any]]) -> set[str]:
    actions = next((b for b in blocks if b.get("type") == "actions"), None)
    if not actions:
        return set()
    return {el.get("action_id") for el in actions.get("elements", []) if "action_id" in el}


def test_approval_card_includes_need_info_button_alongside_approve_deny():
    blocks = approval_card_blocks(
        action={"id": "act-X", "action_type": "isolate_host", "target": "h-1"},
        case={"id": "case-X"},
        requested_by_slack_id="U777",
        web_base=WEB_BASE,
    )
    ids = _action_ids(blocks)
    assert {"aisoc_action_approve", "aisoc_action_deny", "aisoc_action_need_info"} <= ids


def test_approval_card_timeout_footer_appears_when_timeout_supplied():
    blocks = approval_card_blocks(
        action={"id": "act-X", "action_type": "isolate_host", "target": "h-1"},
        case={"id": "case-X"},
        requested_by_slack_id="U777",
        web_base=WEB_BASE,
        timeout_seconds=600,
        safe_default="rejected",
    )
    rendered = str(blocks)
    assert "Auto-denied" in rendered or "Auto-rejected" in rendered
    assert "10 min" in rendered


def test_approval_card_no_timeout_footer_when_zero_timeout():
    blocks = approval_card_blocks(
        action={"id": "act-X", "action_type": "isolate_host", "target": "h-1"},
        case={"id": "case-X"},
        requested_by_slack_id="U777",
        web_base=WEB_BASE,
        timeout_seconds=0,
    )
    assert "Auto-" not in str(blocks)


def test_rich_approval_card_includes_related_alerts_and_why_this_matters():
    alerts = [
        {"id": "a1", "rule_name": "Suspicious PowerShell", "severity": "high"},
        {"id": "a2", "rule_name": "Lateral movement attempt", "severity": "critical"},
    ]
    blocks = rich_approval_card_blocks(
        action={"id": "act-X", "action_type": "isolate_host", "target": "h-1"},
        case={
            "id": "case-X",
            "case_number": "CASE-0001",
            "description": "Endpoint EDR flagged a credential dumping attempt.",
        },
        requested_by_slack_id="U777",
        web_base=WEB_BASE,
        related_alerts=alerts,
    )
    rendered = str(blocks)
    assert "Why this matters" in rendered
    assert "credential dumping" in rendered
    assert "Related alerts" in rendered
    assert "Suspicious PowerShell" in rendered
    assert "Lateral movement" in rendered
    # Still carries all three action buttons.
    ids = _action_ids(blocks)
    assert {"aisoc_action_approve", "aisoc_action_deny", "aisoc_action_need_info"} <= ids
