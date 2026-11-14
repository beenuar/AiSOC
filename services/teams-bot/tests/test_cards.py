"""
Adaptive Card factory tests for the Teams bot.

Goals
=====

* Every card has the envelope keys Teams + Outlook require
  (``$schema``, ``type``, ``version``, ``body``).
* ``approval_card`` exposes the three signed buttons in the documented
  order (Approve, Deny, Need-Info) plus an ``Open case`` link.
* Each ``Action.Submit`` data payload carries the canonical fields and
  the signature is verifiable with the same secret.
* The timeout footer renders when ``timeout_seconds`` is set.
"""

from __future__ import annotations

import time
from typing import Any

from app.cards import approval_card, case_context_card, decision_card
from app.services.hmac_signer import verify_card_data

SECRET = "teams-test-secret-not-real"


def _actions(card: dict[str, Any]) -> list[dict[str, Any]]:
    return [a for a in card["actions"] if isinstance(a, dict)]


def test_case_context_card_has_required_envelope():
    card = case_context_card(
        {"id": "case-1", "case_number": "CASE-0001", "title": "EDR detection"},
        web_base="https://app.aisoc.test",
    )
    # Exact-match the schema URL rather than a ``startswith`` substring check.
    # CodeQL (``py/incomplete-url-substring-sanitization``) flags unanchored
    # host-prefix checks because they can match malicious lookalike URLs
    # (e.g. ``http://adaptivecards.io.attacker.example/``). The Adaptive Card
    # spec only defines one schema URL, so we assert it verbatim.
    assert card["$schema"] == "http://adaptivecards.io/schemas/adaptive-card.json"
    assert card["type"] == "AdaptiveCard"
    assert card["version"] == "1.5"
    assert isinstance(card["body"], list) and len(card["body"]) >= 2
    open_url = next(a for a in card["actions"] if a["type"] == "Action.OpenUrl")
    assert open_url["url"].endswith("/cases/case-1")


def test_approval_card_has_three_signed_submit_buttons():
    card = approval_card(
        action={"id": "act-1", "action_type": "isolate_host", "target": "h-1"},
        case={"id": "case-1", "case_number": "CASE-0001"},
        requested_by="user@example.com",
        web_base="https://app.aisoc.test",
        signing_secret=SECRET,
        issued_at=int(time.time()),
    )
    actions = _actions(card)
    submit_actions = [a for a in actions if a["type"] == "Action.Submit"]
    assert len(submit_actions) == 3

    verbs = [a["data"]["verb"] for a in submit_actions]
    assert verbs == ["approve", "reject", "need_info"]

    for action in submit_actions:
        data = action["data"]
        assert data["action_id"] == "act-1"
        assert data["case_id"] == "case-1"
        assert isinstance(data["issued_at"], int)
        # Signature is verifiable with the same secret.
        verify_card_data(data, secret=SECRET, max_age_seconds=600)


def test_approval_card_timeout_footer_present():
    card = approval_card(
        action={"id": "act-1", "action_type": "block_ip", "target": "1.2.3.4"},
        case={"id": "case-1"},
        requested_by="alice@example.com",
        web_base="https://app.aisoc.test",
        signing_secret=SECRET,
        timeout_seconds=600,
        safe_default="rejected",
    )
    rendered = str(card)
    assert "Auto-denied" in rendered
    assert "10 min" in rendered


def test_approval_card_no_timeout_footer_when_disabled():
    card = approval_card(
        action={"id": "act-1", "action_type": "block_ip", "target": "1.2.3.4"},
        case={"id": "case-1"},
        requested_by="alice@example.com",
        web_base="https://app.aisoc.test",
        signing_secret=SECRET,
    )
    assert "Auto-" not in str(card)


def test_decision_card_emits_terminal_state_block():
    card = decision_card(decision="approved", action_id="act-1", decided_by="bob@example.com")
    assert card["type"] == "AdaptiveCard"
    text = str(card["body"])
    assert "approved" in text
    assert "bob@example.com" in text
    assert "act-1" in text
    # No interactive surfaces — buttons are gone.
    assert "actions" not in card or card.get("actions") in (None, [])
