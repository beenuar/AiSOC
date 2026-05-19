"""Tests for T2.3 LLM input contract: no raw OCSF / vendor log JSON in model messages.

Uses ``summarize_structure_for_llm`` for safe payloads and asserts
``validate_messages`` / ``LLMInputContract`` reject raw JSON blobs that match
log-shape heuristics (e.g. ``class_uid``).
"""

from __future__ import annotations

import json

import pytest
from app.llm.contract import (
    LLMContractViolation,
    LLMInputContract,
    classify_message,
    set_contract_enforcement,
    validate_messages,
)
from app.prompt_serialization import summarize_structure_for_llm


@pytest.fixture
def contract_enforced():
    prev = set_contract_enforcement(True)
    try:
        yield
    finally:
        set_contract_enforcement(prev)


def test_classify_message_flags_minimal_ocsf_json() -> None:
    """Raw OCSF-shaped JSON must be classified as log-like."""
    blob = json.dumps({"class_uid": 7003, "category_uid": 2, "activity_id": 1})
    assert classify_message(blob) is not None


def test_llm_input_contract_rejects_raw_ocsf_json(contract_enforced) -> None:
    raw = json.dumps({"class_uid": 1, "activity_id": 2, "metadata": {"product": "AWS"}})
    with pytest.raises(LLMContractViolation):
        LLMInputContract.validate([{"role": "user", "content": raw}])


def test_validate_messages_accepts_summarized_structure(contract_enforced) -> None:
    entity = {
        "user_id": "u-1",
        "display_name": "Alice",
        "risk": {"score": 42},
    }
    body = summarize_structure_for_llm(entity, label="entity_snapshot", max_lines=80, max_depth=3)
    msgs = [
        {"role": "system", "content": "You are a security analyst."},
        {"role": "user", "content": body},
    ]
    validate_messages(msgs)
    LLMInputContract.validate(msgs)


def test_validate_messages_rejects_nested_json_string_with_class_uid(
    contract_enforced,
) -> None:
    """Even inside prose, a substring matching OCSF field names must fail."""
    bad = "Context: " + json.dumps({"class_uid": 99})
    with pytest.raises(LLMContractViolation):
        validate_messages([{"role": "user", "content": bad}])
