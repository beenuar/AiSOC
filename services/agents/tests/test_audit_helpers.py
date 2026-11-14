"""Tests for the InvestigatorState audit-log helper methods.

Phase 1A of the Leading-AI-SOC plan expanded `AuditEntry` with structured event
kinds (`LLM_PROMPT`, `LLM_RESPONSE`, `TOOL_CALL`, `EVIDENCE_CITED`,
`DECISION_REASON`). Those helpers must produce stable, deterministic hashes and
populate the ledger metadata that the read-side API and UI depend on.

We register a tiny stub for ``app.investigator`` so ``app/investigator/state.py``
can be imported without dragging in LangGraph or any LLM client (the package's
``__init__.py`` eagerly imports the orchestrator which depends on those). The
state module itself only uses stdlib + pydantic + ``app.models.state``.
"""

from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

# Provide a hollow ``app.investigator`` package so importing
# ``app.investigator.state`` does not execute the real package __init__,
# which transitively imports langgraph / openai.
#
# We MUST also bind the stub on the parent ``app`` module's namespace —
# inserting into ``sys.modules`` alone leaves ``app.investigator`` invisible
# to attribute-walking helpers like ``pytest.MonkeyPatch.setattr("app.investigator.X.Y")``
# (which calls ``getattr(app, "investigator")``). Skipping that step caused
# later test modules (``test_four_agent_facade``) to fail with
# ``AttributeError: 'module' object at app.investigator has no attribute 'investigator'``
# whenever this module loaded first in collection order.
if "app.investigator" not in sys.modules:
    pkg = types.ModuleType("app.investigator")
    pkg.__path__ = [str(_AGENTS_ROOT / "app" / "investigator")]
    sys.modules["app.investigator"] = pkg
    import app as _app_pkg  # noqa: PLC0415

    _app_pkg.investigator = pkg  # type: ignore[attr-defined]

state_module = importlib.import_module("app.investigator.state")

AuditEntry = state_module.AuditEntry
InvestigatorState = state_module.InvestigatorState
StepKind = state_module.StepKind
_stable_hash = state_module._stable_hash


def _make_state() -> InvestigatorState:
    return InvestigatorState(case_id="INC-TEST-1", tenant_id="t-1")


def test_stable_hash_is_deterministic_across_dict_orderings() -> None:
    a = {"alpha": 1, "beta": [2, 3], "gamma": {"k": "v"}}
    b = {"gamma": {"k": "v"}, "beta": [2, 3], "alpha": 1}
    assert _stable_hash(a) == _stable_hash(b)
    # Different payloads must hash differently
    assert _stable_hash(a) != _stable_hash({"alpha": 2})


def test_log_llm_prompt_records_hash_and_metadata() -> None:
    state = _make_state()
    prompt = "Classify this alert: brute-force on user@example.com"
    h = state.log_llm_prompt(agent="recon", prompt=prompt, model="gpt-4o-mini", purpose="recon-extract")
    assert len(state.audit_log) == 1
    entry = state.audit_log[0]
    assert isinstance(entry, AuditEntry)
    assert entry.kind is StepKind.LLM_PROMPT
    assert entry.agent == "recon"
    assert entry.input_hash == h
    assert entry.metadata["model"] == "gpt-4o-mini"
    assert entry.metadata["purpose"] == "recon-extract"
    assert entry.metadata["prompt"].startswith("Classify this alert")


def test_log_llm_prompt_handles_message_lists() -> None:
    state = _make_state()
    messages = [
        {"role": "system", "content": "you are a SOC analyst"},
        {"role": "user", "content": "alert: failed login spike"},
    ]
    h = state.log_llm_prompt(agent="forensic", prompt=messages, model="gpt-4o-mini")
    entry = state.audit_log[-1]
    assert entry.input_hash == h
    assert entry.metadata["messages"] == messages
    # Same messages must produce the same hash
    state2 = _make_state()
    h2 = state2.log_llm_prompt(agent="forensic", prompt=messages, model="gpt-4o-mini")
    assert h == h2


def test_log_llm_response_links_to_prompt_via_hash() -> None:
    state = _make_state()
    prompt_hash = state.log_llm_prompt(agent="recon", prompt="hi", purpose="t")
    out_hash = state.log_llm_response(
        agent="recon",
        response="hello back",
        prompt_hash=prompt_hash,
        model="gpt-4o-mini",
        tokens_used=42,
        latency_ms=137,
        cost_usd=0.0001,
    )
    assert len(state.audit_log) == 2
    resp = state.audit_log[-1]
    assert resp.kind is StepKind.LLM_RESPONSE
    assert resp.input_hash == prompt_hash
    assert resp.output_hash == out_hash
    assert resp.duration_ms == 137
    assert resp.metadata["tokens_used"] == 42
    assert resp.metadata["cost_usd"] == 0.0001
    assert resp.metadata["prompt_hash"] == prompt_hash


def test_log_tool_call_captures_args_and_result() -> None:
    state = _make_state()
    state.log_tool_call(
        agent="recon",
        tool_name="enrich_ioc",
        args={"value": "1.2.3.4", "type": "ipv4"},
        result={"reputation": "malicious", "score": 92},
        latency_ms=23,
        success=True,
    )
    entry = state.audit_log[-1]
    assert entry.kind is StepKind.TOOL_CALL
    assert entry.metadata["tool"] == "enrich_ioc"
    assert entry.metadata["success"] is True
    assert entry.metadata["result"]["score"] == 92
    assert entry.input_hash and entry.output_hash
    assert entry.duration_ms == 23


def test_log_tool_call_marks_failures() -> None:
    state = _make_state()
    state.log_tool_call(
        agent="forensic",
        tool_name="kb_search",
        args={"q": "lateral movement"},
        result=None,
        success=False,
    )
    entry = state.audit_log[-1]
    assert entry.metadata["success"] is False
    assert "[FAILED]" in entry.summary
    assert entry.output_hash is None


def test_log_evidence_records_citation_with_weight() -> None:
    state = _make_state()
    state.log_evidence(
        agent="recon",
        evidence_kind="mitre_technique",
        ref="T1110.001",
        weight=0.8,
        details={"tactic": "Credential Access"},
    )
    entry = state.audit_log[-1]
    assert entry.kind is StepKind.EVIDENCE_CITED
    assert entry.summary == "mitre_technique: T1110.001"
    assert entry.metadata["weight"] == 0.8
    assert entry.metadata["tactic"] == "Credential Access"
    assert entry.output_hash is not None


def test_log_decision_records_reason_and_confidence() -> None:
    state = _make_state()
    state.log_decision(
        agent="responder",
        decision="risk=high",
        reason="3 IOCs match active campaign + lateral movement detected",
        confidence=0.87,
        alternatives=["risk=medium", "risk=critical"],
    )
    entry = state.audit_log[-1]
    assert entry.kind is StepKind.DECISION_REASON
    assert entry.metadata["decision"] == "risk=high"
    assert entry.metadata["confidence"] == 0.87
    assert "lateral movement" in entry.metadata["reason"]
    assert entry.metadata["alternatives"] == ["risk=medium", "risk=critical"]


def test_audit_log_is_append_only_and_ordered() -> None:
    state = _make_state()
    state.log(StepKind.RECON, "recon", "started")
    state.log_llm_prompt(agent="recon", prompt="x")
    state.log_llm_response(agent="recon", response="y")
    state.log_evidence(agent="recon", evidence_kind="ioc", ref="1.2.3.4")
    state.log_decision(agent="recon", decision="enrich", reason="ip seen")
    kinds = [e.kind for e in state.audit_log]
    assert kinds == [
        StepKind.RECON,
        StepKind.LLM_PROMPT,
        StepKind.LLM_RESPONSE,
        StepKind.EVIDENCE_CITED,
        StepKind.DECISION_REASON,
    ]
