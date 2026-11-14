"""A truncated forensic reply must become INCONCLUSIVE, never findings (#1873).

The live incident that forced this: a reply cut at ``max_tokens`` still
parsed as JSON — the greedy ``\\{[\\s\\S]*\\}`` span glued whatever survived
into a matchable blob — and the fragment flowed into the report verbatim,
fabricating a kernel-rootkit narrative about the reporting deployment's own
SOC host. The platform's standing rule is that a fallback which invents
evidence is worse than one that says it cannot answer, so a reply that ran
to the token ceiling is an *incomplete investigation*, marked as such.

These tests drive the real ``_llm_forensic`` with only the model factory and
``safe_ainvoke`` stubbed, so the gate, the extraction and the logging under
test are the production ones.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.investigator import forensic_agent
from app.investigator.state import InvestigatorState, StepKind


class _Reply:
    """The slice of a langchain AIMessage the agent reads."""

    def __init__(self, content: str, finish_reason: str | None = None) -> None:
        self.content = content
        self.response_metadata: dict[str, Any] = {}
        if finish_reason is not None:
            self.response_metadata["finish_reason"] = finish_reason
        self.usage_metadata = {"output_tokens": 4096}


def _state() -> InvestigatorState:
    state = InvestigatorState(case_id="CASE-TRUNC", tenant_id="t")
    state.raw_alert = {"alerts": [{"id": "a1"}]}
    state.alert_summary = "summary"
    return state


@pytest.fixture(autouse=True)
def _stub_model(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(forensic_agent, "make_chat_model", MagicMock(return_value=object()))
    monkeypatch.setattr(forensic_agent, "resolve_model_alias", MagicMock(return_value="test-model"))
    monkeypatch.setattr(forensic_agent, "record_llm_call", MagicMock(return_value=None))
    yield


@pytest.mark.asyncio
async def test_a_reply_cut_at_the_ceiling_is_inconclusive_not_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    truncated = '{"timeline": [{"t": "fabricated"}], "root_cause_hypothesis": "kernel rootkit on'
    monkeypatch.setattr(forensic_agent, "safe_ainvoke", AsyncMock(return_value=_Reply(truncated, finish_reason="length")))

    state = _state()
    out = await forensic_agent._llm_forensic(state)

    assert "INCONCLUSIVE" in out["root_cause_hypothesis"]
    assert out["timeline"] == [] and out["artefacts"] == []
    assert "rootkit" not in json.dumps(out), "truncated narrative leaked into the findings"
    kinds = [entry.kind for entry in state.audit_log]
    assert StepKind.ERROR in kinds, "the suppression must be visible in the audit log"
    # The truncated fragment must not be recorded as a model *response*
    # narrative either — suppression means suppression.
    assert all("rootkit" not in (entry.summary or "") for entry in state.audit_log)


@pytest.mark.asyncio
async def test_a_complete_reply_still_parses(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {"timeline": [], "artefacts": [], "root_cause_hypothesis": "benign", "blast_radius": "none", "confidence": 0.8, "summary": "ok"}
    monkeypatch.setattr(forensic_agent, "safe_ainvoke", AsyncMock(return_value=_Reply(json.dumps(body), finish_reason="stop")))

    out = await forensic_agent._llm_forensic(_state())
    assert out["root_cause_hypothesis"] == "benign"


@pytest.mark.asyncio
async def test_prose_after_the_json_defers_to_manual(monkeypatch: pytest.MonkeyPatch) -> None:
    """The extraction is anchored at the end: a runaway reply that keeps
    talking after its JSON is not laundered into structured findings."""
    rambling = '{"root_cause_hypothesis": "x"} and then the model kept going with prose'
    monkeypatch.setattr(forensic_agent, "safe_ainvoke", AsyncMock(return_value=_Reply(rambling, finish_reason="stop")))

    out = await forensic_agent._llm_forensic(_state())
    # Falls through to the deterministic/manual path rather than returning
    # the glued blob. The deterministic fallback's shape varies; the pin is
    # that the prose reply's content did not come back as parsed findings.
    assert out.get("root_cause_hypothesis") != "x"
