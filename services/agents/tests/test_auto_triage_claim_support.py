"""The triage path must withhold a closure whose decisive claim traces to nothing.

Testing `score_claim_support` directly proves the function works. It cannot
prove `run_auto_triage` calls it, and this repository's recurring defect is
exactly that: a mechanism that exists, is unit-tested, and has no caller on
the path that needs it.

So these drive `run_auto_triage` itself, with the model replaced and nothing
else. The alert, the prompt build, the parser, the metrics, the closure policy
and the three existing demotions are all the production ones. The model is
substituted because the rationale is the *input* to the behaviour under test —
asking a real model to produce a specific unsupported claim would make the
test measure the model.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest
from app.agents import auto_triage_agent
from app.models.state import AgentStatus, InvestigationState

#: An alert whose evidence carries the IP the rationale will cite and no
#: authorization of any kind. Severity and risk score are low so the
#: deterministic parts of the path have no reason to escalate on their own.
SCAN_ALERT = {
    "id": "alert-portscan-1",
    "severity": "low",
    "risk_score": 0.2,
    "rule_id": "net-portscan-horizontal",
    "src_ip": "198.51.100.14",
    "dst_ip": "203.0.113.7",
    "ports_contacted": 1024,
}


class _FixedReply:
    """A chat model that returns one prepared verdict. No network, no provider."""

    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload
        self.model_name = "test-fixed-reply"

    async def ainvoke(self, _messages, **_kwargs):  # noqa: ANN001, ANN202
        class _Response:
            content = json.dumps(self._payload)

        return _Response()


@pytest.fixture
def pin_model(monkeypatch: pytest.MonkeyPatch):
    """Replace only the model. Everything else on the path stays production."""

    def _pin(payload: dict[str, object]) -> None:
        monkeypatch.setattr(auto_triage_agent, "make_chat_model", lambda *a, **k: _FixedReply(payload))

        async def _passthrough(llm, messages, **kwargs):  # noqa: ANN001, ANN202
            return await llm.ainvoke(messages, **kwargs)

        monkeypatch.setattr(auto_triage_agent, "safe_ainvoke", _passthrough)

    return _pin


def _state(alert: dict[str, object]) -> InvestigationState:
    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary="Horizontal port scan from 198.51.100.14",
        raw_alert=dict(alert),
    )


async def test_unsupported_authorization_claim_blocks_the_closure(pin_model) -> None:
    """High confidence, auto-closeable verdict, perfectly grounded indicators — and withheld."""
    pin_model(
        {
            "verdict": "benign_true_positive",
            "confidence": 0.97,
            "rationale": (
                "Traffic from 198.51.100.14 to 203.0.113.7 is our approved vulnerability scanner, authorized under change CHG0049112."
            ),
        }
    )

    state = await auto_triage_agent.run_auto_triage(_state(SCAN_ALERT))

    assert state.verdict == "benign_true_positive"
    assert state.confidence == pytest.approx(0.97)
    assert state.status is not AgentStatus.COMPLETED
    assert any("Auto-close blocked" in f and "CHG0049112" in f for f in state.findings)
    assert any(b.startswith("claim_support=") for b in state.confidence_basis)


async def test_an_evidenced_authorization_claim_still_closes(pin_model, authorized_closure_tenant) -> None:
    """The legitimate case. A check that refuses this is one somebody disables."""
    alert = {**SCAN_ALERT, "change_ticket": "CHG0049112", "approved_by": "security-engineering"}
    pin_model(
        {
            "verdict": "benign_true_positive",
            "confidence": 0.97,
            "rationale": "Traffic from 198.51.100.14 is authorized under change CHG0049112, approved by security-engineering.",
        }
    )

    state = await auto_triage_agent.run_auto_triage(_state(alert))

    assert state.status is AgentStatus.COMPLETED
    assert not any("Auto-close blocked" in f for f in state.findings)


async def test_a_rationale_making_no_decisive_claim_still_closes(pin_model, authorized_closure_tenant) -> None:
    """Not scored must not behave like a score of zero."""
    pin_model(
        {
            "verdict": "false_positive",
            "confidence": 0.95,
            "rationale": (
                "The rule counts distinct destination ports and this source contacted 1024 of them, "
                "which is the condition it was written for; the dst_ip 203.0.113.7 is the collector."
            ),
        }
    )

    state = await auto_triage_agent.run_auto_triage(_state(SCAN_ALERT))

    assert state.status is AgentStatus.COMPLETED


async def test_contradicted_claim_blocks_and_names_the_field(pin_model) -> None:
    alert = {**SCAN_ALERT, "approval_status": "revoked"}
    pin_model(
        {
            "verdict": "benign",
            "confidence": 0.99,
            "rationale": "This is approved activity under an existing change record.",
        }
    )

    state = await auto_triage_agent.run_auto_triage(_state(alert))

    assert state.status is not AgentStatus.COMPLETED
    assert any("approval_status" in f for f in state.findings)


async def test_the_block_is_counted_and_not_only_logged(pin_model) -> None:
    before = auto_triage_agent.get_metrics()["unsupported_decisive_claims"]
    pin_model(
        {
            "verdict": "benign",
            "confidence": 0.99,
            "rationale": "This ran inside the scheduled maintenance window and is routine.",
        }
    )

    await auto_triage_agent.run_auto_triage(_state(SCAN_ALERT))

    assert auto_triage_agent.get_metrics()["unsupported_decisive_claims"] == before + 1
