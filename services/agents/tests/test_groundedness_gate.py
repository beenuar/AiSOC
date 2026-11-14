"""A verdict must not auto-close on reasoning the evidence does not support.

`score_groundedness` measures what fraction of the concrete indicators an
agent's output asserts — IPs, hashes, CVEs, MITRE techniques, domains — appear
in the evidence it was given. It shipped as an eval axis and had no caller
anywhere in the service.

So a confident "false positive" whose reasoning cited an IP that appeared
nowhere in the alert was persisted, written back as an institutional-memory
prior, and auto-closed, with nothing recording that the reasoning was invented.
That is the exact failure the honesty bar exists to prevent, and it was
measured only against synthetic eval fixtures.

These tests drive the gate through the triage worker, since the defect was
that nothing called the scorer on a live verdict.
"""

from __future__ import annotations

import uuid

import pytest
from app.models.state import AgentStatus, InvestigationState
from app.workers import fused_alert_consumer as consumer
from app.workers.fused_alert_consumer import FusedAlertTriageWorker

FALSE_POSITIVE = "false_positive"


@pytest.fixture(autouse=True)
def _gate_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("AISOC_AGENT_GROUNDEDNESS_GATE", raising=False)
    monkeypatch.delenv("AISOC_AGENT_GROUNDEDNESS_FLOOR", raising=False)


def _worker() -> FusedAlertTriageWorker:
    return FusedAlertTriageWorker(bootstrap_servers="localhost:9092")


def _state(findings: list[str], alert: dict | None = None) -> InvestigationState:
    return InvestigationState(
        run_id=uuid.uuid4(),
        incident_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        alert_summary="Outbound connection from WIN-DC01",
        raw_alert=alert if alert is not None else {"hostname": "WIN-DC01", "src_ip": "10.0.0.5"},
        findings=findings,
        status=AgentStatus.COMPLETED,
    )


# ── the regression ────────────────────────────────────────────────────────


def test_a_verdict_citing_an_ip_that_is_not_in_the_evidence_is_demoted():
    """The case that was silently auto-closing.

    The alert mentions 10.0.0.5. The reasoning confidently discusses
    203.0.113.77, which the agent was never given.
    """
    state = _state(["Traffic to 203.0.113.77 is a known benign CDN egress, closing."])
    verdict, confidence = _worker()._apply_groundedness_gate(state, FALSE_POSITIVE, 0.97)
    assert verdict == "needs_review"
    assert state.status is not AgentStatus.COMPLETED
    assert state.groundedness is not None and state.groundedness < 0.75


def test_a_grounded_verdict_is_left_alone():
    state = _state(["Traffic from 10.0.0.5 matches the documented backup window."])
    verdict, confidence = _worker()._apply_groundedness_gate(state, FALSE_POSITIVE, 0.91)
    assert verdict == FALSE_POSITIVE
    assert confidence == 0.91
    assert state.groundedness == 1.0


def test_confidence_is_lowered_to_match_the_demoted_verdict():
    """A 0.97 confidence must not survive onto a verdict we no longer trust."""
    unseen_sha256 = "deadbeef" + "0" * 56  # 64 hex chars, absent from the alert
    state = _state([f"Hash {unseen_sha256} is a known-good signed binary."])
    _, confidence = _worker()._apply_groundedness_gate(state, FALSE_POSITIVE, 0.97)
    assert confidence < 0.97


def test_the_demotion_is_explained_in_the_findings():
    """An analyst reading the case must see why it was escalated."""
    state = _state(["Traffic to 203.0.113.77 is benign."])
    _worker()._apply_groundedness_gate(state, FALSE_POSITIVE, 0.95)
    assert any("demoted" in f.lower() for f in state.findings)
    assert any("203.0.113.77" in f for f in state.findings)


# ── scope ─────────────────────────────────────────────────────────────────


def test_an_escalating_verdict_is_not_gated():
    """A verdict already routed to a human is not making an unsupervised call.

    Demoting it would add review load without reducing risk.
    """
    state = _state(["Traffic to 203.0.113.77 indicates C2."])
    verdict, confidence = _worker()._apply_groundedness_gate(state, "true_positive", 0.88)
    assert verdict == "true_positive"
    assert confidence == 0.88


def test_reasoning_with_no_concrete_indicators_is_not_penalised():
    """Nothing checkable was asserted, so nothing can be hallucinated."""
    state = _state(["Matches the tenant's documented maintenance window."])
    verdict, _ = _worker()._apply_groundedness_gate(state, FALSE_POSITIVE, 0.9)
    assert verdict == FALSE_POSITIVE


def test_empty_reasoning_is_not_gated():
    state = _state([])
    verdict, _ = _worker()._apply_groundedness_gate(state, FALSE_POSITIVE, 0.9)
    assert verdict == FALSE_POSITIVE


def test_indicators_in_the_raw_event_payload_count_as_evidence():
    """Evidence is the whole alert the agent saw, not just its top fields."""
    state = _state(
        ["Connection to 198.51.100.9 matches the documented proxy."],
        alert={"hostname": "WIN-DC01", "raw_event": {"dest": "198.51.100.9"}},
    )
    verdict, _ = _worker()._apply_groundedness_gate(state, FALSE_POSITIVE, 0.9)
    assert verdict == FALSE_POSITIVE


# ── controls ──────────────────────────────────────────────────────────────


def test_the_gate_can_be_disabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AISOC_AGENT_GROUNDEDNESS_GATE", "0")
    state = _state(["Traffic to 203.0.113.77 is benign."])
    verdict, confidence = _worker()._apply_groundedness_gate(state, FALSE_POSITIVE, 0.95)
    assert verdict == FALSE_POSITIVE
    assert confidence == 0.95


def test_the_floor_is_configurable(monkeypatch: pytest.MonkeyPatch):
    """Half the indicators grounded passes a 0.4 floor and fails a 0.9 one."""
    findings = ["Traffic from 10.0.0.5 to 203.0.113.77 reviewed."]
    monkeypatch.setenv("AISOC_AGENT_GROUNDEDNESS_FLOOR", "0.4")
    assert _worker()._apply_groundedness_gate(_state(findings), FALSE_POSITIVE, 0.9)[0] == FALSE_POSITIVE
    monkeypatch.setenv("AISOC_AGENT_GROUNDEDNESS_FLOOR", "0.9")
    assert _worker()._apply_groundedness_gate(_state(findings), FALSE_POSITIVE, 0.9)[0] == "needs_review"


def test_a_scoring_failure_never_changes_the_verdict(monkeypatch: pytest.MonkeyPatch):
    """The verdict is the product. A broken scorer must not rewrite it."""

    def _boom(*a, **k):  # noqa: ANN002, ANN003
        raise RuntimeError("scorer exploded")

    monkeypatch.setattr(consumer, "score_groundedness", _boom)
    state = _state(["Traffic to 203.0.113.77 is benign."])
    verdict, confidence = _worker()._apply_groundedness_gate(state, FALSE_POSITIVE, 0.95)
    assert verdict == FALSE_POSITIVE
    assert confidence == 0.95
