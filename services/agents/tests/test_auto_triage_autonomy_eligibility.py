"""The eligibility input must be on the triage path, not merely in the tree.

`test_autonomy_eligibility.py` proves the function decides correctly. It
cannot prove `run_auto_triage` consults it, and the recurring defect in this
repository is exactly a mechanism that exists, is unit-tested and has no
caller on the path that needs it — an earned `auto_close` grant sat with no
reader at all while the documentation described it as governing closure.

So these drive `run_auto_triage` with only the model substituted. The three
properties asserted are the three that make this an input rather than a
second policy: it is recorded on every closure, it can withhold one the
threshold allowed, and it can never grant one the threshold withheld.
"""

from __future__ import annotations

import json
from uuid import uuid4

import pytest

from app.agents import auto_triage_agent
from app.confidence import eligibility
from app.confidence.eligibility import PerformanceRecord
from app.models.state import AgentStatus, InvestigationState

CLEAN_ALERT = {
    "id": "alert-eligibility-1",
    "severity": "low",
    "risk_score": 0.1,
    "rule_id": "net-portscan-horizontal",
    "src_ip": "198.51.100.14",
    "ports_contacted": 1024,
}

#: A rationale that reasons from the telemetry and makes no decisive claim,
#: so the claim-support gate does not fire and this file measures one thing.
CLEAN_RATIONALE = "The rule counts distinct destination ports and this source contacted 1024 of them, which is the condition it was written for."


class _FixedReply:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload
        self.model_name = "measured-model-v1"

    async def ainvoke(self, _messages, **_kwargs):  # noqa: ANN001, ANN202
        class _Response:
            content = json.dumps(self._payload)

        return _Response()


@pytest.fixture
def pin_model(monkeypatch: pytest.MonkeyPatch):
    def _pin(payload: dict[str, object]) -> None:
        monkeypatch.setattr(auto_triage_agent, "make_chat_model", lambda *a, **k: _FixedReply(payload))

        async def _passthrough(llm, messages, **kwargs):  # noqa: ANN001, ANN202
            return await llm.ainvoke(messages, **kwargs)

        monkeypatch.setattr(auto_triage_agent, "safe_ainvoke", _passthrough)

    return _pin


def _state() -> InvestigationState:
    return InvestigationState(
        incident_id=uuid4(),
        tenant_id=uuid4(),
        alert_summary="Horizontal port scan from 198.51.100.14",
        raw_alert=dict(CLEAN_ALERT),
    )


def _closeable() -> dict[str, object]:
    return {"verdict": "false_positive", "confidence": 0.99, "rationale": CLEAN_RATIONALE}


async def test_the_eligibility_verdict_is_recorded_on_every_closure(pin_model) -> None:
    """Including — especially — when it is unmeasured.

    "Not measured" belongs in front of whoever reviews the closure. A silent
    unmeasured state is indistinguishable from a measured pass.
    """
    pin_model(_closeable())

    state = await auto_triage_agent.run_auto_triage(_state())

    basis = [b for b in state.confidence_basis if b.startswith("auto_closure_safety=")]
    assert basis, "the closure carries no record of whether autonomy was earned"
    assert "not measured" in basis[0]


async def test_unmeasured_does_not_block_by_default(pin_model) -> None:
    """Additive: a deployment that has measured nothing behaves as it did."""
    pin_model(_closeable())

    state = await auto_triage_agent.run_auto_triage(_state())

    assert state.status is AgentStatus.COMPLETED


async def test_the_strict_posture_withholds_a_closure_the_threshold_allowed(pin_model, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_AUTONOMY_REQUIRE_MEASURED", "1")
    pin_model(_closeable())

    state = await auto_triage_agent.run_auto_triage(_state())

    assert state.confidence == pytest.approx(0.99), "the model's confidence is unchanged; what changed is what it buys"
    assert state.status is not AgentStatus.COMPLETED
    assert any("Auto-close withheld" in f and "not measured" in f for f in state.findings)


async def test_a_measurement_below_the_floor_withholds_the_closure(pin_model, monkeypatch: pytest.MonkeyPatch) -> None:
    """A graded configuration that fell short blocks regardless of posture."""
    prompt = auto_triage_agent._triage_prompt()
    state = _state()
    row = PerformanceRecord.from_dict(
        {
            "model": "measured-model-v1",
            "prompt_name": "triage.system",
            "prompt_version": prompt.version,
            "prompt_sha256": prompt.sha256,
            "tenant_context": str(state.tenant_id),
            "alert_class": None,
            "samples": 500,
            "auto_close_precision": 0.62,
            "corpus_digest": "sha256:" + "0" * 64,
            "code_revision": "0" * 40,
            "measured_at": "2026-10-20T00:00:00+00:00",
            "measured_by": "test",
        }
    )
    monkeypatch.setattr(eligibility, "load_records", lambda: (row,))
    pin_model(_closeable())

    out = await auto_triage_agent.run_auto_triage(state)

    assert out.status is not AgentStatus.COMPLETED
    assert any("0.62" in f for f in out.findings)


async def test_a_clearing_measurement_closes_and_says_what_it_rested_on(pin_model, monkeypatch: pytest.MonkeyPatch) -> None:
    """The positive control. A gate stuck closed reads exactly like working caution."""
    prompt = auto_triage_agent._triage_prompt()
    state = _state()
    row = PerformanceRecord.from_dict(
        {
            "model": "measured-model-v1",
            "prompt_name": "triage.system",
            "prompt_version": prompt.version,
            "prompt_sha256": prompt.sha256,
            "tenant_context": str(state.tenant_id),
            "alert_class": None,
            "samples": 500,
            "auto_close_precision": 0.98,
            "corpus_digest": "sha256:" + "0" * 64,
            "code_revision": "0" * 40,
            "measured_at": "2026-10-20T00:00:00+00:00",
            "measured_by": "test",
        }
    )
    monkeypatch.setattr(eligibility, "load_records", lambda: (row,))
    monkeypatch.setenv("AISOC_AUTONOMY_REQUIRE_MEASURED", "1")
    pin_model(_closeable())

    out = await auto_triage_agent.run_auto_triage(state)

    assert out.status is AgentStatus.COMPLETED
    assert any("auto_closure_safety=0.980" in b for b in out.confidence_basis)


async def test_eligibility_never_grants_a_closure_the_verdict_withheld(pin_model, monkeypatch: pytest.MonkeyPatch) -> None:
    """It narrows only. A true positive stays escalated however well the model scored."""
    prompt = auto_triage_agent._triage_prompt()
    state = _state()
    row = PerformanceRecord.from_dict(
        {
            "model": "measured-model-v1",
            "prompt_name": "triage.system",
            "prompt_version": prompt.version,
            "prompt_sha256": prompt.sha256,
            "tenant_context": str(state.tenant_id),
            "alert_class": None,
            "samples": 5000,
            "auto_close_precision": 1.0,
            "corpus_digest": "sha256:" + "0" * 64,
            "code_revision": "0" * 40,
            "measured_at": "2026-10-20T00:00:00+00:00",
            "measured_by": "test",
        }
    )
    monkeypatch.setattr(eligibility, "load_records", lambda: (row,))
    pin_model({"verdict": "true_positive", "confidence": 0.99, "rationale": CLEAN_RATIONALE})

    out = await auto_triage_agent.run_auto_triage(state)

    assert out.status is not AgentStatus.COMPLETED


async def test_a_prompt_the_measurement_did_not_cover_is_unmeasured(pin_model, monkeypatch: pytest.MonkeyPatch) -> None:
    """A row pinned to another prompt hash must not authorise this one."""
    state = _state()
    row = PerformanceRecord.from_dict(
        {
            "model": "measured-model-v1",
            "prompt_name": "triage.system",
            "prompt_version": "1",
            "prompt_sha256": "f" * 64,
            "tenant_context": str(state.tenant_id),
            "alert_class": None,
            "samples": 5000,
            "auto_close_precision": 1.0,
            "corpus_digest": "sha256:" + "0" * 64,
            "code_revision": "0" * 40,
            "measured_at": "2026-10-20T00:00:00+00:00",
            "measured_by": "test",
        }
    )
    monkeypatch.setattr(eligibility, "load_records", lambda: (row,))
    monkeypatch.setenv("AISOC_AUTONOMY_REQUIRE_MEASURED", "1")
    pin_model(_closeable())

    out = await auto_triage_agent.run_auto_triage(state)

    assert out.status is not AgentStatus.COMPLETED
    assert any("not measured" in b for b in out.confidence_basis)
