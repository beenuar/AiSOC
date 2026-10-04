"""The investigator's analysis is scored against the evidence it was given.

What was missing
----------------
`score_groundedness` measures what fraction of the concrete indicators an
output asserts -- IPs, hashes, CVEs, techniques, domains -- actually appear in
the evidence. The gate around it was real, default-on and demoting, and it
existed in exactly one place: `workers/fused_alert_consumer.py`, the
background auto-triage path.

The investigator path had none. A verdict reached through
`POST /cases/{id}/investigate` -- launched deliberately by an analyst, read
carefully, most likely to be acted on -- was never checked, while the path
nobody watches was.

Why it had to wait for the payload
----------------------------------
The gate scores against `raw_alert`, and on this path `raw_alert` was `{}`:
the console sent the literal string `"Investigate alert: <title>"`. With no
evidence, `_extract` finds no indicators to support anything, so **every**
indicator the model mentions reads as unsupported and the gate demotes
unconditionally. That is not a cautious default -- it is a measurement of
nothing, reported as a finding about the model, and lowering the floor to
cope would have made it certify anything.

`test_no_evidence_is_not_scored` below is the test that pins the refusal.
"""

from __future__ import annotations

import pytest


def _state(*, raw_alert: dict | None = None, summary: str = "", hypothesis: str = "", confidence: float = 0.9):
    from app.investigator.state import ForensicFindings, InvestigatorState

    state = InvestigatorState(case_id="CASE-1", tenant_id="t")
    state.raw_alert = raw_alert if raw_alert is not None else {}
    state.alert_summary = summary
    state.forensic = ForensicFindings(
        root_cause_hypothesis=hypothesis,
        summary=hypothesis,
        confidence=confidence,
    )
    return state


class TestTheGateRefusesToScoreNothing:
    def test_no_evidence_is_not_scored(self) -> None:
        """The reason this could not be wired before the payload flowed.

        An empty evidence set makes every cited indicator unsupported, so a
        gate that scored anyway would demote every investigation on a
        hand-opened case -- and would look like it was catching hallucination.
        """
        from app.confidence import verdict_gate

        outcome = verdict_gate.evaluate(
            verdict="benign",
            confidence=0.9,
            reasoning="The host 10.1.2.3 contacted evil.example.com and dropped a1b2c3d4.",
            raw_alert={},
        )

        assert outcome.skipped, "scored against no evidence"
        assert outcome.score is None
        assert not outcome.demoted
        assert outcome.confidence == 0.9
        assert "no alert payload" in outcome.reason

    def test_an_unscored_run_reports_none_not_zero(self) -> None:
        """`0.0` would mean "scored, nothing supported". A case opened by hand
        has not been measured, and rendering that as a hard zero is the
        fabricated-metric failure in miniature."""
        from app.investigator.orchestrator import _apply_groundedness

        state = _state(raw_alert={}, hypothesis="Something involving 10.1.2.3.")

        _apply_groundedness(state)

        assert state.forensic.groundedness is None
        assert state.forensic.confidence == 0.9


class TestItScoresWhenThereIsEvidence:
    def test_a_grounded_analysis_keeps_its_confidence(self) -> None:
        from app.investigator.orchestrator import _apply_groundedness

        state = _state(
            raw_alert={
                "alerts": [
                    {
                        "raw_event": {
                            "src_ip": "10.1.2.3",
                            "dest_host": "evil.example.com",
                            "sha256": "a1b2c3d4",
                        }
                    }
                ]
            },
            hypothesis="Host 10.1.2.3 contacted evil.example.com and dropped a1b2c3d4.",
            confidence=0.88,
        )

        _apply_groundedness(state)

        assert state.forensic.groundedness is not None
        assert state.forensic.confidence == pytest.approx(0.88)
        assert "Groundedness" not in state.forensic.summary

    def test_an_invented_indicator_lowers_confidence_and_says_why(self) -> None:
        """The whole point. A confident analysis citing an address that
        appears nowhere in the evidence used to be persisted, reported and
        acted on with nothing recording that it was invented."""
        from app.investigator.orchestrator import _apply_groundedness

        state = _state(
            raw_alert={"alerts": [{"raw_event": {"src_ip": "10.1.2.3"}}]},
            hypothesis=("Host 203.0.113.77 beaconed to c2.invalid, dropped deadbeefcafe1234 and exploited CVE-2024-99999 via T1566.002."),
            confidence=0.95,
        )

        _apply_groundedness(state)

        assert state.forensic.groundedness is not None
        assert state.forensic.confidence < 0.95, "confidence was not reduced"
        assert "Groundedness" in state.forensic.summary
        assert "unverified" in state.forensic.summary

    def test_the_caveat_names_the_unsupported_indicators(self) -> None:
        """A bare score tells an analyst something is wrong without saying
        what, which is the kind of warning people learn to scroll past."""
        from app.investigator.orchestrator import _apply_groundedness

        state = _state(
            raw_alert={"alerts": [{"raw_event": {"src_ip": "10.1.2.3"}}]},
            hypothesis="Traffic to 198.51.100.42 and 203.0.113.77 from an unknown binary.",
            confidence=0.9,
        )

        _apply_groundedness(state)

        assert "198.51.100.42" in state.forensic.summary or "203.0.113.77" in state.forensic.summary


class TestTheSwitchStillWorks:
    def test_the_gate_can_be_turned_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.confidence import verdict_gate

        monkeypatch.setenv("AISOC_AGENT_GROUNDEDNESS_GATE", "0")

        outcome = verdict_gate.evaluate(
            verdict="benign",
            confidence=0.9,
            reasoning="Entirely invented 203.0.113.77.",
            raw_alert={"src_ip": "10.1.2.3"},
        )

        assert outcome.skipped
        assert outcome.confidence == 0.9

    def test_an_escalating_verdict_is_left_alone(self) -> None:
        """Demoting something already routed to a human adds review load
        without reducing risk."""
        from app.confidence import verdict_gate

        outcome = verdict_gate.evaluate(
            verdict="true_positive",
            confidence=0.9,
            reasoning="Entirely invented 203.0.113.77.",
            raw_alert={"src_ip": "10.1.2.3"},
        )

        assert outcome.skipped
        assert outcome.verdict == "true_positive"


class TestItIsActuallyReachable:
    def test_the_orchestrator_calls_it(self) -> None:
        """The failure mode this whole plan item is about: a mechanism that
        exists, is tested, and has no caller on the path that needs it."""
        import inspect

        from app.investigator import orchestrator

        source = inspect.getsource(orchestrator.InvestigatorOrchestrator)
        module_source = inspect.getsource(orchestrator)

        assert "_apply_groundedness(" in module_source
        assert module_source.count("_apply_groundedness(") >= 2, "the gate is defined but never called — that is the defect, not the fix"
        assert source  # the class exists and was readable
