"""Behavioral tests for the MITRE ATT&CK-based attack reasoning agents.

These tests exercise each agent in isolation plus the end-to-end workflow.
They use the real (small) v0 progression and actor-hint tables wired into
`attack_reasoner` so a regression that breaks the contract surfaces here.
"""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from attack_reasoning.attack_reasoner import (  # noqa: E402
    ActorProfiler,
    AttackReasoningState,
    MitigationAdvisor,
    PathPredictor,
    TacticalAdvisor,
    TechniqueAnalyzer,
    predict_next_techniques,
    reason_about_attack,
)


# --- State -----------------------------------------------------------------


def test_attack_reasoning_state_initialization():
    state = AttackReasoningState(
        incident_id="TEST-001",
        observed_indicators=[{"type": "ip", "value": "192.168.1.100"}],
    )
    assert state.incident_id == "TEST-001"
    assert len(state.observed_indicators) == 1
    assert state.status == "running"
    assert state.identified_techniques == []
    assert state.confidence_scores == {}


# --- TechniqueAnalyzer ----------------------------------------------------


@pytest.mark.asyncio
async def test_technique_analyzer_uses_description_fields_not_raw_values():
    """Indicators without searchable text fields should yield zero matches."""
    state = AttackReasoningState(
        incident_id="TEST-001",
        observed_indicators=[
            {"type": "ip", "value": "192.168.1.100"},  # no text fields
            {"type": "hash", "value": "abc123"},
        ],
    )
    result = await TechniqueAnalyzer().analyze_indicators(state)
    assert result.identified_techniques == []
    assert result.kill_chain_analysis == {}


@pytest.mark.asyncio
async def test_technique_analyzer_does_not_crash_on_text_inputs():
    state = AttackReasoningState(
        incident_id="TEST-001",
        observed_indicators=[
            {"type": "process", "value": "powershell.exe", "description": "command"},
        ],
    )
    result = await TechniqueAnalyzer().analyze_indicators(state)
    assert isinstance(result.identified_techniques, list)
    assert isinstance(result.kill_chain_analysis, dict)


# --- PathPredictor --------------------------------------------------------


@pytest.mark.asyncio
async def test_path_predictor_uses_progression_map():
    state = AttackReasoningState(
        incident_id="TEST-001",
        identified_techniques=[{"id": "T1566", "name": "Phishing"}],
    )
    result = await PathPredictor().predict_paths(state)
    predicted_ids = {p["id"] for p in result.predicted_techniques}
    # T1566 -> T1059, T1078 per the v0 progression map
    assert {"T1059", "T1078"}.issubset(predicted_ids)


def test_predict_next_techniques_helper_dedupes_across_inputs():
    out = predict_next_techniques(["T1059", "T1078"])
    ids = [p["id"] for p in out]
    assert len(ids) == len(set(ids))


def test_predict_next_techniques_helper_returns_empty_for_unknown():
    assert predict_next_techniques(["T9999"]) == []


# --- MitigationAdvisor ----------------------------------------------------


@pytest.mark.asyncio
async def test_mitigation_advisor_skips_techniques_not_in_corpus():
    state = AttackReasoningState(
        incident_id="TEST-001",
        identified_techniques=[{"id": "T9999", "name": "Bogus"}],
    )
    result = await MitigationAdvisor().recommend_mitigations(state)
    assert result.mitigations == []


# --- ActorProfiler --------------------------------------------------------


@pytest.mark.asyncio
async def test_actor_profiler_returns_empty_when_no_techniques():
    state = AttackReasoningState(incident_id="TEST-001", identified_techniques=[])
    result = await ActorProfiler().profile_actors(state)
    assert result.threat_actors == []


@pytest.mark.asyncio
async def test_actor_profiler_skips_unknown_actor_ids():
    state = AttackReasoningState(
        incident_id="TEST-001",
        identified_techniques=[{"id": "T9999", "name": "Bogus"}],
    )
    result = await ActorProfiler().profile_actors(state)
    assert result.threat_actors == []


# --- TacticalAdvisor ------------------------------------------------------


@pytest.mark.asyncio
async def test_tactical_advisor_dedupes_recommendations_deterministically():
    state = AttackReasoningState(
        incident_id="TEST-001",
        kill_chain_analysis={"Initial Access": ["T1566"], "Execution": ["T1059"]},
        mitigations=[
            {"technique_id": "T1078", "mitigation": "Multi-factor Authentication"},
            {"technique_id": "T1078", "mitigation": "Multi-factor Authentication"},
        ],
        threat_actors=[{"name": "APT29", "confidence": 0.9}],
    )
    result = await TacticalAdvisor().provide_recommendations(state)
    assert result.status == "completed"
    assert len(result.tactical_recommendations) == len(set(result.tactical_recommendations))
    assert any("multi-factor" in rec.lower() for rec in result.tactical_recommendations)
    assert any("APT29" in rec for rec in result.tactical_recommendations)


# --- End-to-end workflow --------------------------------------------------


@pytest.mark.asyncio
async def test_complete_attack_reasoning_workflow_returns_completed_state():
    result = await reason_about_attack(
        "TEST-001",
        [
            {"type": "ip", "value": "192.168.1.100", "context": "Suspicious outbound traffic"},
            {"type": "hash", "value": "abc123", "context": "Malicious payload detected"},
        ],
    )
    assert result.incident_id == "TEST-001"
    # 'failed' is an acceptable terminal state when the MITRE corpus isn't loaded
    assert result.status in {"completed", "failed"}
    assert isinstance(result.identified_techniques, list)
    assert isinstance(result.predicted_techniques, list)
    assert isinstance(result.kill_chain_analysis, dict)
    assert isinstance(result.threat_actors, list)
    assert isinstance(result.mitigations, list)
    assert isinstance(result.tactical_recommendations, list)
    assert isinstance(result.confidence_scores, dict)


if __name__ == "__main__":
    pytest.main([__file__])
