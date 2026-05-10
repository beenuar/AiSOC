"""
MITRE ATT&CK-based Attack Reasoning Engine (v0)
================================================

A LangGraph multi-agent pipeline that, given a list of observed indicators,
walks them through five stages and produces a structured analysis:

    1. TechniqueAnalyzer   - keyword search against the loaded MITRE corpus
    2. PathPredictor       - hardcoded next-technique heuristics
    3. MitigationAdvisor   - pulls mitigations from the loaded corpus for
                             every identified/predicted technique
    4. ActorProfiler       - small hardcoded technique->actor map plus the
                             real MITRE actor lookup for found IDs
    5. TacticalAdvisor     - kill-chain phase, mitigation, and high-confidence
                             actor recommendations (deterministic order)

Honest v0 status
----------------
Path prediction and the technique->actor map are intentionally small,
hardcoded tables - they are seeded heuristics, not learned models. They
are gated behind clear `# v0 STUB` markers and called out in
`docs/attack_reasoning_developer_guide.md`. Replacing them with real
ATT&CK relationship traversal (already loaded by `mitre_full`) is the
intended next step.

AiSOC - open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import structlog
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field

from app.tools.mitre_full import (
    get_actor,
    get_technique,
    map_techniques_to_kill_chain,
    search_techniques_by_name,
)

logger = structlog.get_logger(__name__)


# --- State -----------------------------------------------------------------


class AttackReasoningState(BaseModel):
    """State carried through the LangGraph attack-reasoning workflow."""

    incident_id: Optional[str] = None
    observed_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    identified_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    predicted_techniques: List[Dict[str, Any]] = Field(default_factory=list)
    kill_chain_analysis: Dict[str, List[str]] = Field(default_factory=dict)
    threat_actors: List[Dict[str, Any]] = Field(default_factory=list)
    mitigations: List[Dict[str, Any]] = Field(default_factory=list)
    tactical_recommendations: List[str] = Field(default_factory=list)
    confidence_scores: Dict[str, float] = Field(default_factory=dict)
    status: str = "running"


# --- v0 STUB tables (intentionally small, swap for real traversal) --------

# Hardcoded next-technique progression. Real implementation should walk
# ATT&CK relationship objects loaded by `mitre_full`.
_PROGRESSION_MAP: Dict[str, List[Dict[str, str]]] = {
    "T1566": [  # Phishing
        {"id": "T1059", "reason": "execution commonly follows phishing payload delivery"},
        {"id": "T1078", "reason": "valid accounts often gained via phishing"},
    ],
    "T1059": [  # Command and Scripting Interpreter
        {"id": "T1071", "reason": "C2 communication commonly follows execution"},
        {"id": "T1003", "reason": "credential dumping often follows execution"},
    ],
    "T1078": [  # Valid Accounts
        {"id": "T1003", "reason": "credential access often follows valid-account abuse"},
        {"id": "T1021", "reason": "lateral movement often follows valid-account abuse"},
    ],
    "T1003": [  # OS Credential Dumping
        {"id": "T1021", "reason": "lateral movement commonly follows credential dumping"},
        {"id": "T1041", "reason": "exfiltration commonly follows credential dumping"},
    ],
}

# Hardcoded technique->actor seed map. Real implementation should query
# `mitre_full._actors` (loaded from STIX) for actors that use a technique.
_TECHNIQUE_ACTOR_HINT: Dict[str, List[str]] = {
    "T1059": ["G0016"],  # APT29
    "T1566": ["G0050"],  # APT32
    "T1078": ["G0007"],  # APT28
    "T1003": ["G0009"],  # Deep Panda
}


def predict_next_techniques(observed_technique_ids: List[str]) -> List[Dict[str, Any]]:
    """Return predicted next-techniques for a list of observed technique IDs.

    Single source of truth used by both the LangGraph PathPredictor and
    the REST `/predict-next-techniques` endpoint.
    """
    seen: set[str] = set()
    out: List[Dict[str, Any]] = []
    for tid in observed_technique_ids:
        for entry in _PROGRESSION_MAP.get(tid, []):
            pid = entry["id"]
            if pid in seen:
                continue
            tech = get_technique(pid)
            out.append(
                {
                    "id": pid,
                    "name": tech.get("name", "Unknown") if tech.get("found") else "Unknown",
                    "from_technique": tid,
                    "reason": entry["reason"],
                    "confidence": 0.6,
                }
            )
            seen.add(pid)
    return out


# --- Agents ----------------------------------------------------------------


class TechniqueAnalyzer:
    """Map observed indicators to MITRE ATT&CK techniques via keyword search."""

    async def analyze_indicators(self, state: AttackReasoningState) -> AttackReasoningState:
        identified: List[Dict[str, Any]] = []
        confidence: Dict[str, float] = {}
        seen_ids: set[str] = set()

        for indicator in state.observed_indicators:
            # Free-text keyword search uses description / context fields.
            # Raw values like IPs/hashes are not searched against technique
            # names - that produces junk matches.
            terms: List[str] = []
            for key in ("description", "context", "name"):
                val = indicator.get(key)
                if isinstance(val, str) and val.strip():
                    terms.append(val.strip())
            if not terms:
                continue

            for term in terms:
                for tech in search_techniques_by_name(term, limit=3):
                    tid = tech.get("id")
                    if not tid or tid in seen_ids:
                        continue
                    identified.append(tech)
                    seen_ids.add(tid)
                    # Light confidence heuristic: more tactic phases = stronger anchor
                    confidence[tid] = min(1.0, 0.6 + 0.1 * len(tech.get("tactic_names") or []))

        state.identified_techniques = identified
        state.confidence_scores.update(confidence)
        state.kill_chain_analysis = map_techniques_to_kill_chain(
            [t.get("id") for t in identified if t.get("id")]
        )
        logger.info(
            "technique_analysis_complete",
            techniques=len(identified),
            kill_chain_phases=list(state.kill_chain_analysis.keys()),
        )
        return state


class PathPredictor:
    """Predict likely next-techniques using the v0 progression map."""

    async def predict_paths(self, state: AttackReasoningState) -> AttackReasoningState:
        observed_ids = [t.get("id") for t in state.identified_techniques if t.get("id")]
        state.predicted_techniques = predict_next_techniques(observed_ids)
        logger.info("path_prediction_complete", predictions=len(state.predicted_techniques))
        return state


class MitigationAdvisor:
    """Look up MITRE mitigations for every identified/predicted technique."""

    async def recommend_mitigations(self, state: AttackReasoningState) -> AttackReasoningState:
        all_techniques = state.identified_techniques + state.predicted_techniques
        mitigations: List[Dict[str, Any]] = []
        for tech in all_techniques:
            tid = tech.get("id")
            if not tid:
                continue
            details = get_technique(tid)
            if not details.get("found"):
                continue
            for mitigation_name in details.get("mitigations") or []:
                mitigations.append(
                    {
                        "technique_id": tid,
                        "technique_name": details.get("name", "Unknown"),
                        "mitigation": mitigation_name,
                        "confidence": state.confidence_scores.get(tid, 0.5),
                    }
                )
        state.mitigations = mitigations
        logger.info("mitigation_advice_complete", mitigations=len(mitigations))
        return state


class ActorProfiler:
    """Score candidate actors using the v0 technique->actor seed map."""

    async def profile_actors(self, state: AttackReasoningState) -> AttackReasoningState:
        observed_ids = [t.get("id") for t in state.identified_techniques if t.get("id")]
        if not observed_ids:
            state.threat_actors = []
            return state

        actor_scores: Dict[str, int] = {}
        actor_matched_techs: Dict[str, set[str]] = {}
        for tid in observed_ids:
            for actor_id in _TECHNIQUE_ACTOR_HINT.get(tid, []):
                actor_scores[actor_id] = actor_scores.get(actor_id, 0) + 1
                actor_matched_techs.setdefault(actor_id, set()).add(tid)

        if not actor_scores:
            state.threat_actors = []
            logger.info("actor_profiling_complete", actors=0)
            return state

        max_score = max(actor_scores.values())
        threat_actors: List[Dict[str, Any]] = []
        for actor_id, score in sorted(actor_scores.items()):
            normalized = score / max_score
            if normalized < 0.3:
                continue
            details = get_actor(actor_id)
            if not details.get("found"):
                # Hint table referenced an actor not in the loaded corpus -
                # skip rather than fabricate a profile.
                continue
            threat_actors.append(
                {
                    **details,
                    "confidence": round(normalized, 3),
                    "matching_techniques": sorted(actor_matched_techs[actor_id]),
                }
            )
        state.threat_actors = threat_actors
        logger.info("actor_profiling_complete", actors=len(threat_actors))
        return state


class TacticalAdvisor:
    """Produce deterministic, deduplicated tactical recommendations."""

    async def provide_recommendations(self, state: AttackReasoningState) -> AttackReasoningState:
        recs: List[str] = []

        kill_chain_recs = {
            "Initial Access": "Strengthen perimeter defenses and monitor for unusual access patterns",
            "Execution": "Implement application allowlisting and monitor process creation",
            "Credential Access": "Enforce multi-factor authentication and credential hygiene",
            "Lateral Movement": "Segment network and monitor authentication logs for anomalous access",
            "Exfiltration": "Apply DLP controls and monitor outbound data volumes",
        }
        for phase, rec in kill_chain_recs.items():
            if phase in state.kill_chain_analysis:
                recs.append(rec)

        for mitigation in state.mitigations:
            mit_name = mitigation.get("mitigation", "")
            if "Multi-factor Authentication" in mit_name:
                recs.append("Implement strong multi-factor authentication for all accounts")
            elif "Antivirus" in mit_name:
                recs.append("Ensure antivirus signatures are up to date and enable real-time scanning")
            elif "Network Intrusion Prevention" in mit_name:
                recs.append("Deploy network intrusion prevention systems and monitor traffic")

        for actor in state.threat_actors:
            if actor.get("confidence", 0) > 0.7:
                recs.append(f"Increase monitoring for {actor.get('name', 'Unknown Actor')} TTPs and IOCs")

        # dict.fromkeys preserves insertion order while deduping (set does not)
        state.tactical_recommendations = list(dict.fromkeys(recs))
        state.status = "completed"
        logger.info("tactical_advice_complete", recommendations=len(state.tactical_recommendations))
        return state


# --- LangGraph wiring -----------------------------------------------------


async def _technique_analysis_node(state: dict) -> dict:
    return (await TechniqueAnalyzer().analyze_indicators(AttackReasoningState(**state))).model_dump()


async def _path_prediction_node(state: dict) -> dict:
    return (await PathPredictor().predict_paths(AttackReasoningState(**state))).model_dump()


async def _mitigation_advice_node(state: dict) -> dict:
    return (await MitigationAdvisor().recommend_mitigations(AttackReasoningState(**state))).model_dump()


async def _actor_profiling_node(state: dict) -> dict:
    return (await ActorProfiler().profile_actors(AttackReasoningState(**state))).model_dump()


async def _tactical_advice_node(state: dict) -> dict:
    return (await TacticalAdvisor().provide_recommendations(AttackReasoningState(**state))).model_dump()


def build_attack_reasoning_graph() -> Any:
    graph = StateGraph(dict)
    graph.add_node("technique_analysis", _technique_analysis_node)
    graph.add_node("path_prediction", _path_prediction_node)
    graph.add_node("mitigation_advice", _mitigation_advice_node)
    graph.add_node("actor_profiling", _actor_profiling_node)
    graph.add_node("tactical_advice", _tactical_advice_node)
    graph.set_entry_point("technique_analysis")
    graph.add_edge("technique_analysis", "path_prediction")
    graph.add_edge("path_prediction", "mitigation_advice")
    graph.add_edge("mitigation_advice", "actor_profiling")
    graph.add_edge("actor_profiling", "tactical_advice")
    graph.add_edge("tactical_advice", END)
    return graph.compile()


attack_reasoning_graph = build_attack_reasoning_graph()


async def reason_about_attack(
    incident_id: str,
    observed_indicators: List[Dict[str, Any]],
) -> AttackReasoningState:
    """Run the full reasoning workflow and return the final state.

    On any unhandled exception inside the graph, returns a state with
    `status="failed"` and a single tactical recommendation describing the
    failure - the caller is expected to surface this rather than crash.
    """
    logger.info("attack_reasoning_start", incident_id=incident_id, indicators=len(observed_indicators))
    initial = AttackReasoningState(incident_id=incident_id, observed_indicators=observed_indicators)
    try:
        result = await attack_reasoning_graph.ainvoke(initial.model_dump())
        final = AttackReasoningState(**result)
        logger.info("attack_reasoning_done", incident_id=incident_id, status=final.status)
        return final
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("attack_reasoning_failed", incident_id=incident_id)
        return AttackReasoningState(
            incident_id=incident_id,
            observed_indicators=observed_indicators,
            status="failed",
            tactical_recommendations=[f"Analysis failed: {exc}"],
        )
