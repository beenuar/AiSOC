"""
LangGraph workflow: wires Auto-Triage → Triage → Enrichment → Investigation
→ Attack-Path agents.

Auto-triage runs first.  If the LLM classifies the alert as FP/benign with
confidence above the auto-close threshold the graph terminates early.
Otherwise the alert flows through the full manual pipeline, ending with the
graph-aware Attack-Path agent that walks Neo4j to compute blast radius.
"""

from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

from app.agents.attack_path_agent import run_attack_path
from app.agents.auto_triage_agent import AutoTriageError, run_auto_triage
from app.agents.enrichment_agent import run_enrichment
from app.agents.investigation_agent import run_investigation
from app.agents.triage_agent import run_triage
from app.models.state import AgentStatus, InvestigationState

logger = structlog.get_logger()


def _state_dict(state: InvestigationState) -> dict:
    return state.to_dict()


def _from_dict(d: dict) -> InvestigationState:
    return InvestigationState.model_validate(d)


# ---- Node wrappers (LangGraph uses dict state, we wrap our Pydantic model) ----


async def auto_triage_node(state: dict) -> dict:
    s = _from_dict(state)
    try:
        s = await run_auto_triage(s)
    except AutoTriageError as exc:
        # LLM/parse failure (issue #571): never terminate on a null verdict —
        # escalate through the full pipeline (deterministic triage runs next).
        logger.warning("graph.auto_triage_failed_escalating", error=str(exc), incident_id=str(s.incident_id))
        s.add_finding(f"Auto-triage LLM unavailable ({exc}) — escalating to full pipeline")
        if s.status is AgentStatus.COMPLETED:
            s.status = AgentStatus.RUNNING
    return s.to_dict()


async def triage_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_triage(s)
    return s.to_dict()


async def enrichment_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_enrichment(s)
    return s.to_dict()


async def investigation_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_investigation(s)
    return s.to_dict()


async def attack_path_node(state: dict) -> dict:
    s = _from_dict(state)
    s = await run_attack_path(s)
    return s.to_dict()


def _should_continue(state: dict) -> str:
    """Conditional edge: stop if max iterations reached or status is terminal."""
    s = _from_dict(state)
    if s.iteration_count >= s.max_iterations:
        return "end"
    if s.status in (AgentStatus.COMPLETED, AgentStatus.FAILED, AgentStatus.CANCELLED):
        return "end"
    return "continue"


def _after_auto_triage(state: dict) -> str:
    """Route after auto-triage: auto-closed alerts go to END, others continue."""
    s = _from_dict(state)
    if s.status == AgentStatus.COMPLETED:
        return "end"
    return "continue"


def build_investigation_graph() -> StateGraph:
    """Build and compile the investigation workflow graph.

    Flow:
        auto_triage ─┬─ (high-confidence FP/benign) ──► END
                      └─ (else) ──► triage ──► enrichment ──► investigation
                                          ──► attack_path ──► END
    """
    graph = StateGraph(dict)

    graph.add_node("auto_triage", auto_triage_node)
    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("attack_path", attack_path_node)

    graph.set_entry_point("auto_triage")

    graph.add_conditional_edges(
        "auto_triage",
        _after_auto_triage,
        {"end": END, "continue": "triage"},
    )
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", "attack_path")
    graph.add_edge("attack_path", END)

    return graph.compile()


def build_escalation_graph() -> StateGraph:
    """The post-triage escalation pipeline (issue #569).

    Shares the SAME node implementations as the full graph but skips the
    auto-triage entry node — used by the Kafka auto-triage worker, which has
    already produced a governed verdict, to route escalated alerts (TP /
    low-confidence / needs_review) through enrichment → investigation →
    attack-path without re-triaging.

    Flow: triage ──► enrichment ──► investigation ──► attack_path ──► END
    """
    graph = StateGraph(dict)
    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("investigation", investigation_node)
    graph.add_node("attack_path", attack_path_node)
    graph.set_entry_point("triage")
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", "attack_path")
    graph.add_edge("attack_path", END)
    return graph.compile()


# Module-level compiled graphs (singletons)
investigation_graph = build_investigation_graph()
escalation_graph = build_escalation_graph()
