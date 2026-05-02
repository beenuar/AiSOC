"""
LangGraph workflow: wires Triage → Enrichment → Investigation agents.
Uses a simple sequential StateGraph (can be extended with conditional edges).
"""
from __future__ import annotations

import structlog
from langgraph.graph import END, StateGraph

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


def _should_continue(state: dict) -> str:
    """Conditional edge: stop if max iterations reached or status is terminal."""
    s = _from_dict(state)
    if s.iteration_count >= s.max_iterations:
        return "end"
    if s.status in (AgentStatus.COMPLETED, AgentStatus.FAILED, AgentStatus.CANCELLED):
        return "end"
    return "continue"


def build_investigation_graph() -> StateGraph:
    """Build and compile the investigation workflow graph."""
    graph = StateGraph(dict)

    graph.add_node("triage", triage_node)
    graph.add_node("enrichment", enrichment_node)
    graph.add_node("investigation", investigation_node)

    graph.set_entry_point("triage")
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", END)

    return graph.compile()


# Module-level compiled graph (singleton)
investigation_graph = build_investigation_graph()
