"""Iterative hypothesis-tree ``HunterAgent`` (todo ``t2b-hunter``).

The Hunter takes a free-form hypothesis ("we may have stealer logs in
darkweb forums", "WIN-DC01 looks beaconing") and explores it by walking
a tree of related hypotheses, pivoting through CTI / SIEM / EDR tools
until it can either support, refute, or mark inconclusive. The heavy
lifting is delegated to :class:`HypothesisTreeExplorer` so the agent
itself stays a thin tenancy-and-auditing shell.

What this agent guarantees:

* Every tool call is dispatched through :meth:`BaseAgent.call_tool`,
  which means tenancy enforcement, HITL gating, prompt-injection
  defense, and audit logging all apply uniformly. The Hunter never
  fabricates a tool result.
* The trace surface is rich: a ``DECISION`` row when the hunt starts
  (with the classified category), and a ``DECISION`` row at the end
  with the verdict, evidence counts, and pivoted IOCs. The Investigator
  can replay the hunt from these rows alone.
* The return type (:class:`HuntResult`) matches the contract the API
  layer and UI already consume — no caller changes are required to pick
  up the iterative explorer.
"""
from __future__ import annotations

from typing import Optional

from sqlmodel import Session

from app.agents.base import BaseAgent
from app.agents.hunter.explorer import ExplorerBudget, HypothesisTreeExplorer
from app.agents.hunter.models import (
    HuntResult,
    HypothesisNode,
    HypothesisStatus,
    HypothesisVerdict,
)
from app.agents.hunter.tools import BaseAgentToolCaller, HunterToolCaller
from app.models.trace import AgentName, TraceStep


# The Hunter only needs read tools. The allowlist is enforced inside
# ``BaseAgent.call_tool`` and is what keeps a compromised classifier
# from accidentally invoking, say, ``edr.isolate_host``.
_HUNTER_READ_TOOLS: list[str] = [
    "cti.enrich_ioc",
    "cti.darkweb_search",
    "cti.brand_intel",
    "cti.asm_lookup",
    "cti.vuln_intel",
    "siem.search_events",
    "siem.get_related_alerts",
    "edr.get_process_tree",
]


class HunterAgent(BaseAgent):
    """Proactive threat hunter — iterative hypothesis-tree explorer."""

    name = AgentName.HUNTER
    role = "Proactive threat hunter (iterative hypothesis-tree explorer)"
    allowed_tools: list[str] = list(_HUNTER_READ_TOOLS)

    def __init__(
        self,
        db: Session,
        case_id: int,
        tenant_id: str,
        *,
        tool_caller: Optional[HunterToolCaller] = None,
        budget: Optional[ExplorerBudget] = None,
    ) -> None:
        """Construct a Hunter for a single case.

        ``tool_caller`` and ``budget`` are injectable so tests can pass a
        :class:`FakeToolCaller` and tighter budgets without touching the
        production wiring. By default the Hunter wraps itself as the
        tool caller — that keeps tenancy, HITL, and audit all in band.
        """
        super().__init__(db, case_id, tenant_id)
        self._tool_caller = tool_caller or BaseAgentToolCaller(self)
        self._budget = budget or ExplorerBudget()

    async def run_hypothesis(self, hypothesis: str) -> HuntResult:
        """Explore ``hypothesis`` and return the structured result.

        The trace bookends (start / end) are written to the case
        timeline so the analyst sees the hunt as a discrete event. The
        explorer's per-node evidence stays inside the returned
        :class:`HuntResult`; persisting the tree itself to a richer
        store is tracked under a follow-up todo so we don't bloat the
        trace table.
        """
        statement = (hypothesis or "").strip() or "(empty hypothesis)"

        self.trace(
            TraceStep.DECISION,
            summary=f"Hunt started: {statement[:120]}",
            detail={
                "hypothesis": statement,
                "tenant_id": self.tenant_id,
                "budget": {
                    "max_nodes": self._budget.max_nodes,
                    "max_tool_calls": self._budget.max_tool_calls,
                    "max_depth": self._budget.max_depth,
                    "retro_enabled": self._budget.retro_enabled,
                    "retro_window_days": self._budget.retro_window_days,
                },
            },
        )

        explorer = HypothesisTreeExplorer(self._tool_caller, self._budget)
        result = await explorer.explore(statement)

        self.trace(
            TraceStep.DECISION,
            summary=(
                f"Hunt finished: verdict={result.verdict.value} "
                f"nodes_explored={result.nodes_explored} "
                f"tool_calls={result.tool_calls} "
                f"retro_calls={result.retro_calls}"
            ),
            detail={
                "verdict": result.verdict.value,
                "summary": result.summary,
                "follow_ups": list(result.follow_ups),
                "iocs_pivoted": list(result.iocs_pivoted),
                "root_category": result.root.category.value,
                "tree": _node_to_dict(result.root),
            },
        )

        return result


# ── Serialization helpers ───────────────────────────────────────────────


def _node_to_dict(node: HypothesisNode) -> dict:
    """Lightweight JSON-friendly snapshot of a hypothesis tree.

    Lives next to the agent rather than on the dataclass so the model
    file stays a pure data contract. The shape mirrors the dataclass so
    a UI client can render it without an additional schema.
    """
    return {
        "node_id": node.node_id,
        "statement": node.statement,
        "category": node.category.value,
        "status": node.status.value,
        "verdict": node.verdict.value,
        "confidence": node.confidence,
        "depth": node.depth,
        "parent_id": node.parent_id,
        "suggested_tools": list(node.suggested_tools),
        "seed_params": dict(node.seed_params),
        "notes": list(node.notes),
        "evidence": [
            {
                "tool": ev.tool,
                "summary": ev.summary,
                "weight": ev.weight,
                "retro": ev.retro,
                "tool_params": dict(ev.tool_params),
                # We deliberately do NOT include the full payload here —
                # it can be large and is already on disk via the tool
                # audit table. The summary + weight tell the analyst
                # everything they need to decide whether to drill in.
            }
            for ev in node.evidence
        ],
        "children": [_node_to_dict(child) for child in node.children],
    }


# Re-export so callers can ``from app.agents.hunter.agent import …``.
__all__ = [
    "HunterAgent",
    "HypothesisStatus",
    "HypothesisVerdict",
]
