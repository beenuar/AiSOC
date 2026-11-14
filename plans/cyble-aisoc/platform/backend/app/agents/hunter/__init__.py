"""Hunter agent package.

Implements todo ``t2b-hunter``: the Hunter is an iterative
hypothesis-tree explorer with retro-hunt. The public surface is:

* :class:`HunterAgent` — a :class:`app.agents.base.BaseAgent` subclass
  that wires the explorer into the tenant-aware audit / HITL plumbing
  and records a ``DECISION`` trace row per hunt.
* :class:`HypothesisTreeExplorer` — the deterministic, LLM-free inner
  loop that walks a tree of :class:`HypothesisNode` objects, calls
  read-only tools through a :class:`HunterToolCaller`, runs a retro
  pass on telemetry categories, and pivots on IOCs discovered in
  evidence.
* Data contracts in :mod:`app.agents.hunter.models` (``HuntResult``,
  ``HypothesisNode``, ``HypothesisVerdict``, ``Evidence``, …).
* :class:`FakeToolCaller` for unit tests that need to drive the
  explorer without booting the full tool registry.

The explorer is intentionally separate from the agent so an outer LLM
loop (or a future planner agent) can reuse it via any
``HunterToolCaller`` implementation without inheriting any of
``BaseAgent``'s side effects.
"""
from __future__ import annotations

from app.agents.hunter.agent import HunterAgent
from app.agents.hunter.explorer import ExplorerBudget, HypothesisTreeExplorer
from app.agents.hunter.models import (
    Evidence,
    HuntResult,
    HypothesisCategory,
    HypothesisNode,
    HypothesisStatus,
    HypothesisVerdict,
)
from app.agents.hunter.tools import (
    BaseAgentToolCaller,
    FakeToolCaller,
    HunterToolCaller,
)

__all__ = [
    "BaseAgentToolCaller",
    "Evidence",
    "ExplorerBudget",
    "FakeToolCaller",
    "HunterAgent",
    "HunterToolCaller",
    "HuntResult",
    "HypothesisCategory",
    "HypothesisNode",
    "HypothesisStatus",
    "HypothesisTreeExplorer",
    "HypothesisVerdict",
]
