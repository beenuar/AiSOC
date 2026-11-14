"""Investigation Swarm (v8 P3).

For hard cases, fan out 3–5 competing hypothesis agents in parallel — each
independently gathering evidence with its own cost budget — then run a
structured debate node that scores the hypotheses on explicit criteria
(evidence coverage, contradiction count, institutional-memory prior) and emits a
ranked list. The debate is a first-class ledger step type the replay UI renders
as a split-screen.

The scoring is deterministic and offline-testable; an LLM layer can enrich each
hypothesis agent, but the ranking criteria and the cost/latency gates are what
CI enforces.
"""

from app.swarm.complexity import ComplexityAssessment, assess_complexity
from app.swarm.debate import DebateOutcome, RankedHypothesis, hold_debate
from app.swarm.hypotheses import HYPOTHESES, Hypothesis
from app.swarm.swarm import HypothesisResult, run_swarm, run_swarm_sync

__all__ = [
    "assess_complexity",
    "ComplexityAssessment",
    "HYPOTHESES",
    "Hypothesis",
    "run_swarm",
    "run_swarm_sync",
    "HypothesisResult",
    "hold_debate",
    "DebateOutcome",
    "RankedHypothesis",
]
