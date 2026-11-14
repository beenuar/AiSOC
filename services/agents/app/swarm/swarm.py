"""Fan out competing hypothesis agents in parallel, each with a cost budget.

Each hypothesis agent independently "gathers evidence" (deterministically here:
scanning the alert text + techniques for supporting/contradicting signal) and
returns an evidence bundle + a raw support score. Agents run concurrently
(``asyncio.gather``); each is capped by a per-agent token/cost budget so the
swarm's total spend stays bounded and predictable.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from app.keywords import matched, normalise
from app.swarm.hypotheses import HYPOTHESES, Hypothesis

# A per-agent budget (tokens). Deterministic agents don't spend, but the budget
# is threaded through so the LLM-backed variant is bounded and the swarm's
# aggregate cost is (num_agents * per_agent_budget) — the ceiling CI checks.
DEFAULT_PER_AGENT_TOKEN_BUDGET = 1500


@dataclass(frozen=True)
class HypothesisResult:
    key: str
    label: str
    benign: bool
    support_score: float  # 0–1, how well the evidence supports this hypothesis
    evidence: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)
    technique_hits: list[str] = field(default_factory=list)
    tokens_spent: int = 0


def _signal_text(signal: dict) -> str:
    parts = [str(signal.get("alert_summary", "")), str(signal.get("title", "")), str(signal.get("raw", ""))]
    return normalise(" ".join(parts))


def _evaluate(hypothesis: Hypothesis, signal: dict, budget: int) -> HypothesisResult:
    text = _signal_text(signal)
    techniques = {t.upper() for t in (signal.get("techniques") or signal.get("mitre_techniques") or [])}

    # Token-boundary matching: as substrings, ``c2`` credited the C2-beacon
    # hypothesis on any alert naming an EC2 host (#1607).
    evidence = matched(text, hypothesis.supports_keywords)
    contradictions = matched(text, hypothesis.contradicts_keywords)
    tech_hits = sorted(techniques & {t.upper() for t in hypothesis.techniques})

    # Deterministic support score: keyword coverage + technique corroboration,
    # minus contradictions. Bounded to [0, 1].
    kw_component = min(len(evidence) * 0.25, 0.6)
    tech_component = min(len(tech_hits) * 0.3, 0.5)
    penalty = min(len(contradictions) * 0.3, 0.6)
    score = max(0.0, min(1.0, kw_component + tech_component - penalty))

    return HypothesisResult(
        key=hypothesis.key,
        label=hypothesis.label,
        benign=hypothesis.benign,
        support_score=round(score, 4),
        evidence=evidence,
        contradictions=contradictions,
        technique_hits=tech_hits,
        tokens_spent=min(budget, 200),  # deterministic agents are cheap
    )


async def _agent(hypothesis: Hypothesis, signal: dict, budget: int) -> HypothesisResult:
    # Yield to the loop so the fan-out is genuinely concurrent.
    await asyncio.sleep(0)
    return _evaluate(hypothesis, signal, budget)


async def run_swarm(
    signal: dict,
    *,
    hypotheses: list[Hypothesis] | None = None,
    max_agents: int = 5,
    per_agent_budget: int = DEFAULT_PER_AGENT_TOKEN_BUDGET,
) -> list[HypothesisResult]:
    """Fan out up to ``max_agents`` hypothesis agents in parallel."""
    chosen = (hypotheses or HYPOTHESES)[:max_agents]
    results = await asyncio.gather(*[_agent(h, signal, per_agent_budget) for h in chosen])
    return list(results)


def run_swarm_sync(signal: dict, **kwargs) -> list[HypothesisResult]:
    """Synchronous convenience wrapper (for tests / non-async callers)."""
    return asyncio.run(run_swarm(signal, **kwargs))
