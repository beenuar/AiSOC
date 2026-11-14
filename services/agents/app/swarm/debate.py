"""The consensus / debate node.

Agents exchange evidence bundles and the competing hypotheses are scored on
explicit criteria:

* **evidence coverage** — how much supporting signal the hypothesis gathered,
* **contradiction count** — evidence that argues against it (penalized),
* **institutional-memory prior** — how this signature has historically resolved.

Output is a ranked hypothesis list with a calibrated confidence, plus a
ledger-ready ``debate`` payload the replay UI renders as a split-screen.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from app.swarm.swarm import HypothesisResult


@dataclass(frozen=True)
class RankedHypothesis:
    key: str
    label: str
    benign: bool
    score: float  # final debate score, 0–1
    confidence: float  # 0–1, margin-based confidence in the ranking
    evidence: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DebateOutcome:
    ranked: list[RankedHypothesis]
    winner: RankedHypothesis | None
    ledger_payload: dict = field(default_factory=dict)


def hold_debate(
    results: list[HypothesisResult],
    *,
    memory_priors: dict[str, float] | None = None,
) -> DebateOutcome:
    """Score + rank competing hypotheses. ``memory_priors`` maps hypothesis key
    → prior in [0, 1] (e.g. from institutional memory: how often this
    hypothesis was the correct disposition historically)."""
    memory_priors = memory_priors or {}
    scored: list[RankedHypothesis] = []
    for r in results:
        prior = float(memory_priors.get(r.key, 0.0))
        # Explicit criteria: evidence coverage (the support score already blends
        # keyword + technique coverage minus contradictions) + a bounded prior.
        final = max(0.0, min(1.0, 0.8 * r.support_score + 0.2 * prior))
        scored.append(
            RankedHypothesis(
                key=r.key,
                label=r.label,
                benign=r.benign,
                score=round(final, 4),
                confidence=0.0,  # filled after ranking (margin-based)
                evidence=r.evidence,
                contradictions=r.contradictions,
            )
        )

    scored.sort(key=lambda h: h.score, reverse=True)

    # Confidence for the top hypothesis is the margin over the runner-up,
    # clamped to [0.05, 0.95] so we never claim certainty.
    ranked: list[RankedHypothesis] = []
    for i, h in enumerate(scored):
        if i == 0 and len(scored) > 1:
            margin = scored[0].score - scored[1].score
            conf = max(0.05, min(0.95, 0.5 + margin))
        elif i == 0:
            conf = max(0.05, min(0.95, h.score))
        else:
            conf = round(h.score, 4)
        ranked.append(
            RankedHypothesis(
                key=h.key,
                label=h.label,
                benign=h.benign,
                score=h.score,
                confidence=round(conf, 4),
                evidence=h.evidence,
                contradictions=h.contradictions,
            )
        )

    winner = ranked[0] if ranked else None
    payload = {
        "step_type": "debate",
        "hypotheses": [asdict(h) for h in ranked],
        "winner": winner.key if winner else None,
        "winner_label": winner.label if winner else None,
        "winner_confidence": winner.confidence if winner else 0.0,
    }
    return DebateOutcome(ranked=ranked, winner=winner, ledger_payload=payload)


def investigation_completeness(considered: list[str], relevant: set[str]) -> float:
    """Fraction of an incident's relevant hypotheses that were considered.

    This is the substrate self-consistency macro the swarm-vs-single eval uses:
    a single agent considers only its top prior; the swarm considers up to five,
    so on multi-hypothesis incidents the swarm's completeness is structurally
    higher. It is NOT a live-agent accuracy claim (see the eval harness docs).
    """
    if not relevant:
        return 1.0
    covered = len(set(considered) & relevant)
    return round(covered / len(relevant), 4)
