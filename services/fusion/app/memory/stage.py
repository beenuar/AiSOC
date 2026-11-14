"""The deterministic ``memory`` verdict stage.

Consumes the distilled per-signature priors and produces a **bounded** verdict
adjustment (capped at ±0.10, like the mesh stage: institutional memory nudges,
never dominates). A signature the analysts have repeatedly corrected to benign
pulls new alerts of that signature down; one they've repeatedly confirmed nudges
up. Unknown signatures (no prior) contribute nothing.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.memory.distill import SignaturePrior

MEMORY_CAP = 0.10


@dataclass(frozen=True)
class MemoryContribution:
    delta: float
    basis: str
    sample_count: int


def memory_contribution(signature: str, priors: dict[str, SignaturePrior]) -> MemoryContribution:
    """Bounded verdict delta from the distilled prior for ``signature``."""
    prior = priors.get(signature)
    if prior is None:
        return MemoryContribution(delta=0.0, basis="no institutional memory for this signature", sample_count=0)

    # Confidence grows with sample size, saturating ~20 samples.
    weight = min(prior.sample_count / 20.0, 1.0)
    # prior 1.0 (always TP) → +cap ; prior 0.0 (always benign) → -cap.
    direction = (prior.prior - 0.5) * 2.0  # [-1, +1]
    delta = max(-MEMORY_CAP, min(MEMORY_CAP, direction * weight * MEMORY_CAP))
    pct = round(prior.fp_rate * 100)
    basis = f"institutional memory: {prior.sample_count} prior dispositions, {pct}% FP"
    return MemoryContribution(delta=round(delta, 4), basis=basis, sample_count=prior.sample_count)
