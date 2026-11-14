"""Cost-aware model cascade (Wave 5a).

The existing ModelRouter escalates by confidence but treats "cheap" only as tier
ordinality, and the live worker never used it. This adds an explicit
**cheap-first speculative cascade**: run the cheap tier, accept its answer when
confident enough, and escalate to the strong (expensive) tier only when the
cheap answer is below the confidence floor. Most alerts are handled by the cheap
model; only the genuinely-uncertain ones pay for the strong model.

Pure orchestration over caller-supplied async tier functions + a confidence
extractor, so it is provider-agnostic and unit-testable without a live LLM.
Fail-soft: if the strong tier errors, the cheap answer is returned rather than
failing the triage.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()

DEFAULT_CONFIDENCE_FLOOR = 0.75

TierFn = Callable[[], Awaitable[Any]]
ConfidenceFn = Callable[[Any], float]


@dataclass(frozen=True)
class CascadeResult:
    result: Any
    tier_used: str  # "cheap" | "strong"
    cheap_confidence: float
    escalated: bool
    strong_error: str | None = None


async def cost_aware_cascade(
    *,
    cheap: TierFn,
    strong: TierFn,
    extract_confidence: ConfidenceFn,
    confidence_floor: float = DEFAULT_CONFIDENCE_FLOOR,
) -> CascadeResult:
    """Run cheap-first; escalate to strong only when the cheap answer is uncertain."""
    cheap_result = await cheap()
    cheap_conf = _clamp(extract_confidence(cheap_result))
    if cheap_conf >= confidence_floor:
        return CascadeResult(result=cheap_result, tier_used="cheap", cheap_confidence=cheap_conf, escalated=False)

    try:
        strong_result = await strong()
    except Exception as exc:  # noqa: BLE001 — degrade to the cheap answer, never fail triage
        logger.warning("cascade.strong_tier_failed", error=str(exc), cheap_confidence=cheap_conf)
        return CascadeResult(
            result=cheap_result,
            tier_used="cheap",
            cheap_confidence=cheap_conf,
            escalated=True,
            strong_error=str(exc),
        )
    return CascadeResult(result=strong_result, tier_used="strong", cheap_confidence=cheap_conf, escalated=True)


def _clamp(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0
