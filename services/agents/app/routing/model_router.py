"""Unified deterministic → ML → LLM model router (Phase 7).

The reality audit found the three-model story (deterministic rules → ML scorers
→ LLM) implemented as *scattered, ad-hoc fallbacks*: `nl_query`, `nl_drafter`,
`explain`, `copilot`, and the sub-agents each independently check "is a key
configured?" and degrade on their own. There was no single place that:

* decides which tier should answer (cheapest sufficient tier first),
* **attributes** every decision to the tier that produced it (so cost and
  provenance are auditable), and
* enforces a **determinism contract**: when deterministic mode is on (env flag
  or the cost governor tripping its circuit breaker), the router NEVER touches
  the ML or LLM tier, and the deterministic tier is reproducible — identical
  input yields an identical decision.

This module is that place. It is intentionally dependency-light (stdlib only):
the three tier functions are injected, so the router is unit-testable without a
real model, and `build_router` wires the real deterministic scorer while
leaving ML/LLM as optional callables the caller supplies.

Key invariant the gate proves: **the router never silently uses the LLM.** Every
decision carries an `attribution` trail; whenever the LLM tier is skipped or
blocked (deterministic mode, no key, governor circuit open, tier error), the
reason is recorded rather than the router quietly degrading.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)

DETERMINISTIC_ENV_FLAG = "AISOC_DETERMINISTIC"
DEFAULT_CONFIDENCE_FLOOR = 0.85


class ModelTier(str, Enum):
    DETERMINISTIC = "deterministic"
    ML = "ml"
    LLM = "llm"


def is_deterministic_mode() -> bool:
    """Canonical determinism switch. Off by default; set AISOC_DETERMINISTIC=1
    to force the deterministic tier everywhere (air-gap, reproducible evals,
    cost lockdown)."""
    raw = os.environ.get(DETERMINISTIC_ENV_FLAG)
    if raw is None:
        return False
    return raw.strip().lower() in {"1", "true", "yes", "on", "enabled"}


@dataclass(frozen=True)
class RoutingRequest:
    """Input to the router. ``fingerprint`` is the determinism/dedup identity."""

    payload: dict[str, Any]
    tenant_id: str = "00000000-0000-0000-0000-000000000000"

    def fingerprint(self) -> str:
        blob = json.dumps(self.payload, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class TierResult:
    """What a tier returns: an output, a confidence in [0,1], and a reason."""

    output: Any
    confidence: float
    reason: str = ""
    model: str | None = None


@dataclass(frozen=True)
class RoutingDecision:
    """The router's verdict, fully attributed."""

    tier: ModelTier
    output: Any
    confidence: float
    model_used: str
    attribution: list[str] = field(default_factory=list)
    tiers_considered: list[str] = field(default_factory=list)
    deterministic: bool = False
    escalation_blocked_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "confidence": self.confidence,
            "model_used": self.model_used,
            "attribution": list(self.attribution),
            "tiers_considered": list(self.tiers_considered),
            "deterministic": self.deterministic,
            "escalation_blocked_reason": self.escalation_blocked_reason,
        }


@runtime_checkable
class Governor(Protocol):
    """Subset of cost_governor used here — kept as a Protocol so this module
    doesn't import the heavy governor at module load."""

    def check(self, tenant_id: str, fingerprint: str) -> Any: ...


TierFn = Callable[[RoutingRequest], TierResult | Awaitable[TierResult]]


async def _maybe_await(value: TierResult | Awaitable[TierResult]) -> TierResult:
    if inspect.isawaitable(value):
        return await value
    return value


class ModelRouter:
    """Routes a request to the cheapest sufficient tier, fully attributed.

    Escalation ladder: deterministic → ML → LLM. A tier "wins" when its
    confidence meets ``confidence_floor``; otherwise the router escalates to the
    next available tier. The LLM tier is only ever reached when it is
    configured, deterministic mode is off, and the governor (if any) permits
    spend — and if it is *not* reached, the reason is recorded.
    """

    def __init__(
        self,
        *,
        deterministic_fn: TierFn,
        ml_fn: TierFn | None = None,
        llm_fn: TierFn | None = None,
        confidence_floor: float = DEFAULT_CONFIDENCE_FLOOR,
        deterministic_only: bool = False,
        governor: Governor | None = None,
    ) -> None:
        self._deterministic_fn = deterministic_fn
        self._ml_fn = ml_fn
        self._llm_fn = llm_fn
        self._floor = confidence_floor
        self._forced_deterministic = deterministic_only
        self._governor = governor

    def _resolve_deterministic_only(self, request: RoutingRequest, attribution: list[str]) -> bool:
        if self._forced_deterministic:
            attribution.append("deterministic-only: forced by construction")
            return True
        if is_deterministic_mode():
            attribution.append(f"deterministic-only: {DETERMINISTIC_ENV_FLAG} is set")
            return True
        if self._governor is not None:
            try:
                decision = self._governor.check(request.tenant_id, request.fingerprint())
                use_llm = bool(getattr(decision, "use_llm", True))
                label = getattr(getattr(decision, "decision", None), "value", None) or str(getattr(decision, "decision", "?"))
                if not use_llm:
                    attribution.append(f"deterministic-only: cost governor decision '{label}' forbids LLM spend")
                    return True
            except Exception as exc:  # noqa: BLE001 — governor must never crash routing
                logger.warning("model_router.governor_check_failed", extra={"error": str(exc)})
        return False

    async def route(self, request: RoutingRequest) -> RoutingDecision:
        attribution: list[str] = []
        considered: list[str] = []
        deterministic_only = self._resolve_deterministic_only(request, attribution)

        # Tier 1 — deterministic. Always runs; it's the floor of the ladder.
        det = await _maybe_await(self._deterministic_fn(request))
        considered.append(ModelTier.DETERMINISTIC.value)

        higher_tier_available = (self._ml_fn is not None or self._llm_fn is not None) and not deterministic_only
        if det.confidence >= self._floor or not higher_tier_available:
            if deterministic_only:
                attribution.append("resolved on deterministic tier (deterministic-only mode)")
            elif det.confidence >= self._floor:
                attribution.append(f"deterministic tier confident ({det.confidence:.2f} >= floor {self._floor:.2f})")
            else:
                attribution.append("no higher tier available; using deterministic result")
            blocked = None
            if not higher_tier_available and det.confidence < self._floor:
                blocked = "deterministic-only mode" if deterministic_only else "no ML/LLM tier configured"
            return RoutingDecision(
                tier=ModelTier.DETERMINISTIC,
                output=det.output,
                confidence=det.confidence,
                model_used=det.model or "deterministic",
                attribution=attribution + ([det.reason] if det.reason else []),
                tiers_considered=considered,
                deterministic=True,
                escalation_blocked_reason=blocked,
            )

        # Tier 2 — ML. Cheaper than the LLM; try before escalating further.
        best = det
        best_tier = ModelTier.DETERMINISTIC
        if self._ml_fn is not None:
            attribution.append(f"deterministic below floor ({det.confidence:.2f} < {self._floor:.2f}); escalating to ML")
            ml = await _maybe_await(self._ml_fn(request))
            considered.append(ModelTier.ML.value)
            if ml.confidence >= self._floor or self._llm_fn is None:
                if ml.confidence >= self._floor:
                    attribution.append(f"ML tier confident ({ml.confidence:.2f} >= floor)")
                    blocked = None
                else:
                    attribution.append("no LLM tier configured; using ML result")
                    blocked = "no LLM tier configured"
                return RoutingDecision(
                    tier=ModelTier.ML,
                    output=ml.output,
                    confidence=ml.confidence,
                    model_used=ml.model or "ml",
                    attribution=attribution + ([ml.reason] if ml.reason else []),
                    tiers_considered=considered,
                    deterministic=False,
                    escalation_blocked_reason=blocked,
                )
            if ml.confidence > best.confidence:
                best, best_tier = ml, ModelTier.ML

        # Tier 3 — LLM. Last resort; only reached when configured + permitted.
        if self._llm_fn is not None:
            attribution.append("escalating to LLM tier")
            considered.append(ModelTier.LLM.value)
            try:
                llm = await _maybe_await(self._llm_fn(request))
                return RoutingDecision(
                    tier=ModelTier.LLM,
                    output=llm.output,
                    confidence=llm.confidence,
                    model_used=llm.model or "llm",
                    attribution=attribution + ([llm.reason] if llm.reason else []),
                    tiers_considered=considered,
                    deterministic=False,
                )
            except Exception as exc:  # noqa: BLE001 — LLM failure must degrade, not crash
                reason = f"LLM tier failed ({type(exc).__name__}); falling back to {best_tier.value}"
                attribution.append(reason)
                return RoutingDecision(
                    tier=best_tier,
                    output=best.output,
                    confidence=best.confidence,
                    model_used=best.model or best_tier.value,
                    attribution=attribution,
                    tiers_considered=considered,
                    deterministic=best_tier is ModelTier.DETERMINISTIC,
                    escalation_blocked_reason=reason,
                )

        # No LLM tier at all — never silently pretend; record the block.
        blocked = "no LLM tier configured"
        attribution.append(f"escalation to LLM blocked: {blocked}; using {best_tier.value} result")
        return RoutingDecision(
            tier=best_tier,
            output=best.output,
            confidence=best.confidence,
            model_used=best.model or best_tier.value,
            attribution=attribution,
            tiers_considered=considered,
            deterministic=best_tier is ModelTier.DETERMINISTIC,
            escalation_blocked_reason=blocked,
        )


def build_router(
    *,
    ml_fn: TierFn | None = None,
    llm_fn: TierFn | None = None,
    confidence_floor: float = DEFAULT_CONFIDENCE_FLOOR,
    governor: Governor | None = None,
) -> ModelRouter:
    """Wire a router with the real deterministic triage scorer as tier 1.

    ML/LLM tiers are optional and injected by the caller (they carry heavy
    deps), so this factory stays import-light and the deterministic path always
    works — including air-gapped.
    """

    def _deterministic(request: RoutingRequest) -> TierResult:
        # Lazy import so this module never drags the agents package at import.
        from app.agents.triage_agent import _score_alert  # noqa: PLC0415
        from app.models.state import InvestigationState  # noqa: PLC0415

        payload = request.payload
        state = InvestigationState(
            alert_summary=str(payload.get("alert_summary") or payload.get("title") or ""),
            raw_alert=payload.get("raw_alert") or payload,
        )
        verdict, confidence = _score_alert(state)
        return TierResult(
            output={"verdict": verdict},
            confidence=confidence,
            reason=f"heuristic triage → {verdict}",
            model="deterministic:triage",
        )

    return ModelRouter(
        deterministic_fn=_deterministic,
        ml_fn=ml_fn,
        llm_fn=llm_fn,
        confidence_floor=confidence_floor,
        governor=governor,
    )
