"""Multi-model routing (Phase 7): deterministic → ML → LLM with attribution."""

from app.routing.model_router import (
    DEFAULT_CONFIDENCE_FLOOR,
    DETERMINISTIC_ENV_FLAG,
    ModelRouter,
    ModelTier,
    RoutingDecision,
    RoutingRequest,
    TierResult,
    build_router,
    is_deterministic_mode,
)

__all__ = [
    "DEFAULT_CONFIDENCE_FLOOR",
    "DETERMINISTIC_ENV_FLAG",
    "ModelRouter",
    "ModelTier",
    "RoutingDecision",
    "RoutingRequest",
    "TierResult",
    "build_router",
    "is_deterministic_mode",
]
