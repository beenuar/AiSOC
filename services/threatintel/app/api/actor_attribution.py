"""HTTP API for threat actor attribution.

The attribution engine is held on ``app.state.attribution_engine`` so the
``os_store`` and any future shared dependencies can be injected at startup
(see ``services/threatintel/app/main.py``). FastAPI dependencies pull the
engine from the request, which keeps tests and per-request overrides
straightforward.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from app.actors.attribution import (
    AttributionResult,
    ThreatActorAttributionEngine,
    ThreatActorProfile,
)

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/actors", tags=["threat-actors"])


def get_attribution_engine(request: Request) -> ThreatActorAttributionEngine:
    """FastAPI dependency that returns the engine bound at startup."""
    engine = getattr(request.app.state, "attribution_engine", None)
    if engine is None:
        raise HTTPException(
            status_code=503,
            detail="Attribution engine not initialized",
        )
    return engine


class AttributionRequest(BaseModel):
    """Body for ``POST /attribute``.

    ``case_metadata`` is optional; when omitted the target-sector component
    of the score is skipped.
    """

    iocs: list[dict[str, Any]] = Field(
        default_factory=list,
        description=("Indicators of compromise. Each item should include 'value' and ideally 'type' (e.g. 'ipv4', 'domain', 'sha256')."),
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="Observed MITRE ATT&CK technique IDs (e.g. ['T1566', 'T1059']).",
    )
    case_metadata: dict[str, Any] | None = Field(
        default=None,
        description=("Free-form case metadata. 'targets' (list of sector strings) is the only field consulted today."),
    )


@router.post("/attribute", response_model=AttributionResult)
async def attribute_incident(
    body: AttributionRequest,
    engine: ThreatActorAttributionEngine = Depends(get_attribution_engine),
) -> AttributionResult:
    """Attribute an incident to the highest-scoring known actor.

    Returns ``actor_id="unknown"`` when no actor exceeds the engine's
    confidence threshold.
    """
    try:
        result = await engine.attribute_incident(
            iocs=body.iocs,
            mitre_techniques=body.mitre_techniques,
            case_metadata=body.case_metadata or {},
        )
        logger.info(
            "Incident attributed",
            actor=result.actor_name,
            confidence=result.confidence_score,
        )
        return result
    except Exception as exc:
        logger.error("Incident attribution failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Attribution failed: {exc}") from exc


@router.get("/profiles", response_model=list[ThreatActorProfile])
async def list_actor_profiles(
    engine: ThreatActorAttributionEngine = Depends(get_attribution_engine),
) -> list[ThreatActorProfile]:
    """List all known threat actor profiles in the catalog."""
    try:
        profiles = await engine.list_actor_profiles()
        logger.info("Retrieved threat actor profiles", count=len(profiles))
        return profiles
    except Exception as exc:
        logger.error("Failed to retrieve actor profiles", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Failed to retrieve profiles: {exc}") from exc


@router.get("/profiles/{actor_id}", response_model=ThreatActorProfile)
async def get_actor_profile(
    actor_id: str,
    engine: ThreatActorAttributionEngine = Depends(get_attribution_engine),
) -> ThreatActorProfile:
    """Retrieve a single threat actor profile by ID (404 if unknown)."""
    profile = await engine.get_actor_profile(actor_id)
    if profile is None:
        raise HTTPException(
            status_code=404,
            detail=f"Actor profile '{actor_id}' not found",
        )
    logger.info("Retrieved threat actor profile", actor_id=actor_id)
    return profile
