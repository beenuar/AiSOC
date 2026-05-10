"""
API endpoints for MITRE ATT&CK-based attack reasoning.

Provides RESTful access to the LangGraph multi-agent attack reasoning system
defined in `app.attack_reasoning.attack_reasoner`.
"""

from __future__ import annotations

from typing import Any, Dict, List

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.attack_reasoning.attack_reasoner import (
    predict_next_techniques as predict_next_techniques_helper,
    reason_about_attack,
)
from app.tools.mitre_full import get_actor, get_actor_techniques, get_technique

logger = structlog.get_logger(__name__)
router = APIRouter(prefix="/api/v1/attack-reasoning", tags=["attack-reasoning"])


# --- Request models -------------------------------------------------------


class AnalyzeRequest(BaseModel):
    incident_id: str = Field(..., description="Incident identifier")
    observed_indicators: List[Dict[str, Any]] = Field(
        ...,
        description="Observed security indicators with at least one of name/description/context fields",
    )


class PredictRequest(BaseModel):
    identified_techniques: List[str] = Field(
        ...,
        description="Already-observed ATT&CK technique IDs (e.g. ['T1059', 'T1078'])",
    )


# --- Endpoints ------------------------------------------------------------


@router.post("/analyze")
async def analyze_attack(req: AnalyzeRequest) -> Dict[str, Any]:
    """Analyze an attack using the MITRE ATT&CK-based reasoning workflow."""
    logger.info("attack_reasoning_request", incident_id=req.incident_id)
    try:
        result_state = await reason_about_attack(req.incident_id, req.observed_indicators)
    except Exception as exc:  # pragma: no cover - reason_about_attack handles its own
        logger.exception("attack_reasoning_unhandled", incident_id=req.incident_id)
        raise HTTPException(status_code=500, detail=f"Attack reasoning analysis failed: {exc}")

    result_dict = result_state.model_dump()
    logger.info(
        "attack_reasoning_response",
        incident_id=req.incident_id,
        techniques=len(result_dict.get("identified_techniques", [])),
        actors=len(result_dict.get("threat_actors", [])),
        recommendations=len(result_dict.get("tactical_recommendations", [])),
    )
    return result_dict


@router.post("/predict-next-techniques")
async def predict_next_techniques(req: PredictRequest) -> Dict[str, Any]:
    """Predict likely next techniques given a set of observed technique IDs.

    Uses the same v0 progression table as the LangGraph PathPredictor agent
    (`app.attack_reasoning.attack_reasoner._PROGRESSION_MAP`) so the API and
    the graph never drift.
    """
    logger.info("predict_next_techniques_request", count=len(req.identified_techniques))
    predictions = predict_next_techniques_helper(req.identified_techniques)
    return {"input_techniques": req.identified_techniques, "predictions": predictions}


@router.get("/technique/{technique_id}")
async def get_technique_details(technique_id: str) -> Dict[str, Any]:
    """Return MITRE ATT&CK details for a single technique."""
    logger.info("technique_details_request", technique_id=technique_id)
    details = get_technique(technique_id)
    if not details.get("found"):
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return {"technique": details}


@router.get("/actor/{actor_id}")
async def get_actor_profile(actor_id: str) -> Dict[str, Any]:
    """Return MITRE ATT&CK details and known techniques for a threat actor."""
    logger.info("actor_profile_request", actor_id=actor_id)
    actor_details = get_actor(actor_id)
    if not actor_details.get("found"):
        raise HTTPException(status_code=404, detail=f"Actor {actor_id} not found")
    actor_techniques = get_actor_techniques(actor_id)
    return {"actor": actor_details, "techniques": actor_techniques}
