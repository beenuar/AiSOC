"""Unified autonomy policy (Wave 5b).

The agent produces a verdict + confidence; the actions gate keys on blast radius
+ tier. They never shared a contract, so confidence never influenced execution.
This module unifies them into one decision over (confidence, blast radius,
reversibility).

Posture: **aggressive-but-safe** — a REVERSIBLE, low-blast-radius action with
high model confidence may auto-execute by default (it can be rolled back and
its scope is limited), while anything non-reversible, high/critical blast, or
low-confidence still requires a human. This is the "auto-response by default for
reversible low-blast actions, gated by confidence + rollback" behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models.action import BlastRadius
from app.services.autonomy_safety import REVERSIBLE_ACTIONS, AutonomyMode

# Confidence needed to auto-execute a reversible LOW-blast action.
AUTO_LOW_BLAST_CONFIDENCE = 0.85
# Higher bar to auto-execute a reversible MEDIUM-blast action.
AUTO_MEDIUM_BLAST_CONFIDENCE = 0.95


@dataclass(frozen=True)
class AutonomyDecision:
    mode: AutonomyMode
    rationale: str
    confidence: float
    reversible: bool


def is_reversible(action_type: str) -> bool:
    return action_type in REVERSIBLE_ACTIONS


def unified_decision(
    *,
    action_type: str,
    blast_radius: BlastRadius,
    confidence: float,
    reversible: bool | None = None,
    low_blast_floor: float = AUTO_LOW_BLAST_CONFIDENCE,
    medium_blast_floor: float = AUTO_MEDIUM_BLAST_CONFIDENCE,
) -> AutonomyDecision:
    """Decide how an action may run, unifying model confidence with blast radius."""
    rev = is_reversible(action_type) if reversible is None else reversible
    conf = max(0.0, min(1.0, confidence))

    def d(mode: AutonomyMode, why: str) -> AutonomyDecision:
        return AutonomyDecision(mode=mode, rationale=why, confidence=conf, reversible=rev)

    # Critical blast is never auto, regardless of confidence.
    if blast_radius == BlastRadius.CRITICAL:
        return d(AutonomyMode.QUEUED_APPROVAL, "CRITICAL blast radius always requires human approval")

    # Without a real rollback path, never auto-execute — a wrong call can't be undone.
    if not rev:
        return d(AutonomyMode.QUEUED_APPROVAL, "non-reversible action requires human approval")

    # High blast, even reversible, needs a human.
    if blast_radius == BlastRadius.HIGH:
        return d(AutonomyMode.QUEUED_APPROVAL, "reversible HIGH-blast action queued for approval")

    if blast_radius == BlastRadius.LOW and conf >= low_blast_floor:
        return d(AutonomyMode.AUTO, f"reversible LOW-blast action, confidence {conf:.2f} >= {low_blast_floor:.2f} — auto-execute")

    if blast_radius == BlastRadius.MEDIUM and conf >= medium_blast_floor:
        return d(AutonomyMode.AUTO, f"reversible MEDIUM-blast action, confidence {conf:.2f} >= {medium_blast_floor:.2f} — auto-execute")

    return d(AutonomyMode.QUEUED_APPROVAL, f"confidence {conf:.2f} below auto floor for {blast_radius.value} blast — queued for approval")
