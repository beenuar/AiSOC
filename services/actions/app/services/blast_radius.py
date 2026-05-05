"""
Blast-radius gate: evaluates action risk before execution.
Enforces approval workflows for high-risk actions.
"""

from __future__ import annotations

import structlog

from app.models.action import (
    ACTION_BLAST_RADIUS,
    APPROVAL_REQUIRED_ACTIONS,
    ActionRequest,
    ActionStatus,
    BlastRadius,
)

logger = structlog.get_logger()

# Tenant-level blast radius policy: max auto-execute radius
_AUTO_EXECUTE_LIMIT = BlastRadius.MEDIUM

_BLAST_RADIUS_ORDER = {
    BlastRadius.MINIMAL: 0,
    BlastRadius.LOW: 1,
    BlastRadius.MEDIUM: 2,
    BlastRadius.HIGH: 3,
    BlastRadius.CRITICAL: 4,
}


class BlastRadiusGate:
    """
    Evaluates whether an action can be auto-executed or requires approval.
    """

    def evaluate(self, request: ActionRequest) -> tuple[ActionStatus, BlastRadius, str]:
        """
        Returns (initial_status, blast_radius, reason).

        - APPROVED: safe to execute automatically
        - AWAITING_APPROVAL: requires human approval before execution
        """
        blast_radius = ACTION_BLAST_RADIUS.get(request.action_type, BlastRadius.MEDIUM)

        # Check if action type always requires approval
        if request.action_type in APPROVAL_REQUIRED_ACTIONS:
            logger.info(
                "Action requires approval (policy)",
                action_type=request.action_type,
                blast_radius=blast_radius,
            )
            return (
                ActionStatus.AWAITING_APPROVAL,
                blast_radius,
                f"Action type '{request.action_type}' always requires human approval",
            )

        # Check blast radius against auto-execute limit
        if _BLAST_RADIUS_ORDER[blast_radius] > _BLAST_RADIUS_ORDER[_AUTO_EXECUTE_LIMIT]:
            logger.info(
                "Action requires approval (blast radius exceeded)",
                action_type=request.action_type,
                blast_radius=blast_radius,
                limit=_AUTO_EXECUTE_LIMIT,
            )
            return (
                ActionStatus.AWAITING_APPROVAL,
                blast_radius,
                f"Blast radius '{blast_radius}' exceeds auto-execute limit '{_AUTO_EXECUTE_LIMIT}'",
            )

        logger.info(
            "Action approved for auto-execution",
            action_type=request.action_type,
            blast_radius=blast_radius,
        )
        return (
            ActionStatus.APPROVED,
            blast_radius,
            f"Blast radius '{blast_radius}' within auto-execute policy",
        )
