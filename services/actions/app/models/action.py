"""
Action models for the Action Execution Service.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    CAPTURE_FORENSICS = "capture_forensics"
    ADD_IOC_TO_BLOCKLIST = "add_ioc_to_blocklist"
    NOTIFY_SLACK = "notify_slack"
    CREATE_TICKET = "create_ticket"
    RUN_PLAYBOOK = "run_playbook"
    # Wave 1 — ChatOps user verification: outbound interactive Slack/Teams prompt
    # asking the affected user to confirm or deny an event ("Was this you?").
    # The response is HMAC-validated and routed back into the case timeline.
    CHATOPS_VERIFY = "chatops_verify"


class ActionStatus(str, Enum):
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class BlastRadius(str, Enum):
    MINIMAL = "minimal"  # Notification-only, no infra changes
    LOW = "low"  # Reversible, limited scope
    MEDIUM = "medium"  # Affects single resource, reversible
    HIGH = "high"  # Affects multiple resources or users
    CRITICAL = "critical"  # Broad impact, potential service disruption


# Map action types to their blast radius levels
ACTION_BLAST_RADIUS: dict[ActionType, BlastRadius] = {
    ActionType.BLOCK_IP: BlastRadius.MEDIUM,
    ActionType.BLOCK_DOMAIN: BlastRadius.MEDIUM,
    ActionType.ISOLATE_HOST: BlastRadius.HIGH,
    ActionType.DISABLE_USER: BlastRadius.HIGH,
    ActionType.RESET_PASSWORD: BlastRadius.MEDIUM,
    ActionType.KILL_PROCESS: BlastRadius.MEDIUM,
    ActionType.QUARANTINE_FILE: BlastRadius.LOW,
    ActionType.CAPTURE_FORENSICS: BlastRadius.LOW,
    ActionType.ADD_IOC_TO_BLOCKLIST: BlastRadius.LOW,
    ActionType.NOTIFY_SLACK: BlastRadius.MINIMAL,
    ActionType.CREATE_TICKET: BlastRadius.MINIMAL,
    ActionType.RUN_PLAYBOOK: BlastRadius.MEDIUM,
    # ChatOps verification asks a user a yes/no question — no infra changes.
    ActionType.CHATOPS_VERIFY: BlastRadius.MINIMAL,
}

# Actions that require explicit human approval
APPROVAL_REQUIRED_ACTIONS = {
    ActionType.ISOLATE_HOST,
    ActionType.DISABLE_USER,
    ActionType.RESET_PASSWORD,
    ActionType.KILL_PROCESS,
}


class ActionRequest(BaseModel):
    """Request to execute an action."""

    id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    tenant_id: UUID
    action_type: ActionType
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    requested_by: str = "system"
    rationale: str = ""
    auto_rollback: bool = False
    rollback_after_seconds: int | None = None


class ActionResult(BaseModel):
    """Result of an executed action."""

    action_id: UUID
    status: ActionStatus
    blast_radius: BlastRadius
    output: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    rollback_data: dict[str, Any] = Field(default_factory=dict)
    executed_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
