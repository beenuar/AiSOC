"""
Agent state models for LangGraph workflows.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AgentTask(str, Enum):
    TRIAGE = "triage"
    INVESTIGATION = "investigation"
    THREAT_HUNT = "threat_hunt"
    CONTAINMENT = "containment"
    ENRICHMENT = "enrichment"
    REPORTING = "reporting"


class AgentStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProposedAction(BaseModel):
    """An action the agent wants to take, subject to approval gating."""

    id: UUID = Field(default_factory=uuid4)
    action_type: str
    description: str
    risk_level: ActionRisk
    target: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool = False
    rationale: str = ""


class InvestigationState(BaseModel):
    """Full state object passed through the LangGraph workflow."""

    # Identifiers
    run_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    tenant_id: UUID
    task: AgentTask = AgentTask.INVESTIGATION
    status: AgentStatus = AgentStatus.PENDING

    # Input
    alert_summary: str = ""
    raw_alert: dict[str, Any] = Field(default_factory=dict)

    # Findings accumulated during investigation
    findings: list[str] = Field(default_factory=list)
    ioc_enrichments: dict[str, Any] = Field(default_factory=dict)
    threat_intel: dict[str, Any] = Field(default_factory=dict)
    mitre_mappings: list[str] = Field(default_factory=list)

    # Actions
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    executed_actions: list[dict[str, Any]] = Field(default_factory=list)

    # LLM messages (for LangGraph)
    messages: list[dict[str, Any]] = Field(default_factory=list)

    # Calibrated confidence on the agent's verdict (0.0–1.0). Calibrated via
    # the Brier-score gate in the eval harness — see services/agents/app/confidence
    # and tests/test_confidence_calibration.py.
    confidence: float = 0.0
    confidence_basis: list[str] = Field(default_factory=list)
    verdict: str | None = None

    # Metadata
    iteration_count: int = 0
    max_iterations: int = 10
    error: str | None = None

    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None

    def add_finding(self, finding: str) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")
