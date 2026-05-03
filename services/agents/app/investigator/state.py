"""
Extended state model for the multi-agent investigator pipeline.
Extends the existing InvestigationState with per-agent outputs and audit log.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.models.state import InvestigationState  # re-use base model


class StepKind(str, Enum):
    RECON = "recon"
    FORENSIC = "forensic"
    RESPONDER = "responder"
    REPORTER = "reporter"
    TOOL_CALL = "tool_call"
    LLM_CALL = "llm_call"


class AuditEntry(BaseModel):
    """Immutable audit log entry for every agent step."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    kind: StepKind
    agent: str
    summary: str
    input_hash: str | None = None   # sha256 of serialised input
    output_hash: str | None = None  # sha256 of serialised output
    duration_ms: int = 0
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReconFindings(BaseModel):
    """Output of ReconAgent."""

    iocs: list[dict[str, Any]] = Field(default_factory=list)
    related_incidents: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    attack_surface: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    summary: str = ""


class ForensicFindings(BaseModel):
    """Output of ForensicAgent."""

    timeline: list[dict[str, Any]] = Field(default_factory=list)  # [{ts, event, src}]
    artefacts: list[str] = Field(default_factory=list)
    root_cause_hypothesis: str = ""
    blast_radius: str = ""
    confidence: float = 0.0  # 0–1
    summary: str = ""


class ResponderPlan(BaseModel):
    """Output of ResponderAgent (dry-run — no live execution)."""

    recommended_actions: list[dict[str, Any]] = Field(default_factory=list)
    containment_steps: list[str] = Field(default_factory=list)
    eradication_steps: list[str] = Field(default_factory=list)
    recovery_steps: list[str] = Field(default_factory=list)
    estimated_effort_hours: float = 0.0
    risk_level: str = "medium"
    dry_run: bool = True
    summary: str = ""


class InvestigatorState(BaseModel):
    """
    Full state threaded through the Pillar-1 LangGraph pipeline.
    Every node receives this as a dict and must return the full updated dict.
    """

    # Core identifiers
    run_id: UUID = Field(default_factory=uuid4)
    case_id: str  # external case / incident ID
    tenant_id: str = "default"

    # Raw input
    alert_summary: str = ""
    raw_alert: dict[str, Any] = Field(default_factory=dict)

    # Per-agent outputs (populated progressively)
    recon: ReconFindings = Field(default_factory=ReconFindings)
    forensic: ForensicFindings = Field(default_factory=ForensicFindings)
    responder: ResponderPlan = Field(default_factory=ResponderPlan)
    report_md: str = ""
    report_html: str = ""

    # Shared enrichment cache (IOC → enrichment result)
    enrichment_cache: dict[str, Any] = Field(default_factory=dict)

    # LLM message history (accumulated for context)
    messages: list[dict[str, Any]] = Field(default_factory=list)

    # Audit trail
    audit_log: list[AuditEntry] = Field(default_factory=list)

    # Control
    status: str = "pending"   # pending | running | completed | failed
    error: str | None = None
    iteration: int = 0
    max_iterations: int = 6

    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None

    # ---------- helpers ----------

    def log(self, kind: StepKind, agent: str, summary: str, **meta: Any) -> None:
        self.audit_log.append(
            AuditEntry(kind=kind, agent=agent, summary=summary, metadata=meta)
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "InvestigatorState":
        return cls.model_validate(d)
