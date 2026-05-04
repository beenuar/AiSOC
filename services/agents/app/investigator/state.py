"""
Extended state model for the multi-agent investigator pipeline.
Extends the existing InvestigationState with per-agent outputs and audit log.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from app.models.state import InvestigationState  # re-use base model


def _stable_hash(payload: Any) -> str:
    """Deterministic SHA-256 of an arbitrary JSON-serialisable payload.

    Used to fingerprint LLM prompts, tool calls, and evidence so the ledger
    can prove "this exact input produced this exact output" without storing
    the raw blob inline. Sorted keys keep dict ordering deterministic.
    """
    try:
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    except (TypeError, ValueError):
        encoded = str(payload).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class StepKind(str, Enum):
    RECON = "recon"
    FORENSIC = "forensic"
    RESPONDER = "responder"
    REPORTER = "reporter"
    REPORT = "report"
    ERROR = "error"
    TOOL_CALL = "tool_call"
    LLM_CALL = "llm_call"
    LLM_PROMPT = "llm_prompt"
    LLM_RESPONSE = "llm_response"
    EVIDENCE_CITED = "evidence_cited"
    DECISION_REASON = "decision_reason"


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

    def log_entry(self, entry: AuditEntry) -> None:
        """Append a fully-formed entry (used when caller has computed hashes)."""
        self.audit_log.append(entry)

    def log_llm_prompt(
        self,
        agent: str,
        prompt: str | list[dict[str, Any]],
        *,
        model: str | None = None,
        purpose: str = "",
    ) -> str:
        """Record the literal prompt sent to an LLM. Returns the input hash so
        the response event can reference it."""
        meta: dict[str, Any] = {"model": model, "purpose": purpose}
        # Truncate the visible content but always preserve the full hash
        if isinstance(prompt, str):
            meta["prompt"] = prompt[:8000]
            input_hash = _stable_hash(prompt)
        else:
            meta["messages"] = prompt
            input_hash = _stable_hash(prompt)
        self.audit_log.append(
            AuditEntry(
                kind=StepKind.LLM_PROMPT,
                agent=agent,
                summary=purpose or "LLM prompt",
                metadata=meta,
                input_hash=input_hash,
            )
        )
        return input_hash

    def log_llm_response(
        self,
        agent: str,
        response: str,
        *,
        prompt_hash: str | None = None,
        model: str | None = None,
        tokens_used: int = 0,
        latency_ms: int = 0,
        cost_usd: float = 0.0,
    ) -> str:
        """Record the literal LLM response. Returns the output hash."""
        output_hash = _stable_hash(response)
        meta = {
            "response": response[:8000],
            "model": model,
            "tokens_used": tokens_used,
            "cost_usd": cost_usd,
            "prompt_hash": prompt_hash,
        }
        self.audit_log.append(
            AuditEntry(
                kind=StepKind.LLM_RESPONSE,
                agent=agent,
                summary=f"LLM response ({tokens_used} tokens)",
                metadata=meta,
                input_hash=prompt_hash,
                output_hash=output_hash,
                duration_ms=latency_ms,
            )
        )
        return output_hash

    def log_tool_call(
        self,
        agent: str,
        tool_name: str,
        args: dict[str, Any] | None = None,
        result: Any = None,
        *,
        latency_ms: int = 0,
        success: bool = True,
    ) -> None:
        """Record a tool invocation with full I/O capture for replay."""
        args = args or {}
        input_hash = _stable_hash({"tool": tool_name, "args": args})
        output_hash = _stable_hash(result) if result is not None else None
        summary = f"{tool_name}({', '.join(args.keys())})"
        if not success:
            summary = f"{summary} [FAILED]"
        self.audit_log.append(
            AuditEntry(
                kind=StepKind.TOOL_CALL,
                agent=agent,
                summary=summary,
                metadata={
                    "tool": tool_name,
                    "args": args,
                    "result": result,
                    "success": success,
                },
                input_hash=input_hash,
                output_hash=output_hash,
                duration_ms=latency_ms,
            )
        )

    def log_evidence(
        self,
        agent: str,
        evidence_kind: str,
        ref: str,
        *,
        weight: float = 1.0,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Record a piece of evidence the agent cited toward a finding.

        ``evidence_kind`` is short label like 'ioc', 'log_event', 'kb_article',
        'mitre_technique'. ``ref`` is the canonical identifier (URL, id, hash).
        """
        self.audit_log.append(
            AuditEntry(
                kind=StepKind.EVIDENCE_CITED,
                agent=agent,
                summary=f"{evidence_kind}: {ref}",
                metadata={
                    "evidence_kind": evidence_kind,
                    "ref": ref,
                    "weight": weight,
                    **(details or {}),
                },
                output_hash=_stable_hash({"kind": evidence_kind, "ref": ref}),
            )
        )

    def log_decision(
        self,
        agent: str,
        decision: str,
        reason: str,
        *,
        confidence: float = 0.0,
        alternatives: list[str] | None = None,
    ) -> None:
        """Record a decision the agent made and the reasoning chain that
        produced it. This is the "why" view that auditors need."""
        self.audit_log.append(
            AuditEntry(
                kind=StepKind.DECISION_REASON,
                agent=agent,
                summary=f"{decision} (conf={confidence:.2f})",
                metadata={
                    "decision": decision,
                    "reason": reason,
                    "confidence": confidence,
                    "alternatives": alternatives or [],
                },
                output_hash=_stable_hash({"decision": decision, "reason": reason}),
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "InvestigatorState":
        return cls.model_validate(d)
