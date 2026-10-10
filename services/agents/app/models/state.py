"""
Agent state models for LangGraph workflows.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

#: Ceiling on the literal prompt / response kept beside a hash. Matches
#: `InvestigatorState`'s, so the two paths truncate at the same point.
_LLM_LITERAL_LIMIT = 8000


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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

    #: Set when the run stopped on its token or model-call budget rather
    #: than finishing. Carried on the state so the console and the ledger
    #: can say "this did not conclude" rather than presenting a partial
    #: run's last verdict as the answer.
    budget_exhausted: bool = False
    budget_exhausted_reason: str | None = None

    #: The model that actually answered this triage, set from the call rather
    #: than from the pin.
    #:
    #: `fused_alert_consumer` stamps a shadow decision with
    #: `getattr(state, "model_used", None)`. The field did not exist, so that
    #: default was the only branch that ever ran and **every shadow decision
    #: recorded a null model** -- which makes per-model agreement, the reason
    #: the column exists, empty on every deployment.
    #:
    #: `None` means "no model answered", which is the honest value on the
    #: deterministic path. It is deliberately not defaulted to a pin name: a
    #: non-null column that nobody wrote is worse than an empty one, because
    #: it reads as a measurement.
    model_used: str | None = None

    # Identifiers
    run_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    tenant_id: UUID
    task: AgentTask = AgentTask.INVESTIGATION
    status: AgentStatus = AgentStatus.PENDING

    # Input
    alert_summary: str = ""
    raw_alert: dict[str, Any] = Field(default_factory=dict)

    # Durable statements compiled from repeated analyst disagreement for this
    # tenant (services/api analyst_feedback). Carried on the state rather than
    # fetched inside the agent so the network read happens once per alert on
    # the worker's own timeline, and so a test can set it directly.
    organisation_memory: list[dict[str, Any]] = Field(default_factory=list)

    # The tenant skill that matched this alert, if any, and the version of it.
    # Carried for the same reason organisation memory is, plus one more: this
    # is the provenance a disputed verdict is explained from months later, so
    # it travels with the verdict rather than being recoverable only by
    # re-running the resolver against a store that has since changed.
    # `{"skill_id": ..., "version": N, "ref": "id@vN", "owner": ...}`.
    tenant_skill: dict[str, Any] | None = None

    # Knowledge-base runbook chunks retrieved for this alert, as
    # `app.context.knowledge_base.RunbookRetrieval.as_state()` renders them:
    # the chunks, the markers a citation resolves through, and what the
    # retrieval refused. Carried for the same reasons as the two above.
    #
    # A dict rather than the dataclass because this module sits below
    # `app.context`, whose package import reaches back here through
    # `bundle.py`. A type annotation is not worth an import cycle.
    knowledge_base: dict[str, Any] | None = None

    #: True when the prompt-injection guard refused any evidence retrieved
    #: for this alert. Carried onto the per-signature outcome prior, so a
    #: benign disposition reached through attacker-reachable text can never
    #: auto-close a later alert with the same signature.
    #:
    #: A field rather than a lookup at suppression time: by then the
    #: retrieval is gone, and recomputing it would mean re-running the guard
    #: over text the triage no longer holds.
    injection_suspected: bool = False

    # The last few analyst decisions on alerts of this shape, as
    # `app.context.dispositions.RecentDispositions.as_state()` renders them,
    # and the directory record for the principals this alert names, as
    # `app.context.identity.IdentityContext.as_state()` renders it. Dicts
    # rather than the dataclasses for the same import-cycle reason as above.
    recent_dispositions: dict[str, Any] | None = None
    identity_context: dict[str, Any] | None = None

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

    # Pre-fetched investigation context (graph neighbourhood, blast radius,
    # historical verdicts, UEBA baselines, TI matches). Built on the escalation
    # path so an auto-escalated alert is investigated with the same context an
    # analyst-initiated investigation of the same alert would have had.
    context_bundle: dict[str, Any] | None = None

    # Fraction of the concrete indicators cited in the reasoning that actually
    # appear in the evidence (see app/confidence/groundedness.py). None means
    # the verdict was not scored. Recorded alongside the verdict so an
    # ungrounded auto-closure is visible after the fact, not just at the time.
    groundedness: float | None = None

    # What the recursive investigation actually did: which strategy was
    # selected, how many distinct pivots it took, whether it hit its
    # iteration cap or time budget, and which data classes it could not
    # check. Recorded rather than inferred, because a narrative is not
    # evidence that anything was looked at — an investigation that called
    # one tool and wrote three paragraphs reads identically to one that
    # pivoted five times. This is what the depth gate grades.
    investigation_depth: dict[str, Any] | None = None

    # The literal model calls this run made, in order (issue #1276).
    #
    # The auto-triage ledger recorded a verdict and nothing a reader could
    # check it against: no prompt, and `input_hash`/`output_hash` null on
    # every step. A verdict with no recorded prompt cannot be replayed, and
    # replay is what `aisoc_explain_step` is documented to provide.
    #
    # The convention is the manual path's, not a second one: the hash is
    # over the full text and is always present, while the literal copy is
    # truncated, because these payloads carry customer data. Written by
    # `record_llm_exchange`; read by `ledger.persist_auto_triage`.
    llm_exchanges: list[dict[str, Any]] = Field(default_factory=list)

    # Metadata
    iteration_count: int = 0
    max_iterations: int = 10
    error: str | None = None

    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None

    def add_finding(self, finding: str) -> None:
        self.findings.append(finding)

    def record_llm_exchange(
        self,
        *,
        agent: str,
        purpose: str,
        model: str | None,
        prompt: str | list[dict[str, Any]],
        response: str,
        duration_ms: int,
    ) -> dict[str, Any]:
        """Record one model call so the verdict it produced can be replayed.

        Mirrors ``InvestigatorState.log_llm_prompt`` /
        ``log_llm_response`` on the manual path: a SHA-256 over the full
        text always, a truncated literal for a human reader. The two
        differ only in shape — the manual path appends two audit entries,
        this one records a single call with both of its hashes, because
        the ledger row it becomes carries ``input_hash`` and
        ``output_hash`` on the same event.
        """
        prompt_text = prompt if isinstance(prompt, str) else json.dumps(prompt, sort_keys=True, default=str)
        exchange = {
            "agent": agent,
            "purpose": purpose,
            "model": model,
            "prompt": prompt_text[:_LLM_LITERAL_LIMIT],
            "prompt_truncated": len(prompt_text) > _LLM_LITERAL_LIMIT,
            "response": response[:_LLM_LITERAL_LIMIT],
            "response_truncated": len(response) > _LLM_LITERAL_LIMIT,
            "input_hash": _stable_hash(prompt_text),
            "output_hash": _stable_hash(response),
            "duration_ms": int(duration_ms),
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.llm_exchanges.append(exchange)
        return exchange

    def to_dict(self) -> dict:
        return self.model_dump(mode="json")
