"""In-memory data models for the closed-loop Exposure agent.

These are *not* SQLModels — they're the working dataclasses the
:class:`ExposureAgent` shuttles between phases. Confirmed exposures are
persisted as ``Case`` rows (the primary unit of work for the SOC) and as
``EXPOSURE`` nodes in the Threat Graph (the durable entity record the
plan calls for at L297). Holding the in-flight findings as dataclasses
keeps the sweep code easy to test and easy to reason about without
prematurely committing every transient CTI hit to a SQL table.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class ExposureKind(str, Enum):
    """The four signal classes Pillar 4 of the plan calls out at L294.

    Each maps 1:1 to a Cyble CTI tool already wired through the global
    tool registry, so the agent's tool surface is constrained at the
    type level rather than via free-form strings.
    """

    DARKWEB_CREDENTIAL = "darkweb_credential"  # cti.darkweb_search hits
    BRAND_TYPOSQUAT = "brand_typosquat"  # cti.brand_intel hits
    ASM_FINDING = "asm_finding"  # cti.asm_lookup hits
    VULN_INTEL = "vuln_intel"  # cti.vuln_intel hits


# Mapping from each exposure kind to the deterministic containment
# spec the Exposure Agent will hand off. None means "no auto-response;
# leave the case at status=NEW for human triage." The actual tool
# invocation is performed by the Responder via its existing allowlist;
# the Exposure Agent only *proposes* the action so the blast-radius
# remains owned by Responder + its HITL gateway.
DEFAULT_RESPONSE_TOOL: dict[ExposureKind, str | None] = {
    ExposureKind.DARKWEB_CREDENTIAL: "idp.reset_password",
    ExposureKind.BRAND_TYPOSQUAT: "ticket.create",  # request takedown ticket
    ExposureKind.ASM_FINDING: "ticket.create",  # remediation ticket
    ExposureKind.VULN_INTEL: "ticket.create",  # patch ticket
}


@dataclass
class ExposureFinding:
    """One normalised CTI hit ready for graph + case materialisation.

    ``key`` is the canonical identity of the exposure inside the Threat
    Graph — it must be stable across sweeps so re-verification can match
    "is the same signal still present". Built as
    ``f"{kind}:{subject}"`` so two CTI tools surfacing the same email
    address or domain collapse onto the same graph node.
    """

    kind: ExposureKind
    tenant_id: str
    subject: str  # the email/domain/asset the exposure is about
    title: str  # short human-readable summary
    narrative: str  # full case narrative seed
    severity: str = "medium"  # mirrors Severity enum strings
    affected_users: list[str] = field(default_factory=list)
    affected_hosts: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    observed_at: datetime = field(default_factory=datetime.utcnow)
    source_tool: str = ""  # which cti.* tool produced this

    @property
    def key(self) -> str:
        return f"{self.kind.value}:{self.subject}"

    @property
    def response_tool(self) -> str | None:
        return DEFAULT_RESPONSE_TOOL.get(self.kind)


@dataclass
class ExposureSweepResult:
    """Summary returned by a single :meth:`ExposureAgent.sweep` call.

    The scheduler logs this object; smoke tests assert against it.
    """

    tenant_id: str
    findings_total: int = 0
    new_findings: int = 0
    cases_opened: list[int] = field(default_factory=list)
    cases_verified_closed: list[int] = field(default_factory=list)
    cases_escalated: list[int] = field(default_factory=list)
    responses_routed: int = 0
    graph_nodes_upserted: int = 0
    graph_edges_upserted: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "findings_total": self.findings_total,
            "new_findings": self.new_findings,
            "cases_opened": list(self.cases_opened),
            "cases_verified_closed": list(self.cases_verified_closed),
            "cases_escalated": list(self.cases_escalated),
            "responses_routed": self.responses_routed,
            "graph_nodes_upserted": self.graph_nodes_upserted,
            "graph_edges_upserted": self.graph_edges_upserted,
            "errors": list(self.errors),
        }
