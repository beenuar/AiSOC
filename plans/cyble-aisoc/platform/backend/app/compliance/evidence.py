"""Compliance evidence-pack generator (Reporter sub-mode).

Given a case, produce a structured evidence pack that maps the
platform's controls + audit trail to specific SOC2 / ISO27001 / PCI
DSS / HIPAA control IDs. The pack is the JSON form of what an auditor
asks for during a Type II audit:

    "Show me the security incident process operating effectively."

Inputs:

- The :class:`Case` row (verdict, severity, status, narrative).
- Every :class:`AgentTrace` row (the "why did the agent do that?"
  trail).
- Every :class:`ToolCall` row (forward + paired rollback).
- Every :class:`HitlRequest` row (analyst approval / denial / MFA
  receipt hash).
- The counterfactual why-not facts from
  :func:`app.explain.counterfactual.explain_case`.

Outputs:

- ``framework_summary``: per-framework PASS / FAIL roll-up.
- ``controls``: a list of :class:`ControlMapping` rows. Each row cites
  the control id, the platform feature that satisfies it, and the
  evidence rows (trace ids / tool call ids / hitl request ids) that
  prove it operated for *this* case.
- ``audit_pack``: a flat blob of the underlying rows so the auditor
  can pivot off the same JSON without a second API call.

Design rules:

- Read-only and deterministic: same inputs produce the same pack.
- No LLM call: control mappings are a static rubric, not a generated
  narrative. The free-form narrative belongs to the existing Reporter.
- Tenant-scoped: every query filters on ``tenant_id`` before the row
  leaves the session.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from sqlmodel import select

from app.db import session_scope
from app.explain import explain_case
from app.models.case import Case, CaseStatus, Severity, Verdict
from app.models.hitl import HitlRequest, HitlState
from app.models.tool_call import ToolCall
from app.models.trace import AgentTrace, TraceStep


SUPPORTED_FRAMEWORKS = ("soc2", "iso27001", "pci_dss", "hipaa")


@dataclass
class ControlMapping:
    """One framework control row in the evidence pack."""

    framework: str
    control_id: str
    title: str
    description: str
    status: str  # "satisfied" | "partial" | "not_applicable" | "gap"
    evidence: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComplianceEvidence:
    case_id: int
    tenant_id: str
    frameworks: list[str]
    framework_summary: dict[str, dict[str, int]] = field(default_factory=dict)
    controls: list[ControlMapping] = field(default_factory=list)
    audit_pack: dict[str, Any] = field(default_factory=dict)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["generated_at"] = self.generated_at.isoformat()
        return out


# ─── Snapshot ───────────────────────────────────────────────────────


def _snapshot(case_id: int, tenant_id: str) -> Optional[dict[str, Any]]:
    with session_scope() as session:
        case = session.get(Case, case_id)
        if case is None or case.tenant_id != tenant_id:
            return None

        traces = list(
            session.exec(
                select(AgentTrace)
                .where(AgentTrace.case_id == case_id)
                .where(AgentTrace.tenant_id == tenant_id)
                .order_by(AgentTrace.created_at.asc())
            ).all()
        )
        tool_calls = list(
            session.exec(
                select(ToolCall)
                .where(ToolCall.case_id == case_id)
                .where(ToolCall.tenant_id == tenant_id)
                .order_by(ToolCall.id.asc())
            ).all()
        )
        hitl = list(
            session.exec(
                select(HitlRequest)
                .where(HitlRequest.case_id == case_id)
                .where(HitlRequest.tenant_id == tenant_id)
                .order_by(HitlRequest.created_at.asc())
            ).all()
        )

        return {
            "case": {
                "id": case.id,
                "tenant_id": case.tenant_id,
                "title": case.title,
                "status": case.status.value
                if isinstance(case.status, CaseStatus)
                else str(case.status),
                "severity": case.severity.value
                if isinstance(case.severity, Severity)
                else str(case.severity),
                "verdict": case.verdict.value
                if isinstance(case.verdict, Verdict)
                else str(case.verdict),
                "confidence": float(case.confidence or 0.0),
                "affected_users": list(case.affected_users or []),
                "affected_hosts": list(case.affected_hosts or []),
                "iocs": list(case.iocs or []),
                "mitre_techniques": list(case.mitre_techniques or []),
                "narrative": case.narrative or "",
                "created_at": case.created_at.isoformat()
                if case.created_at
                else None,
                "closed_at": case.closed_at.isoformat()
                if case.closed_at
                else None,
            },
            "traces": [
                {
                    "id": t.id,
                    "agent": str(t.agent.value if hasattr(t.agent, "value") else t.agent),
                    "step": t.step.value
                    if isinstance(t.step, TraceStep)
                    else str(t.step),
                    "summary": t.summary,
                    "created_at": t.created_at.isoformat()
                    if t.created_at
                    else None,
                }
                for t in traces
            ],
            "tool_calls": [
                {
                    "id": tc.id,
                    "tool_name": tc.tool_name,
                    "integration": tc.integration,
                    "risk_class": tc.risk_class.value
                    if hasattr(tc.risk_class, "value")
                    else str(tc.risk_class),
                    "success": bool(tc.success),
                    "rollback_of_id": tc.rollback_of_id,
                    "rolled_back_at": tc.rolled_back_at.isoformat()
                    if tc.rolled_back_at
                    else None,
                    "rolled_back_by": tc.rolled_back_by,
                    "hitl_required": bool(tc.hitl_required),
                    "hitl_approved_by": tc.hitl_approved_by,
                    "duration_ms": tc.duration_ms,
                }
                for tc in tool_calls
            ],
            "hitl": [
                {
                    "id": h.id,
                    "tool_name": h.tool_name,
                    "integration": h.integration,
                    "state": h.state.value
                    if isinstance(h.state, HitlState)
                    else str(h.state),
                    "decided_by": h.decided_by,
                    "decided_at": h.decided_at.isoformat()
                    if h.decided_at
                    else None,
                    "decision_reason": h.decision_reason,
                    "mfa_method": getattr(h, "mfa_method", None),
                    "mfa_receipt_hash": getattr(h, "mfa_receipt_hash", None),
                    "blast_radius_keys": sorted((h.blast_radius or {}).keys()),
                }
                for h in hitl
            ],
        }


# ─── Control mapping rubric ─────────────────────────────────────────


def _control(
    *,
    framework: str,
    control_id: str,
    title: str,
    description: str,
    status: str,
    evidence: list[dict[str, Any]] | None = None,
    notes: str = "",
) -> ControlMapping:
    return ControlMapping(
        framework=framework,
        control_id=control_id,
        title=title,
        description=description,
        status=status,
        evidence=evidence or [],
        notes=notes,
    )


def _evidence_traces(snapshot: dict[str, Any], step: str) -> list[dict[str, Any]]:
    return [
        {"trace_id": t["id"], "summary": t["summary"]}
        for t in snapshot["traces"]
        if t["step"] == step
    ]


def _evidence_tool_calls(
    snapshot: dict[str, Any], *, hitl_required: bool | None = None
) -> list[dict[str, Any]]:
    rows = snapshot["tool_calls"]
    if hitl_required is not None:
        rows = [tc for tc in rows if tc["hitl_required"] == hitl_required]
    return [
        {
            "tool_call_id": tc["id"],
            "tool_name": tc["tool_name"],
            "risk_class": tc["risk_class"],
            "approved_by": tc["hitl_approved_by"],
        }
        for tc in rows
    ]


def _evidence_hitl(
    snapshot: dict[str, Any], *, state: str | None = None
) -> list[dict[str, Any]]:
    rows = snapshot["hitl"]
    if state is not None:
        rows = [h for h in rows if h["state"] == state]
    return [
        {
            "hitl_request_id": h["id"],
            "tool_name": h["tool_name"],
            "decided_by": h["decided_by"],
            "decision_reason": h["decision_reason"],
            "blast_radius_keys": h["blast_radius_keys"],
        }
        for h in rows
    ]


def _evidence_rollbacks(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "tool_call_id": tc["id"],
            "rollback_of_id": tc["rollback_of_id"],
            "rolled_back_at": tc["rolled_back_at"],
            "rolled_back_by": tc["rolled_back_by"],
        }
        for tc in snapshot["tool_calls"]
        if tc["rollback_of_id"] is not None or tc["rolled_back_at"] is not None
    ]


def _build_soc2(snapshot: dict[str, Any]) -> list[ControlMapping]:
    out: list[ControlMapping] = []

    decisions = _evidence_traces(snapshot, TraceStep.DECISION.value)
    out.append(
        _control(
            framework="soc2",
            control_id="CC2.1",
            title="Information for the operation of internal control",
            description=(
                "Verdicts and decisions taken on the case are durably "
                "logged in the AgentTrace stream and reproducible from "
                "tool-call evidence."
            ),
            status="satisfied" if decisions else "gap",
            evidence=decisions,
        )
    )

    out.append(
        _control(
            framework="soc2",
            control_id="CC4.1",
            title="Monitoring activities",
            description=(
                "Continuous detection validation, scheduled exposure / "
                "supply-chain sweeps, and the open-benchmark suite "
                "verify the platform's controls operate as expected."
            ),
            status="satisfied",
            notes=(
                "Evidence is platform-level rather than per-case; see "
                "/benchmark/leaderboard and /redteam/leaderboard."
            ),
        )
    )

    hitl_decisions = _evidence_hitl(snapshot)
    out.append(
        _control(
            framework="soc2",
            control_id="CC6.1",
            title="Logical access security",
            description=(
                "Privileged actions (containment, IdP changes, IAM "
                "changes) are gated by HITL approval with MFA receipt."
            ),
            status="satisfied" if hitl_decisions else "not_applicable",
            evidence=hitl_decisions,
            notes=(
                "Per-decision MFA hash + reason are persisted with the "
                "HITL row."
            ),
        )
    )

    rollbacks = _evidence_rollbacks(snapshot)
    out.append(
        _control(
            framework="soc2",
            control_id="CC7.3",
            title="System recovery — undo / rollback",
            description=(
                "Reversible actions are paired with a rollback handler "
                "and the platform's rollback service emits paired "
                "ToolCall rows on undo."
            ),
            status="satisfied" if rollbacks else "not_applicable",
            evidence=rollbacks,
        )
    )

    out.append(
        _control(
            framework="soc2",
            control_id="CC7.4",
            title="Security incident management",
            description=(
                "The case represents the documented incident-management "
                "cycle: detection, triage, investigation, containment, "
                "reporting, post-mortem (counterfactual why-not facts)."
            ),
            status="satisfied",
            evidence=[
                {
                    "case_id": snapshot["case"]["id"],
                    "status": snapshot["case"]["status"],
                    "verdict": snapshot["case"]["verdict"],
                }
            ],
        )
    )

    return out


def _build_iso(snapshot: dict[str, Any]) -> list[ControlMapping]:
    out: list[ControlMapping] = []

    out.append(
        _control(
            framework="iso27001",
            control_id="A.5.24",
            title="Information security incident management planning",
            description=(
                "The agent mesh executes the documented incident-"
                "management runbook: detect, triage, investigate, "
                "contain, report."
            ),
            status="satisfied",
        )
    )
    out.append(
        _control(
            framework="iso27001",
            control_id="A.5.25",
            title="Assessment and decision on information security events",
            description=(
                "AgentTrace entries with step=DECISION record the "
                "platform's assessment of the event and the rationale."
            ),
            status="satisfied"
            if _evidence_traces(snapshot, TraceStep.DECISION.value)
            else "gap",
            evidence=_evidence_traces(snapshot, TraceStep.DECISION.value),
        )
    )
    out.append(
        _control(
            framework="iso27001",
            control_id="A.5.26",
            title="Response to information security incidents",
            description=(
                "Containment tool calls executed against the affected "
                "entities, gated by HITL where applicable."
            ),
            status="satisfied"
            if snapshot["tool_calls"]
            else "not_applicable",
            evidence=_evidence_tool_calls(snapshot),
        )
    )
    out.append(
        _control(
            framework="iso27001",
            control_id="A.8.16",
            title="Monitoring activities",
            description=(
                "Continuous detection validation runs the synthetic "
                "OCSF catalogue against live rules to surface drift "
                "and coverage regressions."
            ),
            status="satisfied",
            notes="Evidence is platform-level via the BAS scheduler.",
        )
    )
    return out


def _build_pci(snapshot: dict[str, Any]) -> list[ControlMapping]:
    out: list[ControlMapping] = []
    out.append(
        _control(
            framework="pci_dss",
            control_id="10.6",
            title="Review logs of all system components",
            description=(
                "Tool-call audit + AgentTrace provide a tamper-evident "
                "record of every component touched during the case."
            ),
            status="satisfied",
            evidence=_evidence_tool_calls(snapshot),
        )
    )
    out.append(
        _control(
            framework="pci_dss",
            control_id="12.10",
            title="Implement an incident response plan",
            description=(
                "Case lifecycle is the documented incident response "
                "plan; closure status records the outcome."
            ),
            status="satisfied",
            evidence=[
                {
                    "case_id": snapshot["case"]["id"],
                    "status": snapshot["case"]["status"],
                }
            ],
        )
    )
    return out


def _build_hipaa(snapshot: dict[str, Any]) -> list[ControlMapping]:
    out: list[ControlMapping] = []
    out.append(
        _control(
            framework="hipaa",
            control_id="164.308(a)(6)",
            title="Security incident procedures",
            description=(
                "Cases drive a documented response procedure with "
                "HITL gating on any action that could affect access "
                "to ePHI."
            ),
            status="satisfied"
            if snapshot["hitl"]
            else "partial",
            evidence=_evidence_hitl(snapshot),
            notes=(
                "If the affected asset is tagged as PHI in CMDB, the "
                "dry-run simulator surfaces the data-classification on "
                "the HITL request automatically."
            ),
        )
    )
    out.append(
        _control(
            framework="hipaa",
            control_id="164.312(b)",
            title="Audit controls",
            description=(
                "AgentTrace + ToolCall rows together form the audit "
                "log of every system action taken during the case."
            ),
            status="satisfied",
            evidence=_evidence_traces(snapshot, TraceStep.TOOL_CALL.value),
        )
    )
    return out


_BUILDERS: dict[str, Any] = {
    "soc2": _build_soc2,
    "iso27001": _build_iso,
    "pci_dss": _build_pci,
    "hipaa": _build_hipaa,
}


def _summarise(controls: list[ControlMapping]) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for control in controls:
        bucket = out.setdefault(
            control.framework,
            {"total": 0, "satisfied": 0, "partial": 0, "gap": 0, "not_applicable": 0},
        )
        bucket["total"] += 1
        bucket[control.status] = bucket.get(control.status, 0) + 1
    return out


# ─── Public API ─────────────────────────────────────────────────────


def build_evidence_pack(
    *,
    case_id: int,
    tenant_id: str,
    frameworks: list[str] | None = None,
) -> Optional[ComplianceEvidence]:
    """Generate a multi-framework compliance evidence pack for a case.

    ``frameworks`` defaults to all supported frameworks. Pass a subset
    when the tenant only operates under one regime.
    """
    snapshot = _snapshot(case_id, tenant_id)
    if snapshot is None:
        return None
    selected = frameworks or list(SUPPORTED_FRAMEWORKS)
    controls: list[ControlMapping] = []
    for fw in selected:
        builder = _BUILDERS.get(fw)
        if builder is None:
            continue
        controls.extend(builder(snapshot))

    cf = explain_case(case_id=case_id, tenant_id=tenant_id)
    audit_pack = {
        "case": snapshot["case"],
        "traces": snapshot["traces"],
        "tool_calls": snapshot["tool_calls"],
        "hitl": snapshot["hitl"],
        "counterfactual": cf.to_dict() if cf is not None else None,
    }
    return ComplianceEvidence(
        case_id=snapshot["case"]["id"],
        tenant_id=snapshot["case"]["tenant_id"],
        frameworks=selected,
        framework_summary=_summarise(controls),
        controls=controls,
        audit_pack=audit_pack,
    )
