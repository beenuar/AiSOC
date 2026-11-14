"""Counterfactual why-not explanations (t4-counterfactual).

Every closed case raises the same audit-grade questions:

    "Why was this user not disabled?"
    "Why was this host not isolated?"
    "Why was the case not escalated to Tier 2?"
    "Why wasn't a takedown filed for this brand impersonation?"

The traditional SOC answer ("the analyst made a judgement call") is the
one regulators trust the *least*. This module produces a structured,
evidence-grounded answer for every plausible-but-not-taken action by:

1. Walking the case's :class:`AgentTrace` to learn what each agent
   *considered* (``THINK`` / ``DECISION`` steps) and what it *did*
   (``TOOL_CALL`` / ``HANDOFF`` steps).
2. Walking the case's :class:`ToolCall` history to learn what was
   actually executed.
3. Walking the case's :class:`HitlRequest` history to learn what was
   *proposed* but blocked by an analyst (denied / timed out / rolled
   back).
4. Cross-referencing the catalogue of remediation tools registered for
   the case's tenant to identify *plausible* tools that were never
   even attempted, and producing a one-line counterfactual reason
   ("CMDB criticality is unknown — agent declined to isolate without
   business-owner approval"; "verdict was false_positive — no
   containment was warranted").

The output is intentionally *facts*, not prose — the case-file UI
renders each fact as a row, and the Reporter sub-mode (t4-compliance)
folds them into the SOC2 evidence pack. No LLM call here; the inputs
are deterministic database rows.

Design rules:

- Read-only against the live environment. The function takes
  ``(case_id, tenant_id)`` and returns a snapshot — no DB writes, no
  external IO.
- Tenant-scoped: every query is filtered by ``tenant_id``.
- Cheap: a single short scope opens a SQLite session, snapshots the
  rows we need, and exits before any analysis runs. Total wall-clock
  on the demo DB is sub-millisecond.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from sqlmodel import select

from app.db import session_scope
from app.models.case import Case, CaseStatus, Severity, Verdict
from app.models.hitl import HitlRequest, HitlState
from app.models.tool_call import RiskClass, ToolCall
from app.models.trace import AgentName, AgentTrace, TraceStep
from app.tools.registry import ToolDef, registry as tool_registry


# Tools that materially change the case posture and therefore deserve a
# "why-not" explanation when they are *not* called. Keep this list
# small on purpose — pulling 40 facts per case dilutes the signal.
_ACTIONABLE_TOOLS: list[str] = [
    "edr.isolate_host",
    "edr.kill_process",
    "edr.quarantine_file",
    "idp.disable_user",
    "idp.revoke_sessions",
    "idp.reset_password",
    "saas.revoke_oauth_grant",
    "cloud.deactivate_access_key",
    "cloud.disable_iam_user",
    "comms.notify_owner",
    "ticketing.open_ticket",
]


@dataclass
class CounterfactualFact:
    """One why-not row, ready to render in the case-file UI."""

    question: str
    answer: str
    evidence: list[str] = field(default_factory=list)
    # One of: "verdict", "tool_skipped", "tool_blocked", "agent_skipped",
    # "escalation", "containment", "no_change".
    category: str = "no_change"
    # Tool name when the fact is about a specific tool the platform did
    # NOT call; empty when the fact is about an agent or verdict.
    tool_name: Optional[str] = None
    # Whether the lack of action was a *correct* decision given the
    # available evidence (so the audit pack can summarise as
    # "controls operated as designed, X / Y items").
    was_appropriate: bool = True


@dataclass
class CaseExplanation:
    """Snapshot returned by :func:`explain_case`."""

    case_id: int
    tenant_id: str
    verdict: str
    severity: str
    status: str
    facts: list[CounterfactualFact] = field(default_factory=list)
    # Convenience aggregates for the case-file UI traffic-light.
    facts_total: int = 0
    facts_appropriate: int = 0
    facts_questionable: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── Internal data classes ───────────────────────────────────────────


@dataclass
class _CaseSnapshot:
    """Plain-data view of a case and its audit trail.

    We snapshot field-by-field inside a single ``session_scope`` and let
    the session close *before* any analysis runs so SQLAlchemy never
    raises ``DetachedInstanceError`` on attribute access — the same
    pattern the actor profiler and supply-chain agents use.
    """

    case_id: int
    tenant_id: str
    verdict: str
    severity: str
    status: str
    confidence: float
    affected_users: list[str]
    affected_hosts: list[str]
    iocs: list[str]
    response_actions: list[dict[str, Any]]
    traces: list[dict[str, Any]]
    tool_calls: list[dict[str, Any]]
    hitl_requests: list[dict[str, Any]]


def _snapshot_case(case_id: int, tenant_id: str) -> Optional[_CaseSnapshot]:
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

        return _CaseSnapshot(
            case_id=case.id,
            tenant_id=case.tenant_id,
            verdict=case.verdict.value
            if isinstance(case.verdict, Verdict)
            else str(case.verdict),
            severity=case.severity.value
            if isinstance(case.severity, Severity)
            else str(case.severity),
            status=case.status.value
            if isinstance(case.status, CaseStatus)
            else str(case.status),
            confidence=float(case.confidence or 0.0),
            affected_users=list(case.affected_users or []),
            affected_hosts=list(case.affected_hosts or []),
            iocs=list(case.iocs or []),
            response_actions=list(case.response_actions or []),
            traces=[
                {
                    "agent": t.agent.value
                    if isinstance(t.agent, AgentName)
                    else str(t.agent),
                    "step": t.step.value
                    if isinstance(t.step, TraceStep)
                    else str(t.step),
                    "summary": t.summary,
                    "detail": dict(t.detail or {}),
                }
                for t in traces
            ],
            tool_calls=[
                {
                    "tool_name": tc.tool_name,
                    "integration": tc.integration,
                    "success": bool(tc.success),
                    "error": tc.error,
                    "params": dict(tc.params or {}),
                    "result": dict(tc.result or {}),
                    "rolled_back_at": tc.rolled_back_at.isoformat()
                    if tc.rolled_back_at
                    else None,
                }
                for tc in tool_calls
            ],
            hitl_requests=[
                {
                    "id": h.id,
                    "tool_name": h.tool_name,
                    "integration": h.integration,
                    "state": h.state.value
                    if isinstance(h.state, HitlState)
                    else str(h.state),
                    "decided_by": h.decided_by,
                    "decision_reason": h.decision_reason,
                }
                for h in hitl
            ],
        )


# ─── Fact generators ────────────────────────────────────────────────


def _verdict_fact(snapshot: _CaseSnapshot) -> CounterfactualFact:
    """Why was the verdict X (and not the alternative)?"""
    verdict = snapshot.verdict
    if verdict == Verdict.TRUE_POSITIVE.value:
        return CounterfactualFact(
            question="Why was this case classified as a true positive?",
            answer=(
                f"The agent mesh found at least one independent piece of "
                f"evidence supporting malicious intent and classified at "
                f"confidence={snapshot.confidence:.2f}."
            ),
            evidence=_evidence_summary(snapshot),
            category="verdict",
            was_appropriate=True,
        )
    if verdict in {
        Verdict.FALSE_POSITIVE.value,
        Verdict.BENIGN.value,
    }:
        return CounterfactualFact(
            question="Why was this case closed without containment?",
            answer=(
                f"The agent mesh ruled the case {verdict} at "
                f"confidence={snapshot.confidence:.2f} based on the "
                "evidence below; no containment action was warranted."
            ),
            evidence=_evidence_summary(snapshot),
            category="verdict",
            was_appropriate=True,
        )
    if verdict == Verdict.NEEDS_HUMAN.value:
        return CounterfactualFact(
            question="Why was the case escalated to a human analyst?",
            answer=(
                "The agent mesh could not reach a confident verdict from "
                "the available evidence and routed the case to HITL for "
                "human judgement."
            ),
            evidence=_evidence_summary(snapshot),
            category="escalation",
            was_appropriate=True,
        )
    return CounterfactualFact(
        question="Why is the case verdict still UNKNOWN?",
        answer=(
            "The agent mesh has not yet reached a verdict for this case. "
            "If the case is OPEN this is expected; if CLOSED with "
            "verdict=UNKNOWN, this is an audit gap and should be "
            "investigated."
        ),
        evidence=_evidence_summary(snapshot),
        category="verdict",
        was_appropriate=snapshot.status
        not in {
            CaseStatus.CLOSED_TRUE_POSITIVE.value,
            CaseStatus.CLOSED_FALSE_POSITIVE.value,
            CaseStatus.CLOSED_BENIGN.value,
        },
    )


def _evidence_summary(snapshot: _CaseSnapshot) -> list[str]:
    """Compact human-readable evidence list pulled from the case."""
    out: list[str] = []
    if snapshot.iocs:
        out.append(f"IOCs on case: {', '.join(snapshot.iocs[:5])}")
    if snapshot.affected_users:
        out.append(
            f"Affected users: {', '.join(snapshot.affected_users[:5])}"
        )
    if snapshot.affected_hosts:
        out.append(
            f"Affected hosts: {', '.join(snapshot.affected_hosts[:5])}"
        )
    if snapshot.tool_calls:
        names = sorted({tc["tool_name"] for tc in snapshot.tool_calls})
        out.append(f"Tools called: {', '.join(names)}")
    decisions = [t for t in snapshot.traces if t["step"] == TraceStep.DECISION.value]
    if decisions:
        last = decisions[-1]
        out.append(f"Last decision ({last['agent']}): {last['summary']}")
    return out


def _hitl_outcome_for(
    *, snapshot: _CaseSnapshot, tool_name: str
) -> Optional[dict[str, Any]]:
    """Most recent HITL request for ``tool_name`` on this case, if any."""
    matches = [
        h for h in snapshot.hitl_requests if h["tool_name"] == tool_name
    ]
    return matches[-1] if matches else None


def _tool_called(*, snapshot: _CaseSnapshot, tool_name: str) -> bool:
    return any(tc["tool_name"] == tool_name for tc in snapshot.tool_calls)


def _tool_relevant_to_case(td: ToolDef, snapshot: _CaseSnapshot) -> bool:
    """Heuristic: should we explain why this tool was *not* called?

    A tool is relevant iff the case has at least one entity it can act
    on. ``edr.isolate_host`` is irrelevant when no host is on the case;
    ``idp.disable_user`` is irrelevant when no user is.
    """
    if td.name.startswith("edr."):
        return bool(snapshot.affected_hosts)
    if td.name.startswith("idp.") or td.name.startswith("saas."):
        return bool(snapshot.affected_users)
    if td.name.startswith("cloud."):
        return bool(snapshot.affected_users) or bool(snapshot.iocs)
    return True


def _tool_skipped_fact(
    *, td: ToolDef, snapshot: _CaseSnapshot
) -> Optional[CounterfactualFact]:
    """Build the fact for a plausible-but-skipped tool, or None to omit."""
    if _tool_called(snapshot=snapshot, tool_name=td.name):
        return None
    if not _tool_relevant_to_case(td, snapshot):
        return None

    hitl = _hitl_outcome_for(snapshot=snapshot, tool_name=td.name)
    label = _tool_label(td)

    # 1. The agent proposed it but a HITL review denied / timed out.
    if hitl is not None:
        state = hitl["state"]
        if state == HitlState.DENIED.value:
            who = hitl.get("decided_by") or "the analyst"
            reason = hitl.get("decision_reason") or "no reason recorded"
            return CounterfactualFact(
                question=f"Why was {label} not executed?",
                answer=(
                    f"The agent proposed {td.name} but {who} denied the "
                    f"HITL request: {reason}"
                ),
                evidence=[f"hitl_request_id={hitl.get('id')}", f"state={state}"],
                category="tool_blocked",
                tool_name=td.name,
                was_appropriate=True,
            )
        if state == HitlState.TIMEOUT.value:
            return CounterfactualFact(
                question=f"Why was {label} not executed?",
                answer=(
                    f"The agent proposed {td.name} but the HITL approval "
                    "request timed out without a decision; per platform "
                    "policy, timeouts default to deny."
                ),
                evidence=[
                    f"hitl_request_id={hitl.get('id')}",
                    f"state={state}",
                ],
                category="tool_blocked",
                tool_name=td.name,
                was_appropriate=True,
            )
        if state == HitlState.PENDING.value:
            return CounterfactualFact(
                question=f"Why has {label} not yet executed?",
                answer=(
                    f"The agent proposed {td.name} and the HITL approval "
                    "request is still PENDING. Waiting on analyst decision."
                ),
                evidence=[f"hitl_request_id={hitl.get('id')}"],
                category="tool_blocked",
                tool_name=td.name,
                was_appropriate=True,
            )

    # 2. The case verdict was benign / false-positive / unknown — no
    #    containment was warranted.
    if snapshot.verdict in {
        Verdict.FALSE_POSITIVE.value,
        Verdict.BENIGN.value,
    }:
        return CounterfactualFact(
            question=f"Why was {label} not executed?",
            answer=(
                f"Case verdict was {snapshot.verdict}; no containment "
                "action was warranted."
            ),
            evidence=_evidence_summary(snapshot),
            category="containment",
            tool_name=td.name,
            was_appropriate=True,
        )
    if snapshot.verdict == Verdict.UNKNOWN.value and snapshot.status not in {
        CaseStatus.CLOSED_TRUE_POSITIVE.value,
        CaseStatus.CLOSED_FALSE_POSITIVE.value,
        CaseStatus.CLOSED_BENIGN.value,
    }:
        return CounterfactualFact(
            question=f"Why has {label} not yet executed?",
            answer=(
                "Case has not yet reached a verdict; the agent mesh has "
                "not requested this action."
            ),
            evidence=_evidence_summary(snapshot),
            category="containment",
            tool_name=td.name,
            was_appropriate=True,
        )

    # 3. True positive: drill down per-category before flagging the
    #    skip as questionable. The audit pack should only get
    #    "was_appropriate=False" rows for *real* coverage gaps, not for
    #    the dozen alternative tools the agent didn't need to call.
    if snapshot.verdict == Verdict.TRUE_POSITIVE.value:
        # If a denied / pending HITL exists for *another* tool in the
        # same family, the analyst already engaged on containment;
        # treat sibling tools as appropriate skips.
        family = _tool_family(td.name)
        sibling_engaged = any(
            _tool_family(h["tool_name"]) == family
            and h["state"]
            in {HitlState.DENIED.value, HitlState.TIMEOUT.value, HitlState.PENDING.value}
            for h in snapshot.hitl_requests
        )
        # If any sibling tool in the same family actually executed, the
        # containment problem was solved through that path; this row is
        # appropriate.
        sibling_executed = any(
            _tool_family(tc["tool_name"]) == family
            and tc.get("success", True)
            for tc in snapshot.tool_calls
        )
        appropriate = sibling_engaged or sibling_executed
        return CounterfactualFact(
            question=f"Why was {label} not executed?",
            answer=(
                f"Case is a true positive but the agent mesh did not "
                f"propose {td.name}. "
                + (
                    "Sibling containment tool engaged for the same "
                    "entity — sufficient coverage."
                    if appropriate
                    else "No paired containment tool was attempted; "
                    "review the routing for a coverage gap."
                )
            ),
            evidence=_evidence_summary(snapshot),
            category="containment",
            tool_name=td.name,
            was_appropriate=appropriate,
        )

    return None


def _tool_family(tool_name: str) -> str:
    """Coarse grouping for sibling-aware coverage checks ("edr", "idp")."""
    return tool_name.split(".", 1)[0] if "." in tool_name else tool_name


def _tool_label(td: ToolDef) -> str:
    """User-facing description for a tool ('Isolate the affected host')."""
    if td.name == "edr.isolate_host":
        return "host isolation"
    if td.name == "edr.kill_process":
        return "process termination"
    if td.name == "edr.quarantine_file":
        return "file quarantine"
    if td.name == "idp.disable_user":
        return "user disable"
    if td.name == "idp.revoke_sessions":
        return "session revoke"
    if td.name == "idp.reset_password":
        return "password reset"
    if td.name == "saas.revoke_oauth_grant":
        return "OAuth grant revoke"
    if td.name == "cloud.deactivate_access_key":
        return "AWS access-key deactivation"
    if td.name == "cloud.disable_iam_user":
        return "IAM user disable"
    if td.name == "comms.notify_owner":
        return "owner notification"
    if td.name == "ticketing.open_ticket":
        return "ticketing escalation"
    return td.name


def _rolled_back_facts(
    snapshot: _CaseSnapshot,
) -> list[CounterfactualFact]:
    """Why was a previously-executed tool rolled back?"""
    out: list[CounterfactualFact] = []
    for tc in snapshot.tool_calls:
        if tc.get("rolled_back_at") is None:
            continue
        out.append(
            CounterfactualFact(
                question=(
                    f"Why was {tc['tool_name']} rolled back after execution?"
                ),
                answer=(
                    f"The action was reversed via the platform's rollback "
                    f"service at {tc['rolled_back_at']} — typically because "
                    "an analyst classified the case as a false positive or "
                    "the action was no longer warranted."
                ),
                evidence=[
                    f"tool_name={tc['tool_name']}",
                    f"integration={tc['integration']}",
                ],
                category="containment",
                tool_name=tc["tool_name"],
                was_appropriate=True,
            )
        )
    return out


def _agent_skipped_facts(
    snapshot: _CaseSnapshot,
) -> list[CounterfactualFact]:
    """Why didn't agent X get involved on this case?"""
    seen_agents = {t["agent"] for t in snapshot.traces}
    out: list[CounterfactualFact] = []

    if AgentName.RESPONDER.value not in seen_agents and snapshot.verdict in {
        Verdict.TRUE_POSITIVE.value,
        Verdict.NEEDS_HUMAN.value,
    }:
        out.append(
            CounterfactualFact(
                question=(
                    "Why was the Responder not involved on this true-"
                    "positive case?"
                ),
                answer=(
                    "The case was classified as actionable but the "
                    "Responder agent was never invoked. Review the "
                    "Triager/Investigator handoff logic; this may be a "
                    "coverage gap."
                ),
                evidence=_evidence_summary(snapshot),
                category="agent_skipped",
                was_appropriate=False,
            )
        )

    if AgentName.HUNTER.value not in seen_agents and snapshot.verdict in {
        Verdict.TRUE_POSITIVE.value
    }:
        out.append(
            CounterfactualFact(
                question=(
                    "Why was the Hunter not invoked to widen the search?"
                ),
                answer=(
                    "Hunter runs out-of-band on high-severity true "
                    "positives. If it was not invoked here the platform "
                    "may have already swept the IOC space recently, or "
                    "the IOC set on the case was below the Hunter "
                    "threshold."
                ),
                evidence=_evidence_summary(snapshot),
                category="agent_skipped",
                was_appropriate=True,
            )
        )

    return out


# ─── Public API ─────────────────────────────────────────────────────


def explain_case(case_id: int, tenant_id: str) -> Optional[CaseExplanation]:
    """Generate counterfactual why-not facts for a case.

    Returns ``None`` if the case does not exist or is owned by a
    different tenant.
    """
    snapshot = _snapshot_case(case_id, tenant_id)
    if snapshot is None:
        return None

    facts: list[CounterfactualFact] = []
    facts.append(_verdict_fact(snapshot))

    for tool_name in _ACTIONABLE_TOOLS:
        td = tool_registry.get(tool_name)
        if td is None:
            continue
        # Only WRITE-* and DESTRUCTIVE tools are interesting for
        # why-not — READ tools running or not is a non-event.
        if td.risk_class == RiskClass.READ:
            continue
        fact = _tool_skipped_fact(td=td, snapshot=snapshot)
        if fact is not None:
            facts.append(fact)

    facts.extend(_rolled_back_facts(snapshot))
    facts.extend(_agent_skipped_facts(snapshot))

    appropriate = sum(1 for f in facts if f.was_appropriate)
    questionable = sum(1 for f in facts if not f.was_appropriate)

    return CaseExplanation(
        case_id=snapshot.case_id,
        tenant_id=snapshot.tenant_id,
        verdict=snapshot.verdict,
        severity=snapshot.severity,
        status=snapshot.status,
        facts=facts,
        facts_total=len(facts),
        facts_appropriate=appropriate,
        facts_questionable=questionable,
    )
