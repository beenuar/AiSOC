"""Planner / Orchestrator.

Implements the agent topology from the plan:

    Planner ──▶ Triager ──▶ Investigator ──▶ Responder ──▶ Reporter
                  │              │                              │
                  └─ FP/benign ──┴── benign ────────────────────┘
                                                   ↑
                                              Hunter (out-of-band)

Each agent returns a Handoff. The orchestrator routes to the next agent
until `done=True`. Total iteration cap = 8 to prevent runaways.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Callable

from sqlmodel import Session

from app.agents.base import AgentResult, BaseAgent
from app.agents.cdr import CDRAgent
from app.agents.investigator import InvestigatorAgent
from app.agents.itdr import ITDRAgent
from app.agents.phishing_triage import PhishingTriageAgent
from app.agents.reporter import ReporterAgent
from app.agents.responder import ResponderAgent
from app.agents.saas_posture import SaaSPostureAgent
from app.agents.triager import TriagerAgent
from app.models.case import Case, CaseStatus
from app.models.trace import AgentName, AgentTrace, TraceStep
from app.realtime.case_events import publish_case_closed, publish_case_status

AGENT_MAP: dict[AgentName, type[BaseAgent]] = {
    AgentName.TRIAGER: TriagerAgent,
    AgentName.INVESTIGATOR: InvestigatorAgent,
    AgentName.ITDR: ITDRAgent,
    AgentName.CDR: CDRAgent,
    AgentName.SAAS_POSTURE: SaaSPostureAgent,
    AgentName.PHISHING_TRIAGE: PhishingTriageAgent,
    AgentName.RESPONDER: ResponderAgent,
    AgentName.REPORTER: ReporterAgent,
}

EventSink = Callable[[dict], None]


class Orchestrator:
    """Drives a case through the agent mesh."""

    def __init__(
        self,
        db: Session,
        case_id: int,
        tenant_id: str,
        on_event: EventSink | None = None,
        max_steps: int = 8,
    ) -> None:
        self.db = db
        self.case_id = case_id
        # Tenant ID is explicit on the orchestrator and propagated to every
        # sub-agent we instantiate, so traces/tool calls/HITL requests are
        # always stamped with the tenant that owns the case.
        self.tenant_id = tenant_id
        self.on_event = on_event or (lambda e: None)
        self.max_steps = max_steps

    async def run(self) -> AgentResult:
        case = self.db.get(Case, self.case_id)
        prev_status = case.status
        case.status = CaseStatus.TRIAGING
        self.db.add(case)
        self.db.commit()

        # Mirror the initial NEW → TRIAGING transition onto the realtime
        # stream + websocket bus. Every later transition inside the loop
        # uses the same publisher so consumers see a clean state machine.
        if prev_status != CaseStatus.TRIAGING:
            await publish_case_status(
                tenant_id=self.tenant_id,
                case_id=self.case_id,
                from_status=prev_status.value,
                to_status=CaseStatus.TRIAGING.value,
                actor="orchestrator",
            )

        self._emit({"type": "orchestrator", "msg": "Planner: starting agent mesh", "case_id": self.case_id})

        # Plan trace from the Planner (lightweight — actual planning is the routing logic below)
        planner_trace = AgentTrace(
            case_id=self.case_id,
            tenant_id=self.tenant_id,
            agent=AgentName.PLANNER,
            step=TraceStep.PLAN,
            summary="Route case to Triager → Investigator → Responder → Reporter as warranted",
            detail={"max_steps": self.max_steps},
        )
        self.db.add(planner_trace)
        self.db.commit()

        next_agent: AgentName | None = AgentName.TRIAGER
        last_result: AgentResult | None = None

        for step in range(self.max_steps):
            if next_agent is None:
                break
            cls = AGENT_MAP.get(next_agent)
            if not cls:
                break

            self._emit(
                {
                    "type": "agent_start",
                    "agent": next_agent.value,
                    "case_id": self.case_id,
                    "step": step + 1,
                }
            )

            agent = cls(self.db, self.case_id, tenant_id=self.tenant_id)
            # Map status by agent. Each handoff is a state transition the
            # operator timeline cares about, so publish before we run the
            # next agent — that way the websocket and stream consumers see
            # "case is now INVESTIGATING" *before* the agent's traces arrive.
            new_status = _status_for(next_agent)
            if new_status != case.status:
                from_status = case.status
                case.status = new_status
                self.db.add(case)
                self.db.commit()
                await publish_case_status(
                    tenant_id=self.tenant_id,
                    case_id=self.case_id,
                    from_status=from_status.value,
                    to_status=new_status.value,
                    actor="orchestrator",
                )
            else:
                case.status = new_status
                self.db.add(case)
                self.db.commit()

            last_result = await agent.run()

            self._emit(
                {
                    "type": "agent_end",
                    "agent": next_agent.value,
                    "summary": last_result.summary,
                    "case_id": self.case_id,
                    "handoff": last_result.handoff.to.value if last_result.handoff else None,
                }
            )

            if last_result.done or last_result.handoff is None:
                break
            next_agent = last_result.handoff.to

        # Ensure timestamp updated
        case = self.db.get(Case, self.case_id)
        case.updated_at = datetime.now(timezone.utc)
        self.db.add(case)
        self.db.commit()

        # Closed states emit an explicit case.closed envelope in addition
        # to the regular status transitions, so SLA / MTTR dashboards have
        # a single subscribe-once stream of closures to count.
        if case.status.value.startswith("closed_"):
            await publish_case_closed(
                tenant_id=self.tenant_id,
                case_id=self.case_id,
                verdict=case.verdict.value,
                confidence=case.confidence or 0.0,
                actor="orchestrator",
            )

        self._emit(
            {
                "type": "orchestrator",
                "msg": "Done",
                "case_id": self.case_id,
                "final_status": case.status.value,
            }
        )
        return last_result or AgentResult(summary="no agents ran", done=True)

    def _emit(self, ev: dict) -> None:
        ev["ts"] = datetime.now(timezone.utc).isoformat()
        # Stamp the tenant so the event bus can fan out per-tenant. Without
        # this the bus falls back to the global channel and orchestrator
        # activity would leak across tenant boundaries on the live feed.
        ev.setdefault("tenant_id", self.tenant_id)
        try:
            self.on_event(ev)
        except Exception:
            pass


def _status_for(agent: AgentName) -> CaseStatus:
    return {
        AgentName.TRIAGER: CaseStatus.TRIAGING,
        AgentName.INVESTIGATOR: CaseStatus.INVESTIGATING,
        # ITDR is identity-side deep investigation + surgical containment;
        # surface it as INVESTIGATING so the case timeline reads coherently
        # (the operator sees "still investigating" while we walk the session
        # graph, not "responding" — that's reserved for endpoint/network
        # containment in the Responder).
        AgentName.ITDR: CaseStatus.INVESTIGATING,
        # CDR walks IAM/STS/K8s graphs and issues surgical writes. Mirror
        # ITDR's status policy: keep the timeline reading "investigating"
        # while we enumerate, and reserve RESPONDING for the
        # cross-surface (endpoint/network) Responder pass.
        AgentName.CDR: CaseStatus.INVESTIGATING,
        # SaaS Posture sweeps app inventory / shares / OAuth grants and
        # issues surgical SSPM writes. Same status policy as ITDR/CDR:
        # the operator timeline reads "investigating" while we walk the
        # SaaS surface; RESPONDING is reserved for endpoint/network
        # containment in the Responder.
        AgentName.SAAS_POSTURE: CaseStatus.INVESTIGATING,
        # Phishing Triage is a deep email-specialist pass that runs in lieu
        # of (or alongside) the generic Triager. Surface it as TRIAGING so
        # the operator timeline reads "still triaging this suspicious
        # email" while we run header analysis / detonation / brand checks.
        AgentName.PHISHING_TRIAGE: CaseStatus.TRIAGING,
        AgentName.RESPONDER: CaseStatus.RESPONDING,
        AgentName.REPORTER: CaseStatus.RESPONDING,
    }.get(agent, CaseStatus.TRIAGING)
