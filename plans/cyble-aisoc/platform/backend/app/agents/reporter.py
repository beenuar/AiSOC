"""Reporter: writes case narrative, records to episodic memory, closes case."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlmodel import select

from app.agents.base import AgentResult, BaseAgent
from app.agents.llm import complete
from app.memory.episodic import episodic_record
from app.memory.scratchpad import scratchpad
from app.models.alert import Alert
from app.models.case import Case, CaseStatus, Verdict
from app.models.trace import AgentName, TraceStep
from app.reports import build_case_report


class ReporterAgent(BaseAgent):
    name = AgentName.REPORTER
    role = "Compose human-readable case narrative, persist to memory, close case."
    allowed_tools: list[str] = []  # Reporter doesn't touch tools

    async def run(self) -> AgentResult:
        case = self.db.get(Case, self.case_id)
        alerts = self.db.exec(
            select(Alert)
            .where(Alert.case_id == self.case_id)
            .where(Alert.tenant_id == self.tenant_id)
        ).all()
        primary = alerts[0] if alerts else None

        results = scratchpad.get(self.case_id, "tool_results", []) or []
        cti_high = [r for r in results if r["tool"] == "cti.enrich_ioc" and r["result"].get("threat_score", 0) >= 50]
        proc = [r for r in results if r["tool"] == "edr.get_process_tree"]
        darkweb = [r for r in results if r["tool"] == "cti.darkweb_search"]

        # Build narrative
        bullets = []
        if primary:
            bullets.append(f"Initial alert: **{primary.title}** from {primary.source}")
        if cti_high:
            top = max(cti_high, key=lambda r: r["result"].get("threat_score", 0))
            bullets.append(
                f"Cyble CTI flagged `{top['result'].get('ioc')}` "
                f"(score {top['result'].get('threat_score')}, "
                f"tags: {', '.join(top['result'].get('tags', [])[:3])})"
            )
        if proc:
            bullets.append("EDR process tree showed suspicious child processes from Office macro")
        if darkweb and darkweb[0]["result"].get("hits"):
            bullets.append(f"Dark-web crawl returned {len(darkweb[0]['result']['hits'])} relevant mentions")
        if case.response_actions:
            bullets.append(
                f"Containment: {', '.join(a['action'] for a in case.response_actions)}"
            )

        narrative = "\n".join(f"- {b}" for b in bullets)
        # Theme 2n — tiered router: Reporter only produces a summary, so we
        # route through the agent name. `route_for_agent` will pick the
        # default tier for `reporter` (FAST) unless an operator pinned a
        # specific model via env (LLM_MODEL_REPORTER / LLM_PROVIDER_REPORTER).
        narration = await complete(
            system="You are the Reporter agent. Write a tight, plain-English case summary in 4-6 lines for an analyst.",
            user=f"Verdict: {case.verdict.value}\nFindings:\n{narrative}",
            max_tokens=300,
            agent=self.name.value,
        )
        full_narrative = (narration["text"] + "\n\n" + narrative).strip()

        self.trace(
            TraceStep.THINK,
            "Compose case narrative",
            detail={
                "narrative_preview": full_narrative[:300],
                # Surface model routing decision on the trace so an analyst
                # can audit which model wrote which summary.
                "model": narration.get("model"),
                "tier": narration.get("tier"),
                "route_reason": narration.get("route_reason"),
                "provider": narration.get("provider"),
            },
            tokens_in=narration["tokens_in"],
            tokens_out=narration["tokens_out"],
        )

        case.narrative = full_narrative

        # Theme 2k — Multi-modal report. Built from the canonical case
        # tables (Alert, AgentTrace, ToolCall, HitlRequest) so it always
        # matches the audit log; cached on the scratchpad so the API and
        # the dashboard don't have to rebuild on the very next request.
        # We record only the rollup stats on the trace (full report can
        # be large; it lives at GET /cases/{id}/report).
        try:
            report = build_case_report(
                self.db,
                case_id=self.case_id,
                tenant_id=self.tenant_id,
                case=case,
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.trace(
                TraceStep.ERROR,
                "Multi-modal report build failed",
                detail={"error": str(exc)},
            )
        else:
            scratchpad.set(self.case_id, "case_report", report.to_dict())
            self.trace(
                TraceStep.DECISION,
                "Multi-modal report built",
                detail={"report_stats": report.stats},
            )

        # Final status
        if case.verdict == Verdict.TRUE_POSITIVE:
            case.status = CaseStatus.CLOSED_TRUE_POSITIVE
        elif case.verdict == Verdict.FALSE_POSITIVE:
            case.status = CaseStatus.CLOSED_FALSE_POSITIVE
        elif case.verdict == Verdict.BENIGN:
            case.status = CaseStatus.CLOSED_BENIGN
        else:
            case.status = CaseStatus.AWAITING_HITL
        case.closed_at = datetime.now(timezone.utc) if "closed" in case.status.value else None
        case.updated_at = datetime.now(timezone.utc)
        self.db.add(case)
        self.db.commit()

        # Persist to episodic memory for future similarity recall
        episodic_record(
            case_id=case.id,
            title=case.title,
            narrative=full_narrative,
            verdict=case.verdict.value,
            tags=list(case.mitre_techniques) + list(case.iocs[:3]),
            tenant_id=self.tenant_id,
        )
        self.trace(TraceStep.DECISION, "Case closed and recorded to episodic memory")

        return AgentResult(
            summary=f"Case closed: {case.status.value}",
            done=True,
        )
