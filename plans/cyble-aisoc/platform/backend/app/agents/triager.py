"""Triager: first-pass classification, driven by LLM tool-use.

The LLM is given the alert + similar past cases + the set of triage tools and
is asked to enrich whatever it deems relevant. Tool execution still flows
through `call_tool`, so risk-class HITL, traces, and persistence all apply.

Once enrichment is done, a deterministic scorer over the gathered tool results
decides severity/verdict and which agent gets the handoff. We intentionally
keep the verdict deterministic (auditable) but let the LLM choose investigation
breadth.
"""
from __future__ import annotations

import json

from sqlmodel import select

from app.agents.base import AgentResult, BaseAgent, Handoff
from app.memory.episodic import episodic_recall
from app.memory.scratchpad import scratchpad
from app.models.alert import Alert
from app.models.case import Case, Severity, Verdict
from app.models.trace import AgentName, TraceStep


class TriagerAgent(BaseAgent):
    name = AgentName.TRIAGER
    role = (
        "First-pass alert triage. Decide false-positive vs needs-investigation, "
        "set severity, identify related signals."
    )
    allowed_tools = [
        "siem.search_events",
        "siem.get_related_alerts",
        "cti.enrich_ioc",
        "idp.get_user",
    ]

    async def run(self) -> AgentResult:
        case = self.db.get(Case, self.case_id)
        alerts = self.db.exec(
            select(Alert)
            .where(Alert.case_id == self.case_id)
            .where(Alert.tenant_id == self.tenant_id)
        ).all()
        primary = alerts[0] if alerts else None

        self.trace(
            TraceStep.PLAN,
            f"Triage {len(alerts)} alert(s); LLM-directed enrichment",
            detail={"primary_alert": primary.title if primary else None},
        )

        similar = episodic_recall(
            f"{primary.title if primary else ''} {primary.description if primary else ''}",
            k=3,
            tenant_id=self.tenant_id,
        )
        if similar:
            self.trace(
                TraceStep.THINK,
                f"Found {len(similar)} similar past cases",
                detail={"similar": similar},
            )

        # Hand the LLM the case context and let it pick which tools to call.
        alert_blob = _alert_to_json(primary)
        similar_blob = json.dumps(similar, default=str)[:1200] if similar else "none"

        system_prompt = (
            "You are the Triager agent in a SOC. Your job is to gather just enough "
            "enrichment to decide whether this alert is a false positive or needs "
            "deeper investigation.\n"
            "Rules:\n"
            "- Use `cti.enrich_ioc` for any IP / hash / domain that is concrete.\n"
            "- Use `idp.get_user` when a username is present.\n"
            "- Use `siem.get_related_alerts` on the most identifying entity "
            "(host > user > ip) to detect lateral spread.\n"
            "- Use `siem.search_events` only if you specifically need broader context.\n"
            "- Do NOT loop forever: aim for at most 4 distinct tool calls.\n"
            "- When you have enough, stop calling tools and reply with a one-line "
            "rationale.\n"
        )
        user_msg = (
            f"Primary alert:\n{alert_blob}\n\n"
            f"Similar past cases (episodic memory): {similar_blob}\n\n"
            "Plan and execute the enrichment tools you actually need, then stop."
        )

        try:
            final_text, _msgs = await self.tool_use_loop(
                system=system_prompt,
                user=user_msg,
                max_turns=5,
                max_tokens=600,
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.trace(
                TraceStep.ERROR,
                f"LLM tool-use loop failed: {exc}; falling back to deterministic enrichment",
                detail={"error": str(exc)},
            )
            final_text = ""
            await _deterministic_enrich(self, primary)

        # If the LLM chose to call zero tools (mock with no usable input, or
        # provider failure), do a minimum-viable deterministic pass so the rest
        # of the pipeline still has something to score.
        results = scratchpad.get(self.case_id, "tool_results", []) or []
        if not results and primary is not None:
            await _deterministic_enrich(self, primary)
            results = scratchpad.get(self.case_id, "tool_results", []) or []

        # Deterministic scoring over the (LLM-chosen) tool results.
        cti_max = max(
            (
                r["result"].get("threat_score", 0)
                for r in results
                if r["tool"] == "cti.enrich_ioc"
            ),
            default=0,
        )
        related_count = next(
            (
                r["result"].get("related_count", 0)
                for r in results
                if r["tool"] == "siem.get_related_alerts"
            ),
            0,
        )

        if cti_max >= 80 or related_count >= 2:
            severity = Severity.HIGH if cti_max < 90 else Severity.CRITICAL
            verdict = Verdict.UNKNOWN
            decision = (
                f"Elevated. Max CTI threat score {cti_max}, related alerts: "
                f"{related_count}. Hand to Investigator for deep dive."
            )
            handoff_to = AgentName.INVESTIGATOR
        elif cti_max >= 30:
            severity = Severity.MEDIUM
            verdict = Verdict.UNKNOWN
            decision = "Suspicious but not conclusive. Investigator should confirm."
            handoff_to = AgentName.INVESTIGATOR
        else:
            severity = Severity.LOW
            verdict = Verdict.FALSE_POSITIVE
            decision = "No malicious indicators. Closing as benign FP."
            handoff_to = AgentName.REPORTER

        if final_text:
            self.trace(
                TraceStep.THINK,
                final_text[:300],
                detail={"llm_rationale": final_text},
            )

        self.trace(
            TraceStep.DECISION,
            f"Severity={severity.value}, Verdict={verdict.value}",
            detail={
                "cti_max": cti_max,
                "related": related_count,
                "rationale": decision,
            },
        )

        case.severity = severity
        case.verdict = verdict
        case.confidence = min(0.95, 0.4 + (cti_max / 200) + (related_count * 0.05))
        self.db.add(case)
        self.db.commit()

        return AgentResult(
            summary=f"Triaged: {severity.value} / {verdict.value}",
            handoff=Handoff(to=handoff_to, reason=decision),
            case_updates={"severity": severity.value, "verdict": verdict.value},
        )


def _alert_to_json(alert: Alert | None) -> str:
    if alert is None:
        return "{}"
    payload = {
        "title": alert.title,
        "description": alert.description,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "src_host": alert.src_host,
        "src_user": alert.src_user,
        "file_hash": alert.file_hash,
        "severity_seen": getattr(alert, "severity", None),
    }
    return json.dumps({k: v for k, v in payload.items() if v}, default=str)


async def _deterministic_enrich(agent: "TriagerAgent", primary: Alert | None) -> None:
    """Fallback enrichment when the LLM declines (or fails) to pick any tools.

    Preserves the historical behavior so existing demos still finish.
    """
    if primary is None:
        return
    for ioc in [primary.src_ip, primary.dst_ip, primary.file_hash]:
        if not ioc:
            continue
        await agent.call_tool("cti.enrich_ioc", {"ioc": ioc})
    if primary.src_user:
        await agent.call_tool("idp.get_user", {"user": primary.src_user})
    entity = primary.src_host or primary.src_user or primary.src_ip
    if entity:
        await agent.call_tool("siem.get_related_alerts", {"entity": entity})
