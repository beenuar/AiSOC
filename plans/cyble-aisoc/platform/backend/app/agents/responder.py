"""Responder: containment + remediation, driven by LLM tool-use.

Every tool the LLM selects still goes through the **risk gate** in
`BaseAgent.call_tool`, so destructive containment actions are HITL-queued
based on the case autonomy level. The LLM picks the shape of the response
(isolate host vs. revoke session vs. ticket-only) and the safety gate
decides whether each individual action is allowed to execute now.
"""
from __future__ import annotations

import json

from sqlmodel import select

from app.agents.base import AgentResult, BaseAgent, Handoff
from app.agents.llm import complete as llm_complete
from app.agents.llm import reflect as llm_reflect
from app.config import settings
from app.models.alert import Alert
from app.models.case import Case, CaseStatus, Verdict
from app.models.trace import AgentName, TraceStep


class ResponderAgent(BaseAgent):
    name = AgentName.RESPONDER
    role = (
        "Run containment + remediation. Risk-classified actions, HITL where required."
    )
    allowed_tools = [
        # Forward (containment) actions
        "edr.isolate_host",
        "edr.quarantine_file",
        "edr.kill_process",
        "idp.revoke_sessions",
        "idp.disable_user",
        "idp.reset_password",
        "email.clawback_message",
        "email.block_sender",
        "ticket.create",
        "slack.notify",
        # Reverse (rollback) actions — dispatched by the rollback service
        # via `BaseAgent.call_tool(..., rollback_of_id=...)`. Without these
        # in the allowlist the rollback service can't execute the paired
        # undo even though the tool registry knows the inverse.
        "edr.release_host",
        "edr.restore_file",
        "idp.enable_user",
        "email.restore_message",
        "email.unblock_sender",
        "ticket.close",
        "slack.delete_message",
    ]

    async def run(self) -> AgentResult:
        case = self.db.get(Case, self.case_id)
        alerts = self.db.exec(
            select(Alert)
            .where(Alert.case_id == self.case_id)
            .where(Alert.tenant_id == self.tenant_id)
        ).all()
        primary = alerts[0] if alerts else None

        alert_blob = _alert_to_json(primary)
        case_blob = json.dumps(
            {
                "verdict": getattr(case.verdict, "value", str(case.verdict)),
                "severity": getattr(case.severity, "value", str(case.severity)),
                "confidence": case.confidence,
                "title": case.title,
                "iocs": case.iocs,
                "affected_hosts": case.affected_hosts,
                "affected_users": case.affected_users,
                "autonomy_level": settings.autonomy_level,
            },
            default=str,
        )

        system_prompt = (
            "You are the Responder agent in a SOC. You pick the containment + "
            "remediation actions. The platform enforces a risk gate around every "
            "tool — destructive actions may be HITL-queued automatically, do not "
            "second-guess that, just request what the situation actually needs.\n"
            "Guidance:\n"
            "- TRUE_POSITIVE on endpoint: isolate host, quarantine file, kill process, "
            "  revoke user sessions when relevant.\n"
            "- TRUE_POSITIVE on identity (phish / cred theft): revoke sessions, reset "
            "  password, block sender, clawback message.\n"
            "- NEEDS_HUMAN: notify on-call and create a P1 ticket, do not contain.\n"
            "- BENIGN: create a P3 ticket so we have a record.\n"
            "- Always create a ticket so the case has a trackable handle.\n"
            "Aim for the minimum set of actions that actually contains the threat. "
            "When done, return a 2–3 sentence summary of the actions you took."
        )
        user_msg = (
            f"Case:\n{case_blob}\n\n"
            f"Primary alert:\n{alert_blob}\n\n"
            "Decide and execute the containment plan."
        )

        executed: list[dict] = []
        self.trace(TraceStep.PLAN, "LLM-directed response plan", detail={"case_id": self.case_id})

        # ── Reflection pass ─────────────────────────────────────────────────
        # Before we let the Responder actually execute tools, draft a plan on
        # the DEFAULT tier and have a PREMIUM-tier critic look at it. The
        # critique is appended to the tool-use system prompt so the executing
        # model sees the concerns. Reflection is best-effort — if it errors,
        # we fall back to the unaugmented plan rather than blocking response.
        critique_text = ""
        reflect_approved = True
        try:
            draft = await llm_complete(
                system=system_prompt,
                user=(
                    f"{user_msg}\n\n"
                    "Draft (do not execute) the containment plan as a numbered "
                    "list of tool calls with one-line justifications. End with "
                    "a one-sentence risk summary."
                ),
                max_tokens=500,
                agent=self.name.value,
            )
            draft_text = (draft.get("text") or "").strip()
            if draft_text:
                critique = await llm_reflect(
                    system=(
                        "You are a senior SOC reviewer. You audit proposed "
                        "containment plans for: insufficient evidence, "
                        "disproportionate action, and missing rollback. "
                        "Be concise. Flag risky destructive actions like "
                        "isolate_host and disable_user when evidence is weak."
                    ),
                    plan=draft_text,
                    context=case_blob,
                    agent=self.name.value,
                )
                critique_text = (critique.get("text") or "").strip()
                reflect_approved = bool(critique.get("approve"))
                self.trace(
                    TraceStep.THINK,
                    f"Reflection: {'APPROVE' if reflect_approved else 'REVISE'}",
                    detail={
                        "draft_plan": draft_text[:1200],
                        "critique": critique_text[:1200],
                        "approve": reflect_approved,
                        "issues": critique.get("issues", []),
                        "model_choice": critique.get("model_choice"),
                        "tokens_in": critique.get("tokens_in", 0),
                        "tokens_out": critique.get("tokens_out", 0),
                    },
                )
        except Exception as exc:  # pragma: no cover - defensive
            self.trace(
                TraceStep.ERROR,
                f"Reflection skipped: {exc}",
                detail={"error": str(exc)},
            )

        # Inject the critique into the execution system prompt so the model
        # planning the actual tool calls has to address it. When the critic
        # said REVISE we additionally instruct the executor to prefer
        # ticket/notify over destructive containment.
        augmented_system = system_prompt
        if critique_text:
            verdict = "APPROVE" if reflect_approved else "REVISE"
            augmented_system = (
                f"{system_prompt}\n\n"
                f"SENIOR-REVIEWER CRITIQUE ({verdict}):\n{critique_text}\n\n"
                + (
                    ""
                    if reflect_approved
                    else (
                        "Because the critique was REVISE, you MUST avoid "
                        "destructive actions (idp.disable_user, "
                        "edr.isolate_host, edr.kill_process) unless the "
                        "alert/case strongly justifies them. Prefer "
                        "ticket.create + slack.notify and let HITL decide."
                    )
                )
            )

        try:
            final_text, msgs = await self.tool_use_loop(
                system=augmented_system,
                user=user_msg,
                max_turns=8,
                max_tokens=900,
            )
            # Recover the tool calls executed during the loop from the message stream
            for m in msgs:
                if m.get("role") == "tool" and m.get("name"):
                    executed.append(
                        {
                            "action": m["name"],
                            "result": _safe_load(m.get("content")),
                        }
                    )
        except Exception as exc:  # pragma: no cover - defensive
            self.trace(
                TraceStep.ERROR,
                f"LLM tool-use loop failed: {exc}; falling back to deterministic playbook",
                detail={"error": str(exc)},
            )
            final_text = ""
            executed = await _deterministic_respond(self, primary, case)

        if not executed and primary is not None:
            executed = await _deterministic_respond(self, primary, case)

        if final_text:
            self.trace(
                TraceStep.THINK,
                final_text[:400],
                detail={"llm_summary": final_text},
            )

        case.response_actions = executed
        case.status = CaseStatus.RESPONDING
        self.db.add(case)
        self.db.commit()

        return AgentResult(
            summary=f"{len(executed)} response action(s) executed",
            handoff=Handoff(to=AgentName.REPORTER, reason="Generate case narrative and close."),
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
        "process_name": getattr(alert, "process_name", None),
    }
    return json.dumps({k: v for k, v in payload.items() if v}, default=str)


def _safe_load(content):
    if content is None:
        return None
    if isinstance(content, (dict, list)):
        return content
    if isinstance(content, str):
        try:
            return json.loads(content)
        except Exception:
            return content
    return content


async def _deterministic_respond(
    agent: "ResponderAgent", primary: Alert | None, case: Case
) -> list[dict]:
    """Heuristic fallback when the LLM declines to act."""
    actions: list[dict] = []
    if primary and primary.process_name and "powershell" in (primary.process_name or "").lower():
        agent.trace(TraceStep.PLAN, "Fallback: PowerShell containment playbook")
        if primary.src_host:
            r = await agent.call_tool(
                "edr.isolate_host",
                {"host": primary.src_host, "reason": f"AiSOC case #{agent.case_id} containment"},
            )
            actions.append({"action": "edr.isolate_host", "result": r})
        if primary.file_hash:
            r = await agent.call_tool("edr.quarantine_file", {"sha256": primary.file_hash})
            actions.append({"action": "edr.quarantine_file", "result": r})
        if primary.src_user:
            r = await agent.call_tool("idp.revoke_sessions", {"user": primary.src_user})
            actions.append({"action": "idp.revoke_sessions", "result": r})
    elif primary and "phishing" in (primary.title or "").lower():
        agent.trace(TraceStep.PLAN, "Fallback: phishing remediation playbook")
        r = await agent.call_tool("email.clawback_message", {"message_id": "msg-mock-1"})
        actions.append({"action": "email.clawback_message", "result": r})
        r = await agent.call_tool(
            "email.block_sender",
            {"sender": "billing@m1crosoft-secure.com"},
        )
        actions.append({"action": "email.block_sender", "result": r})
        if primary.src_user:
            r = await agent.call_tool("idp.reset_password", {"user": primary.src_user})
            actions.append({"action": "idp.reset_password", "result": r})
    elif case.verdict == Verdict.NEEDS_HUMAN:
        agent.trace(TraceStep.HITL_REQUEST, "Awaiting analyst decision before containment")
        r = await agent.call_tool(
            "slack.notify",
            {
                "channel": "#sec-on-call",
                "message": f"Case #{agent.case_id} needs review: {case.title}",
            },
        )
        actions.append({"action": "slack.notify", "result": r})
        r = await agent.call_tool(
            "ticket.create",
            {"title": case.title, "description": case.narrative, "priority": "P1"},
        )
        actions.append({"action": "ticket.create", "result": r})
    else:
        agent.trace(TraceStep.PLAN, "Fallback: ticket-only")
        r = await agent.call_tool(
            "ticket.create",
            {"title": case.title, "description": case.narrative or "", "priority": "P3"},
        )
        actions.append({"action": "ticket.create", "result": r})
    return actions
