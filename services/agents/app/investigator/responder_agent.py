"""
ResponderAgent — Phase 3 of the investigator pipeline.

Responsibilities:
  • Generate a prioritised response plan (containment → eradication → recovery)
  • Estimate effort and risk
  • All actions are DRY-RUN only — no live execution occurs here
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

import structlog
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from .state import InvestigatorState, ResponderPlan, StepKind
from .tools import sha256_of

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the ResponderAgent of an AI Security Operations Centre.
Based on the forensic findings, generate a concrete incident response plan.
All actions are DRY-RUN only — do NOT perform any real actions.

Respond ONLY with a JSON object:
{
  "recommended_actions": [
    {"priority": 1, "action": "...", "rationale": "...", "risk": "low|medium|high"}
  ],
  "containment_steps": ["Step 1: ...", "Step 2: ..."],
  "eradication_steps": ["..."],
  "recovery_steps": ["..."],
  "estimated_effort_hours": 4.0,
  "risk_level": "low|medium|high|critical",
  "summary": "Two-sentence response summary."
}
"""


async def _llm_responder(state: InvestigatorState) -> dict[str, Any]:
    import os

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model, temperature=0)

    prompt = (
        f"Alert: {state.alert_summary}\n\n"
        f"Root cause: {state.forensic.root_cause_hypothesis}\n"
        f"Blast radius: {state.forensic.blast_radius}\n"
        f"Confidence: {state.forensic.confidence:.0%}\n"
        f"MITRE: {state.recon.mitre_techniques}\n"
        f"Threat actors: {state.recon.threat_actors}\n\n"
        f"Timeline (last 5):\n"
        + json.dumps(state.forensic.timeline[-5:], indent=2)
    )

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    try:
        response = await llm.ainvoke(messages)
        content = response.content
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            return json.loads(json_match.group())
    except Exception as exc:  # noqa: BLE001
        logger.warning("responder llm failed", error=str(exc))

    return {
        "recommended_actions": [],
        "containment_steps": ["Isolate affected systems immediately."],
        "eradication_steps": ["Remove identified malicious artefacts."],
        "recovery_steps": ["Restore from last known good backup."],
        "estimated_effort_hours": 8.0,
        "risk_level": "high",
        "summary": "Automated response plan generation was not available.",
    }


async def run_responder(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("responder_agent.start", case_id=state.case_id)

    llm_result = await _llm_responder(state)

    state.responder = ResponderPlan(
        recommended_actions=llm_result.get("recommended_actions", []),
        containment_steps=llm_result.get("containment_steps", []),
        eradication_steps=llm_result.get("eradication_steps", []),
        recovery_steps=llm_result.get("recovery_steps", []),
        estimated_effort_hours=float(llm_result.get("estimated_effort_hours", 0)),
        risk_level=llm_result.get("risk_level", "medium"),
        dry_run=True,
        summary=llm_result.get("summary", ""),
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    state.log(
        StepKind.RESPONDER,
        "ResponderAgent",
        f"Generated {len(state.responder.recommended_actions)} recommended actions "
        f"(risk={state.responder.risk_level}, dry_run=True)",
        duration_ms=elapsed_ms,
        input_hash=sha256_of(state.forensic.model_dump()),
        output_hash=sha256_of(state.responder.model_dump()),
    )
    state.iteration += 1
    logger.info("responder_agent.done", case_id=state.case_id, ms=elapsed_ms)
    return state.to_dict()
