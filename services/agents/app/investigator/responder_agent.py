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
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from app.core.cost_telemetry import record_llm_call

from .prompt_sanitizer import (
    sanitize_for_prompt,
    sanitize_iterable_of_strings,
    sanitize_text,
)
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

    # Defence-in-depth: every field surfaced here originated in attacker-
    # influenced data (alert payloads, banners, dark-web excerpts, LLM
    # summaries of the same). Sanitise scalars, cap list lengths, and wrap
    # the timeline blob in <UNTRUSTED_DATA> so the system prompt stays
    # authoritative.
    safe_alert = sanitize_text(state.alert_summary, max_len=2_000)
    safe_root_cause = sanitize_text(state.forensic.root_cause_hypothesis, max_len=1_000)
    safe_blast = sanitize_text(state.forensic.blast_radius, max_len=1_000)
    safe_mitre = sanitize_iterable_of_strings(state.recon.mitre_techniques, max_item_len=64, max_items=25)
    safe_actors = sanitize_iterable_of_strings(state.recon.threat_actors, max_item_len=128, max_items=25)
    timeline_blob = sanitize_for_prompt(
        state.forensic.timeline[-5:],
        label="timeline_tail",
        max_blob_len=2_500,
    )

    prompt = (
        f"Alert: {safe_alert}\n\n"
        f"Root cause: {safe_root_cause}\n"
        f"Blast radius: {safe_blast}\n"
        f"Confidence: {state.forensic.confidence:.0%}\n"
        f"MITRE: {safe_mitre}\n"
        f"Threat actors: {safe_actors}\n\n"
        f"Timeline (last 5):\n{timeline_blob}"
    )

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    prompt_hash = state.log_llm_prompt(
        agent="ResponderAgent",
        prompt=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        model=model,
        purpose="responder: containment/eradication/recovery plan",
    )

    t0 = time.monotonic()
    try:
        response = await llm.ainvoke(messages)
        content = response.content
        latency_ms = int((time.monotonic() - t0) * 1000)
        tokens = 0
        if hasattr(response, "response_metadata"):
            tokens = response.response_metadata.get("token_usage", {}).get("total_tokens", 0) or 0
        # Tier 1.6: record cost telemetry on the active CostTracker.
        call_record = record_llm_call(
            response,
            model=model,
            latency_ms=latency_ms,
            step="responder",
            tool="llm.responder",
        )
        cost_usd = call_record.cost_usd if call_record is not None else 0.0
        state.log_llm_response(
            agent="ResponderAgent",
            response=content if isinstance(content, str) else str(content),
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )
        json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            return json.loads(json_match.group())
    except Exception as exc:  # noqa: BLE001
        logger.warning("responder llm failed", error=str(exc))
        state.log(
            StepKind.ERROR,
            "ResponderAgent",
            f"LLM call failed: {exc}",
        )

    state.log_decision(
        agent="ResponderAgent",
        decision="default_high_risk_plan",
        reason="LLM unavailable; falling back to conservative high-risk containment template",
        confidence=0.3,
    )
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

    # Record the headline risk decision so auditors can see why we picked this level
    state.log_decision(
        agent="ResponderAgent",
        decision=f"risk_level={state.responder.risk_level}",
        reason=(
            f"Based on root cause '{state.forensic.root_cause_hypothesis}' with "
            f"forensic confidence {state.forensic.confidence:.0%} and blast radius "
            f"'{state.forensic.blast_radius}'."
        ),
        confidence=state.forensic.confidence,
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    state.log(
        StepKind.RESPONDER,
        "ResponderAgent",
        f"Generated {len(state.responder.recommended_actions)} recommended actions (risk={state.responder.risk_level}, dry_run=True)",
        duration_ms=elapsed_ms,
        input_hash=sha256_of(state.forensic.model_dump()),
        output_hash=sha256_of(state.responder.model_dump()),
    )
    state.iteration += 1
    logger.info("responder_agent.done", case_id=state.case_id, ms=elapsed_ms)
    return state.to_dict()
