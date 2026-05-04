"""
ForensicAgent — Phase 2 of the investigator pipeline.

Responsibilities:
  • Build a chronological event timeline from enrichment data + raw alert
  • Hypothesise root cause and blast radius
  • Identify forensic artefacts (file paths, registry keys, network artefacts)
  • Produce a confidence-scored forensic summary
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

import structlog
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

from .state import ForensicFindings, InvestigatorState, StepKind
from .tools import sha256_of

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the ForensicAgent of an AI Security Operations Centre.
Given a security alert and its enrichment data, produce:
1. A chronological timeline of events (at most 15 entries).
2. A list of forensic artefacts (file paths, registry keys, network indicators).
3. A root-cause hypothesis (one sentence).
4. An estimated blast radius (what systems/data were or could be affected).
5. A confidence score (0.0–1.0) for your analysis.

Respond ONLY with a JSON object:
{
  "timeline": [{"ts": "ISO8601 or relative", "event": "...", "src": "..."}],
  "artefacts": ["C:\\\\path\\\\to\\\\file.exe", "HKCU\\\\..."],
  "root_cause_hypothesis": "...",
  "blast_radius": "...",
  "confidence": 0.75,
  "summary": "Two-sentence forensic summary."
}
"""


async def _llm_forensic(state: InvestigatorState) -> dict[str, Any]:
    import os

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model, temperature=0)

    enrichment_snippet = json.dumps(
        {k: v for k, v in list(state.enrichment_cache.items())[:10]},
        indent=2,
    )[:3000]

    prompt = (
        f"Alert summary:\n{state.alert_summary}\n\n"
        f"Recon findings:\n{state.recon.summary}\n"
        f"MITRE techniques: {state.recon.mitre_techniques}\n\n"
        f"Enrichment data (sample):\n{enrichment_snippet}"
    )

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    prompt_hash = state.log_llm_prompt(
        agent="ForensicAgent",
        prompt=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        model=model,
        purpose="forensic: timeline, artefacts, root cause, blast radius",
    )

    t0 = time.monotonic()
    try:
        response = await llm.ainvoke(messages)
        content = response.content
        latency_ms = int((time.monotonic() - t0) * 1000)
        tokens = 0
        if hasattr(response, "response_metadata"):
            tokens = (
                response.response_metadata.get("token_usage", {}).get("total_tokens", 0)
                or 0
            )
        state.log_llm_response(
            agent="ForensicAgent",
            response=content if isinstance(content, str) else str(content),
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
        )
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            return json.loads(json_match.group())
    except Exception as exc:  # noqa: BLE001
        logger.warning("forensic llm failed", error=str(exc))
        state.log(
            StepKind.ERROR,
            "ForensicAgent",
            f"LLM call failed: {exc}",
        )

    # Fallback
    state.log_decision(
        agent="ForensicAgent",
        decision="defer_to_manual",
        reason="LLM unavailable or returned malformed output; cannot construct a confident forensic timeline",
        confidence=0.1,
        alternatives=["llm_extraction"],
    )
    return {
        "timeline": [],
        "artefacts": [],
        "root_cause_hypothesis": "Unable to determine root cause automatically.",
        "blast_radius": "Unknown — manual review required.",
        "confidence": 0.1,
        "summary": "Automated forensic analysis was not available.",
    }


async def run_forensic(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("forensic_agent.start", case_id=state.case_id)

    llm_result = await _llm_forensic(state)

    state.forensic = ForensicFindings(
        timeline=llm_result.get("timeline", []),
        artefacts=llm_result.get("artefacts", []),
        root_cause_hypothesis=llm_result.get("root_cause_hypothesis", ""),
        blast_radius=llm_result.get("blast_radius", ""),
        confidence=float(llm_result.get("confidence", 0.0)),
        summary=llm_result.get("summary", ""),
    )

    # Cite each forensic artefact as evidence for downstream replay
    for artefact in state.forensic.artefacts[:50]:
        state.log_evidence(
            agent="ForensicAgent",
            evidence_kind="artefact",
            ref=str(artefact),
            weight=state.forensic.confidence,
        )

    if state.forensic.root_cause_hypothesis:
        state.log_decision(
            agent="ForensicAgent",
            decision="root_cause_hypothesis",
            reason=state.forensic.root_cause_hypothesis,
            confidence=state.forensic.confidence,
        )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    state.log(
        StepKind.FORENSIC,
        "ForensicAgent",
        f"Timeline: {len(state.forensic.timeline)} events, confidence {state.forensic.confidence:.0%}",
        duration_ms=elapsed_ms,
        input_hash=sha256_of(state.recon.model_dump()),
        output_hash=sha256_of(state.forensic.model_dump()),
    )
    state.iteration += 1
    logger.info("forensic_agent.done", case_id=state.case_id, ms=elapsed_ms)
    return state.to_dict()
