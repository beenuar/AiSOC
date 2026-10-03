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
from langchain_core.messages import HumanMessage, SystemMessage

from app.core.cost_telemetry import record_llm_call
from app.llm import safe_ainvoke
from app.llm.factory import make_chat_model, resolve_model_alias
from app.llm.prompt_registry import prompt_text
from app.prompt_serialization import summarize_structure_for_llm

from .bundle_prompt import format_bundle_prompt_append
from .limits import max_completion_tokens
from .prompt_sanitizer import (
    sanitize_iterable_of_strings,
    sanitize_text,
)
from .state import ForensicFindings, InvestigatorState, StepKind
from .tools import sha256_of

logger = structlog.get_logger()


async def _llm_forensic(state: InvestigatorState) -> dict[str, Any]:
    model = resolve_model_alias("investigation")
    llm = make_chat_model("investigation", temperature=0, max_tokens=max_completion_tokens())

    # Defence-in-depth: alert_summary, recon.summary, and the enrichment cache
    # can all carry attacker-controlled strings (banners, dark-web excerpts,
    # WHOIS values, etc.). Sanitise them and wrap the enrichment blob in an
    # explicit <UNTRUSTED_DATA> envelope so the system prompt stays trusted.
    safe_summary = sanitize_text(state.alert_summary, max_len=2_000)
    safe_recon = sanitize_text(state.recon.summary, max_len=2_000)
    safe_mitre = sanitize_iterable_of_strings(state.recon.mitre_techniques, max_item_len=64, max_items=25)
    enrichment_blob = summarize_structure_for_llm(
        dict(list(state.enrichment_cache.items())[:10]),
        label="enrichment_cache",
        max_lines=40,
        max_depth=2,
    )

    # The original alert payload is the ONLY primary evidence this agent
    # has; it used to be absent from the prompt entirely, which is how a
    # run on an empty payload produced a confident fictional timeline.
    raw_alert_blob = summarize_structure_for_llm(
        dict(state.raw_alert or {}),
        label="raw_alert",
        max_lines=80,
        max_depth=3,
    )
    evidence_available = bool((state.raw_alert or {}).get("alerts")
                               or (state.enrichment_cache or {}))

    prompt = (
        f"Alert summary:\n{safe_summary}\n\n"
        f"Original alert data:\n{raw_alert_blob}\n\n"
        f"Recon findings:\n{safe_recon}\n"
        f"MITRE techniques: {safe_mitre}\n\n"
        f"Enrichment data (sample):\n{enrichment_blob}"
        + ("" if evidence_available else
           "\n\nWARNING: no alert payload, no enrichment, no lake results "
           "were retrieved. Produce only an inconclusive analysis.")
    )
    bundle_append = format_bundle_prompt_append(state.context_bundle)
    if bundle_append:
        prompt = f"{prompt}\n\n{bundle_append}"

    system_prompt = prompt_text("forensic.system")
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=prompt),
    ]

    prompt_hash = state.log_llm_prompt(
        agent="ForensicAgent",
        prompt=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        model=model,
        purpose="forensic: timeline, artefacts, root cause, blast radius",
    )

    t0 = time.monotonic()
    try:
        response = await safe_ainvoke(llm, messages)
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
            step="forensic",
            tool="llm.forensic",
        )
        # None when nothing could price the call — see app/core/gateway_cost.py.
        # Not 0.0: an unpriced call is not a free one.
        cost_usd = call_record.cost_usd if call_record is not None else None
        cost_source = call_record.cost_source if call_record is not None else "unpriced"
        resolved_model = call_record.resolved_model if call_record is not None else None
        state.log_llm_response(
            agent="ForensicAgent",
            response=content if isinstance(content, str) else str(content),
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
            cost_source=cost_source,
            resolved_model=resolved_model,
        )
        json_match = re.search(r"\{[\s\S]*\}", content)
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

    findings = ForensicFindings(
        timeline=llm_result.get("timeline", []),
        artefacts=llm_result.get("artefacts", []),
        root_cause_hypothesis=llm_result.get("root_cause_hypothesis", ""),
        blast_radius=llm_result.get("blast_radius", ""),
        confidence=float(llm_result.get("confidence", 0.0)),
        summary=llm_result.get("summary", ""),
    )

    # Honesty gate: an analysis built on zero retrieved evidence is a
    # hypothesis factory, not a forensic result. Strip invented artefacts,
    # cap confidence, and mark the run inconclusive so the report and the
    # UI cannot present fiction as fact (2026-10 live incident: a run over
    # an empty raw_alert "found" C:\\Windows\\Temp\\malware.exe).
    has_primary = bool((state.raw_alert or {}).get("alerts")
                       or (state.raw_alert or {}).get("title")
                       or (state.raw_alert or {}).get("full_log"))
    has_enriched = bool(state.enrichment_cache)
    if not has_primary and not has_enriched:
        findings = findings.model_copy(update={
            "artefacts": [],
            "confidence": min(findings.confidence, 0.1),
            "root_cause_hypothesis": (
                "INCONCLUSIVE - no alert payload or retrieved evidence was "
                "available to this investigation; any finding would be "
                "speculation."
            ),
            "summary": (
                "Automated forensic analysis inconclusive: zero evidence "
                "retrieved. Manual review with the Wazuh locator on the "
                "case is required."
            ),
        })
        state.log(
            StepKind.WARNING if hasattr(StepKind, "WARNING") else StepKind.DECISION_REASON,
            "ForensicAgent",
            "inconclusive: zero evidence retrieved; artefacts suppressed",
        )
    state.forensic = findings

    # Cite forensic artefacts for downstream replay. Provenance is the
    # model's inference, not a retrieved observation - say so, otherwise
    # the audit log launders fabricated artefacts into "evidence_cited".
    for artefact in state.forensic.artefacts[:50]:
        state.log_evidence(
            agent="ForensicAgent",
            evidence_kind="artefact_hypothesis",
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
