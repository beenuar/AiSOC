"""
ReconAgent — Phase 1 of the investigator pipeline.

Responsibilities:
  • Extract IOCs from the alert
  • Enrich each IOC via the enrichment service (fan-out, cached)
  • Map findings to MITRE ATT&CK techniques
  • Identify potential threat-actor clusters
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

from app.core.cost_telemetry import record_llm_call

from .prompt_sanitizer import sanitize_for_prompt, sanitize_text
from .state import InvestigatorState, ReconFindings, StepKind
from .tools import enrich_ioc, extract_iocs, map_to_mitre, sha256_of

logger = structlog.get_logger()

_SYSTEM_PROMPT = """You are the ReconAgent of an AI Security Operations Centre.
Your task is to analyse a security alert and:
1. List all unique IOCs (IPs, domains, URLs, file hashes) found in the alert.
2. Identify probable MITRE ATT&CK techniques based on the alert description.
3. Hypothesise which threat-actor group(s) may be responsible, citing your evidence.
4. Summarise the attack surface at risk.

Respond ONLY with a JSON object matching this schema:
{
  "iocs": [{"type": "ip|domain|url|hash", "value": "..."}],
  "mitre_techniques": ["T1566", ...],
  "threat_actors": ["APT28", ...],
  "attack_surface": {"affected_systems": [...], "data_at_risk": "..."},
  "summary": "One-paragraph reconnaissance summary."
}
"""


async def _llm_recon(state: InvestigatorState) -> dict[str, Any]:
    """Call LLM to perform structured reconnaissance.

    Records the LLM prompt and response into the audit ledger so the
    reasoning trace is replayable.
    """
    import json
    import os

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model, temperature=0)

    # Defence-in-depth: every field surfaced here can be attacker-influenced
    # (alert_summary often echoes log lines; raw_alert is verbatim event data).
    # Sanitise both before they hit the model, and wrap them in an
    # <UNTRUSTED_DATA> envelope so the system prompt's instructions stay
    # authoritative even if an attacker plants a "ignore previous instructions"
    # payload inside a banner or log message.
    safe_summary = sanitize_text(state.alert_summary, max_len=2_000)
    raw_alert_blob = sanitize_for_prompt(
        state.raw_alert,
        label="raw_alert",
        max_blob_len=3_000,
    )
    prompt = f"Alert summary:\n{safe_summary}\n\nRaw alert data:\n{raw_alert_blob}"

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    prompt_hash = state.log_llm_prompt(
        agent="ReconAgent",
        prompt=[
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        model=model,
        purpose="recon: extract IOCs, MITRE techniques, and threat actors",
    )

    t0 = time.monotonic()
    try:
        response = await llm.ainvoke(messages)
        content = response.content
        latency_ms = int((time.monotonic() - t0) * 1000)
        tokens = 0
        if hasattr(response, "response_metadata"):
            tokens = response.response_metadata.get("token_usage", {}).get("total_tokens", 0) or 0
        # Record into the active CostTracker (Tier 1.6) so per-run cost
        # telemetry includes this LLM call. No-op when no tracker is bound.
        call_record = record_llm_call(
            response,
            model=model,
            latency_ms=latency_ms,
            step="recon",
            tool="llm.recon",
        )
        cost_usd = call_record.cost_usd if call_record is not None else 0.0
        state.log_llm_response(
            agent="ReconAgent",
            response=content if isinstance(content, str) else str(content),
            prompt_hash=prompt_hash,
            model=model,
            tokens_used=tokens,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
        )
        # Extract JSON from the response
        import re

        json_match = re.search(r"\{[\s\S]*\}", content)
        if json_match:
            return json.loads(json_match.group())
    except Exception as exc:  # noqa: BLE001
        logger.warning("recon llm failed", error=str(exc))
        state.log(
            StepKind.ERROR,
            "ReconAgent",
            f"LLM call failed, falling back to heuristics: {exc}",
        )

    # Fallback: heuristic extraction
    iocs = extract_iocs(state.alert_summary)
    techniques = map_to_mitre(state.alert_summary)
    state.log_decision(
        agent="ReconAgent",
        decision="use_heuristic_fallback",
        reason="LLM unavailable or returned malformed JSON; relying on regex IOC extraction and keyword MITRE mapping",
        confidence=0.4,
        alternatives=["llm_extraction"],
    )
    return {
        "iocs": iocs,
        "mitre_techniques": techniques,
        "threat_actors": [],
        "attack_surface": {},
        "summary": state.alert_summary[:200],
    }


async def run_recon(state_dict: dict[str, Any]) -> dict[str, Any]:
    """LangGraph node — receives and returns a plain dict."""
    state = InvestigatorState.from_dict(state_dict)
    t0 = time.monotonic()

    logger.info("recon_agent.start", case_id=state.case_id)
    state.status = "running"

    # 1. LLM-powered recon
    llm_result = await _llm_recon(state)

    iocs: list[dict[str, Any]] = llm_result.get("iocs", [])
    # Also extract heuristically and merge
    heuristic_iocs = extract_iocs(state.alert_summary)
    seen = {i["value"] for i in iocs}
    for h in heuristic_iocs:
        if h["value"] not in seen:
            iocs.append(h)
            seen.add(h["value"])

    # 2. Enrich IOCs (fan-out, cached) - each enrichment is a tool call, recorded
    async def _enrich(ioc: dict[str, str]) -> tuple[str, dict[str, Any]]:
        cached = state.enrichment_cache.get(ioc["value"])
        if cached:
            state.log_tool_call(
                agent="ReconAgent",
                tool_name="enrich_ioc",
                args={"value": ioc["value"], "type": ioc["type"], "cached": True},
                result=cached,
                latency_ms=0,
                success=True,
            )
            return ioc["value"], cached
        t_enrich = time.monotonic()
        result = await enrich_ioc(ioc["value"], ioc["type"])
        state.log_tool_call(
            agent="ReconAgent",
            tool_name="enrich_ioc",
            args={"value": ioc["value"], "type": ioc["type"]},
            result=result,
            latency_ms=int((time.monotonic() - t_enrich) * 1000),
            success=bool(result),
        )
        return ioc["value"], result

    enrichment_results = await asyncio.gather(*[_enrich(ioc) for ioc in iocs])
    for val, result in enrichment_results:
        state.enrichment_cache[val] = result
        # Cite each IOC as a piece of evidence
        state.log_evidence(
            agent="ReconAgent",
            evidence_kind="ioc",
            ref=val,
            weight=1.0,
            details={"enrichment": result},
        )

    # 3. Build ReconFindings
    mitre = list(set(llm_result.get("mitre_techniques", []) + map_to_mitre(state.alert_summary)))
    for technique in mitre:
        state.log_evidence(
            agent="ReconAgent",
            evidence_kind="mitre_technique",
            ref=technique,
            weight=0.8,
        )
    state.recon = ReconFindings(
        iocs=iocs,
        threat_actors=llm_result.get("threat_actors", []),
        attack_surface=llm_result.get("attack_surface", {}),
        mitre_techniques=mitre,
        summary=llm_result.get("summary", ""),
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    state.log(
        StepKind.RECON,
        "ReconAgent",
        f"Found {len(iocs)} IOCs, {len(mitre)} MITRE techniques in {elapsed_ms}ms",
        ioc_count=len(iocs),
        duration_ms=elapsed_ms,
        input_hash=sha256_of(state.alert_summary),
        output_hash=sha256_of(state.recon.model_dump()),
    )
    state.iteration += 1
    logger.info("recon_agent.done", case_id=state.case_id, iocs=len(iocs), ms=elapsed_ms)
    return state.to_dict()
