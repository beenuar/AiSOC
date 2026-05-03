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
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage

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
    """Call LLM to perform structured reconnaissance."""
    import os, json

    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    llm = ChatOpenAI(model=model, temperature=0)

    prompt = f"Alert summary:\n{state.alert_summary}\n\nRaw alert data:\n{json.dumps(state.raw_alert, indent=2)[:3000]}"

    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=prompt),
    ]

    try:
        response = await llm.ainvoke(messages)
        content = response.content
        # Extract JSON from the response
        import re
        json_match = re.search(r'\{[\s\S]*\}', content)
        if json_match:
            return json.loads(json_match.group())
    except Exception as exc:  # noqa: BLE001
        logger.warning("recon llm failed", error=str(exc))

    # Fallback: heuristic extraction
    iocs = extract_iocs(state.alert_summary)
    techniques = map_to_mitre(state.alert_summary)
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

    # 2. Enrich IOCs (fan-out, cached)
    async def _enrich(ioc: dict[str, str]) -> tuple[str, dict[str, Any]]:
        cached = state.enrichment_cache.get(ioc["value"])
        if cached:
            return ioc["value"], cached
        result = await enrich_ioc(ioc["value"], ioc["type"])
        return ioc["value"], result

    enrichment_results = await asyncio.gather(*[_enrich(ioc) for ioc in iocs])
    for val, result in enrichment_results:
        state.enrichment_cache[val] = result

    # 3. Build ReconFindings
    mitre = list(set(llm_result.get("mitre_techniques", []) + map_to_mitre(state.alert_summary)))
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
