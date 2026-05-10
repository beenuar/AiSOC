"""
Triage Agent: first responder that classifies severity, extracts IOCs,
maps MITRE techniques, and decides whether automated response is safe.
"""

from __future__ import annotations

import structlog

from app.confidence import score_triage
from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction
from app.tools.mitre import map_techniques_to_kill_chain

logger = structlog.get_logger()

_CRITICAL_KEYWORDS = {
    "ransomware",
    "lateral movement",
    "credential dump",
    "domain admin",
    "exfiltration",
    "mimikatz",
    "cobalt strike",
    "c2",
    "beacon",
    "rootkit",
    "supply chain",
    "zero-day",
    "data breach",
}

_HIGH_KEYWORDS = {
    "phishing",
    "malware",
    "exploit",
    "privilege escalation",
    "brute force",
    "suspicious login",
    "anomaly",
    "backdoor",
}


def _score_alert(state: InvestigationState) -> tuple[str, float]:
    """Return (severity, risk_score) based on alert content heuristics."""
    text = (state.alert_summary + " " + str(state.raw_alert)).lower()
    risk = state.raw_alert.get("risk_score", 0.0)

    if any(kw in text for kw in _CRITICAL_KEYWORDS):
        return "critical", max(risk, 0.9)
    if any(kw in text for kw in _HIGH_KEYWORDS):
        return "high", max(risk, 0.7)
    return "medium", max(risk, 0.4)


async def run_triage(state: InvestigationState) -> InvestigationState:
    """
    Execute the triage phase:
    - Score alert severity
    - Extract IOCs from raw alert
    - Map MITRE techniques
    - Propose initial actions
    """
    logger.info("Triage agent starting", incident_id=str(state.incident_id))

    state.status = AgentStatus.RUNNING
    state.iteration_count += 1

    # --- Severity scoring ---
    severity, risk_score = _score_alert(state)
    state.add_finding(f"Triage severity: {severity} (risk_score={risk_score:.2f})")

    # --- IOC extraction from raw alert ---
    iocs: list[dict] = []
    raw = state.raw_alert
    if raw.get("src_ip"):
        iocs.append({"value": raw["src_ip"], "ioc_type": "ip"})
    if raw.get("dst_ip"):
        iocs.append({"value": raw["dst_ip"], "ioc_type": "ip"})
    if raw.get("domain"):
        iocs.append({"value": raw["domain"], "ioc_type": "domain"})
    if raw.get("file_hash"):
        iocs.append({"value": raw["file_hash"], "ioc_type": "hash"})
    if raw.get("url"):
        iocs.append({"value": raw["url"], "ioc_type": "url"})

    state.add_finding(f"Extracted {len(iocs)} IOCs for enrichment: {[i['value'] for i in iocs]}")
    state.threat_intel["pending_iocs"] = iocs

    # --- MITRE mapping ---
    techniques = raw.get("mitre_techniques", [])
    if techniques:
        kill_chain = map_techniques_to_kill_chain(techniques)
        state.mitre_mappings = techniques
        state.add_finding(f"MITRE kill chain: {kill_chain}")

    # --- Propose isolation if critical ---
    if severity == "critical" and raw.get("hostname"):
        state.proposed_actions.append(
            ProposedAction(
                action_type="isolate_host",
                description=f"Isolate host '{raw['hostname']}' from network",
                risk_level=ActionRisk.HIGH,
                target=raw["hostname"],
                requires_approval=True,
                rationale="Critical severity alert with host identifier present",
            )
        )

    confidence, basis, verdict = score_triage(state)
    state.confidence = confidence
    state.confidence_basis = basis
    state.verdict = verdict
    state.add_finding(f"Triage verdict: {verdict} (confidence={confidence:.2f})")

    state.add_finding("Triage phase complete — proceeding to enrichment")
    logger.info(
        "Triage complete",
        severity=severity,
        ioc_count=len(iocs),
        confidence=round(confidence, 2),
        verdict=verdict,
    )
    return state
