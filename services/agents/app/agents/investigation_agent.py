"""
Investigation Agent: synthesizes findings from triage and enrichment,
generates a structured investigation report with recommended actions.
"""
from __future__ import annotations

import structlog

from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction
from app.tools.mitre import lookup_technique

logger = structlog.get_logger()


async def run_investigation(state: InvestigationState) -> InvestigationState:
    """
    Synthesize findings and generate an investigation report.
    """
    logger.info("Investigation agent starting", incident_id=str(state.incident_id))

    state.iteration_count += 1

    # Analyze enrichment results for threat patterns
    malicious_iocs = {
        k: v
        for k, v in state.ioc_enrichments.items()
        if v.get("threat_classification") in ("malicious", "suspicious")
    }

    # Analyze MITRE techniques for attack stage
    attack_stages = set()
    for tid in state.mitre_mappings:
        info = lookup_technique(tid)
        attack_stages.add(info.get("tactic_name", "Unknown"))

    # --- Generate narrative findings ---
    if malicious_iocs:
        state.add_finding(
            f"CONFIRMED THREAT: {len(malicious_iocs)} malicious IOC(s) identified. "
            f"Immediate containment recommended."
        )

    if attack_stages:
        state.add_finding(
            f"Attack stages observed: {', '.join(sorted(attack_stages))}. "
            f"This indicates a {_classify_attack_complexity(attack_stages)} attack."
        )

    # --- Recommend actions based on findings ---
    if malicious_iocs:
        for ioc, data in malicious_iocs.items():
            if data.get("ioc_type") == "ip":
                state.proposed_actions.append(
                    ProposedAction(
                        action_type="block_ip",
                        description=f"Block malicious IP: {ioc}",
                        risk_level=ActionRisk.MEDIUM,
                        target=ioc,
                        requires_approval=False,
                        parameters={"ip": ioc},
                        rationale=f"Malicious score: {data.get('malicious_score', 'N/A')}",
                    )
                )
            elif data.get("ioc_type") == "domain":
                state.proposed_actions.append(
                    ProposedAction(
                        action_type="block_domain",
                        description=f"Block malicious domain: {ioc}",
                        risk_level=ActionRisk.MEDIUM,
                        target=ioc,
                        requires_approval=False,
                        parameters={"domain": ioc},
                        rationale=f"Malicious score: {data.get('malicious_score', 'N/A')}",
                    )
                )

    # --- Exfiltration detection ---
    if "Exfiltration" in attack_stages or "Command and Control" in attack_stages:
        state.add_finding(
            "CRITICAL: Evidence of C2 or exfiltration stage detected. "
            "Recommend immediate network isolation and forensic acquisition."
        )
        state.proposed_actions.append(
            ProposedAction(
                action_type="capture_forensics",
                description="Initiate memory and disk forensic acquisition",
                risk_level=ActionRisk.LOW,
                target=state.raw_alert.get("hostname", "unknown"),
                requires_approval=True,
                rationale="Exfiltration/C2 stage detected — preserve evidence",
            )
        )

    state.status = AgentStatus.COMPLETED
    state.add_finding(
        f"Investigation complete. Total proposed actions: {len(state.proposed_actions)}"
    )

    logger.info(
        "Investigation complete",
        findings_count=len(state.findings),
        proposed_actions=len(state.proposed_actions),
    )
    return state


def _classify_attack_complexity(stages: set[str]) -> str:
    if len(stages) >= 4:
        return "multi-stage sophisticated"
    if len(stages) >= 2:
        return "multi-stage"
    return "single-stage"
