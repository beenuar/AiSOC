"""
Investigation Agent: synthesizes findings from triage and enrichment,
generates a structured investigation report with recommended actions.
"""

from __future__ import annotations

import httpx
import structlog

from app.confidence import score_investigation
from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction
from app.tools.mitre import lookup_technique

logger = structlog.get_logger()

# URL for the threat intel service
THREAT_INTEL_SERVICE_URL = "http://threatintel:8083"


async def run_investigation(state: InvestigationState) -> InvestigationState:
    """
    Synthesize findings and generate an investigation report.
    """
    logger.info("Investigation agent starting", incident_id=str(state.incident_id))

    state.iteration_count += 1

    # Analyze enrichment results for threat patterns
    malicious_iocs = {k: v for k, v in state.ioc_enrichments.items() if v.get("threat_classification") in ("malicious", "suspicious")}

    # Analyze MITRE techniques for attack stage
    attack_stages = set()
    for tid in state.mitre_mappings:
        info = lookup_technique(tid)
        attack_stages.add(info.get("tactic_name", "Unknown"))

    # --- Perform threat actor attribution ---
    await _perform_threat_actor_attribution(state, malicious_iocs)

    # --- Generate narrative findings ---
    if malicious_iocs:
        state.add_finding(f"CONFIRMED THREAT: {len(malicious_iocs)} malicious IOC(s) identified. Immediate containment recommended.")

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
            "CRITICAL: Evidence of C2 or exfiltration stage detected. Recommend immediate network isolation and forensic acquisition."
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

    confidence, basis, verdict = score_investigation(state)
    state.confidence = confidence
    state.confidence_basis = basis
    state.verdict = verdict
    state.add_finding(
        f"Investigation verdict: {verdict} (confidence={confidence:.2f})"
    )

    state.status = AgentStatus.COMPLETED
    state.add_finding(f"Investigation complete. Total proposed actions: {len(state.proposed_actions)}")

    logger.info(
        "Investigation complete",
        findings_count=len(state.findings),
        proposed_actions=len(state.proposed_actions),
        confidence=round(confidence, 2),
        verdict=verdict,
    )
    return state


async def _perform_threat_actor_attribution(
    state: InvestigationState, malicious_iocs: dict
) -> None:
    """Attribute the incident to a known threat actor.

    Posts the incident's IOCs and observed MITRE techniques to the threat
    intel service's ``/api/v1/actors/attribute`` endpoint and records the
    result on ``state.threat_intel["attribution"]``. Failure is soft — a
    finding is added and the rest of the investigation continues.
    """
    try:
        iocs_payload = [
            {"value": ioc, "type": data.get("ioc_type", "unknown")}
            for ioc, data in state.ioc_enrichments.items()
        ]
        if not iocs_payload and not state.mitre_mappings:
            state.add_finding(
                "Threat actor attribution skipped: no IOCs or MITRE techniques available"
            )
            return

        mitre_techniques: list[str] = list(state.mitre_mappings)

        # raw_alert is the only structured input we currently surface to the
        # agent. Anything richer (target sectors, industry, geography) belongs
        # in alert metadata and can be promoted to first-class fields later.
        raw = state.raw_alert or {}
        case_metadata = {
            "targets": raw.get("targets", []),
            "industry": raw.get("industry", ""),
            "geography": raw.get("geography", ""),
            "severity": raw.get("severity", "medium"),
        }

        attribution_result = await _call_attribution_service(
            iocs=iocs_payload,
            mitre_techniques=mitre_techniques,
            case_metadata=case_metadata,
        )

        state.threat_intel["attribution"] = attribution_result

        if attribution_result and attribution_result.get("actor_id") != "unknown":
            actor_name = attribution_result.get("actor_name", "Unknown")
            confidence = float(attribution_result.get("confidence_score", 0.0))
            severity = "HIGH" if confidence > 0.7 else "MEDIUM"
            state.add_finding(
                f"[{severity}] Attributed incident to {actor_name} "
                f"(confidence={confidence:.2f})"
            )
            for reason in attribution_result.get("reasoning", []):
                state.add_finding(f"Attribution factor: {reason}")
            logger.info(
                "Threat actor attribution successful",
                actor=actor_name,
                confidence=confidence,
            )
        else:
            state.add_finding(
                "No strong threat actor attribution possible with current intelligence"
            )
            logger.info("No strong threat actor attribution possible")

    except Exception as exc:
        logger.warning("Threat actor attribution failed", error=str(exc))
        state.add_finding(f"Threat actor attribution failed: {exc}")


async def _call_attribution_service(
    iocs: list[dict], 
    mitre_techniques: list[str], 
    case_metadata: dict
) -> dict:
    """
    Call the threat intel service's attribution endpoint.
    
    Args:
        iocs: List of indicators of compromise with fields:
              - value: IOC value (string)
              - type: IOC type (e.g., "ipv4", "domain", "sha256")
              - source: Source of the IOC
              - first_seen: ISO 8601 timestamp
              - last_seen: ISO 8601 timestamp
        mitre_techniques: List of MITRE ATT&CK technique IDs (e.g., ["T1566", "T1059"])
        case_metadata: Case metadata with fields:
                       - targets: List of target sectors
                       - industry: Industry sector
                       - geography: Geographic location
                       - severity: Case severity level
        
    Returns:
        Attribution result from the service with fields:
        - actor_id: Unique identifier for the actor
        - actor_name: Human-readable name of the actor
        - confidence_score: Confidence in attribution (0.0-1.0)
        - matched_indicators: List of matched indicators
        - reasoning: List of reasoning steps
        - timestamp: ISO 8601 timestamp of attribution
    """
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{THREAT_INTEL_SERVICE_URL}/api/v1/actors/attribute",
                json={
                    "iocs": iocs,
                    "mitre_techniques": mitre_techniques,
                    "case_metadata": case_metadata
                }
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        logger.error("HTTP error calling attribution service", error=str(exc))
        raise
    except Exception as exc:
        logger.error("Error calling attribution service", error=str(exc))
        raise


def _classify_attack_complexity(stages: set[str]) -> str:
    if len(stages) >= 4:
        return "multi-stage sophisticated"
    if len(stages) >= 2:
        return "multi-stage"
    return "single-stage"
