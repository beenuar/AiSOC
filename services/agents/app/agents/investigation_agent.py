"""
Investigation Agent: synthesizes findings from triage and enrichment,
generates a structured investigation report with recommended actions.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import structlog

from app.confidence import score_investigation
from app.models.state import ActionRisk, AgentStatus, InvestigationState, ProposedAction
from app.tools.mitre import lookup_technique

logger = structlog.get_logger()

# Address of the threat intel service that hosts the attribution endpoint.
# Defaults to the in-cluster Docker Compose hostname; override via env in
# Kubernetes / Fly / standalone deployments.
THREAT_INTEL_SERVICE_URL = os.getenv("AISOC_THREATINTEL_URL", "http://threatintel:8083").rstrip("/")
ATTRIBUTION_TIMEOUT_SECONDS = float(os.getenv("AISOC_ATTRIBUTION_TIMEOUT_SECONDS", "30.0"))


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

    # --- Perform threat actor attribution (best-effort, non-blocking on error) ---
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
    state.add_finding(f"Investigation verdict: {verdict} (confidence={confidence:.2f})")

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


def _classify_attack_complexity(stages: set[str]) -> str:
    if len(stages) >= 4:
        return "multi-stage sophisticated"
    if len(stages) >= 2:
        return "multi-stage"
    return "single-stage"


async def _perform_threat_actor_attribution(state: InvestigationState, malicious_iocs: dict[str, dict[str, Any]]) -> None:
    """Attribute the incident to a known threat actor.

    Posts only the IOCs already classified as ``malicious``/``suspicious``
    plus the observed MITRE techniques to the threat intel service's
    ``/api/v1/actors/attribute`` endpoint and records the result on
    ``state.threat_intel["attribution"]``. Failure is soft — a finding is
    added and the rest of the investigation continues.

    Severity in findings uses AiSOC's four-tier ladder
    (``info``, ``low``, ``medium``, ``high``) to stay consistent with
    detection content and connector normalization.
    """
    try:
        # Only ship the iocs that triage already flagged. This keeps the
        # request small and avoids leaking benign indicators into the
        # attribution model. Fall back to all enrichments if triage didn't
        # mark anything (so MITRE-only attribution still works).
        ioc_source = malicious_iocs if malicious_iocs else state.ioc_enrichments
        iocs_payload = [{"value": ioc, "type": data.get("ioc_type", "unknown")} for ioc, data in ioc_source.items()]
        if not iocs_payload and not state.mitre_mappings:
            state.add_finding("Threat actor attribution skipped: no IOCs or MITRE techniques available")
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
            severity = "high" if confidence > 0.7 else "medium"
            state.add_finding(f"[{severity}] Attributed incident to {actor_name} (confidence={confidence:.2f})")
            for reason in attribution_result.get("reasoning", []):
                state.add_finding(f"Attribution factor: {reason}")
            logger.info(
                "Threat actor attribution successful",
                actor=actor_name,
                confidence=confidence,
            )
        else:
            state.add_finding("No strong threat actor attribution possible with current intelligence")
            logger.info("No strong threat actor attribution possible")

    except Exception as exc:
        logger.warning("Threat actor attribution failed", error=str(exc))
        state.add_finding(f"Threat actor attribution failed: {exc}")


async def _call_attribution_service(
    iocs: list[dict],
    mitre_techniques: list[str],
    case_metadata: dict,
) -> dict:
    """Call the threat intel service's attribution endpoint.

    Args:
        iocs: List of indicators of compromise; each item must include
            ``value`` and ``type``. Other fields (``source``, ``first_seen``,
            ``last_seen``) are forwarded as-is when present.
        mitre_techniques: MITRE ATT&CK technique IDs (e.g. ``["T1566", "T1059"]``).
        case_metadata: Free-form case metadata; ``targets`` (list of sector
            strings) is the only field consulted by attribution today.

    Returns:
        Decoded JSON response from the attribution endpoint with at least
        ``actor_id``, ``actor_name``, ``confidence_score``, and ``reasoning``.

    Raises:
        httpx.HTTPError: on transport or non-2xx responses; the caller
            converts these into a non-fatal finding.
    """
    try:
        async with httpx.AsyncClient(timeout=ATTRIBUTION_TIMEOUT_SECONDS) as client:
            response = await client.post(
                f"{THREAT_INTEL_SERVICE_URL}/api/v1/actors/attribute",
                json={
                    "iocs": iocs,
                    "mitre_techniques": mitre_techniques,
                    "case_metadata": case_metadata,
                },
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPError as exc:
        logger.error("HTTP error calling attribution service", error=str(exc))
        raise
