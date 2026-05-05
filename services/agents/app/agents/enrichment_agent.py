"""
Enrichment Agent: bulk-enriches all pending IOCs via the enrichment microservice.
"""

from __future__ import annotations

import structlog

from app.models.state import InvestigationState
from app.tools.enrichment import bulk_enrich_iocs

logger = structlog.get_logger()


async def run_enrichment(state: InvestigationState) -> InvestigationState:
    """Enrich all IOCs collected during triage."""
    logger.info("Enrichment agent starting", incident_id=str(state.incident_id))

    pending_iocs: list[dict] = state.threat_intel.get("pending_iocs", [])
    if not pending_iocs:
        state.add_finding("No IOCs to enrich — skipping enrichment phase")
        return state

    results = await bulk_enrich_iocs(pending_iocs)

    enriched: dict[str, dict] = {}
    malicious_count = 0

    for result in results:
        ioc_value = result.get("value", "")
        enriched[ioc_value] = result

        threat_class = result.get("threat_classification", "")
        if threat_class in ("malicious", "suspicious"):
            malicious_count += 1
            score = result.get("malicious_score", 0)
            state.add_finding(f"IOC '{ioc_value}' classified as {threat_class} (malicious_score={score})")

    state.ioc_enrichments = enriched

    if malicious_count > 0:
        state.add_finding(f"Enrichment complete: {malicious_count}/{len(results)} IOCs are malicious/suspicious")
    else:
        state.add_finding(f"Enrichment complete: {len(results)} IOCs enriched, none flagged as malicious")

    logger.info(
        "Enrichment complete",
        ioc_count=len(results),
        malicious_count=malicious_count,
    )
    return state
