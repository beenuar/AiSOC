"""
Vuln↔alert correlation booster (Tier 3.5).

Checks alert enrichments for `vulnerabilities` list populated by the enrichment
service. If any entry has `is_exploited: true`, we set `exploit_in_wild=True`
on the FusedAlert and append a positive ConfidenceFactor.
"""

import structlog

from app.models.alert import ConfidenceFactor, FusedAlert

logger = structlog.get_logger()


def apply_vuln_boost(fused: FusedAlert) -> FusedAlert:
    """
    Inspect enrichments for exploited vulnerabilities and mutate the alert.

    Expected enrichment shape (from enrichment service):
        "vulnerabilities": [
            {"cve_id": "CVE-2024-1234", "is_exploited": true, "cvss_score": 9.8, ...},
            ...
        ]
    """
    vulns = fused.enrichments.get("vulnerabilities", []) or []
    exploited = [v for v in vulns if isinstance(v, dict) and v.get("is_exploited")]

    if not exploited:
        return fused

    fused.exploit_in_wild = True

    # Pick the highest CVSS exploited vuln for the rationale (or just the first)
    top = max(exploited, key=lambda v: v.get("cvss_score", 0.0))
    cve = top.get("cve_id", "unknown")

    factor = ConfidenceFactor(
        factor="exploit_in_wild",
        label="Exploit in the wild",
        value=f"{cve} (CVSS {top.get('cvss_score', '?')})",
        contribution=+0.25,
        weight=0.15,
    )
    fused.confidence_rationale.append(factor)
    fused.confidence_score = min(1.0, fused.confidence_score + 0.15)

    logger.info(
        "Vuln boost applied",
        alert_id=str(fused.id),
        cve=cve,
        cvss=top.get("cvss_score"),
    )
    return fused
