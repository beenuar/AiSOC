"""Fuse-time streaming enrichment (Wave 1).

The confidence scorer's ``threat_intel`` factor (weight 0.16) and the
exploit-in-wild vuln boost both read ``fused.enrichments`` — but nothing
populated it in the live path, so every alert scored "no TI match" (-0.3) and
``exploit_in_wild`` stayed ``False`` regardless of the threat-intel and KEV data
the platform already collects.

This module closes that gap: at fuse time it extracts the alert's IOCs, calls
the enrichment service (which fans out to the configured TI providers + CISA
KEV), and merges the results into ``fused.enrichments`` using exactly the schema
the confidence scorer (``misp`` / ``otx`` / ``taxii`` / ``kev`` / ``virustotal``
hits) and ``apply_vuln_boost`` (``vulnerabilities`` list) expect.

Honesty + robustness:

* **No fake TI.** With no provider keys the enrichment service returns empty
  results, so no source-hit keys are emitted and the scorer legitimately keeps
  its "no TI match" prior. TI only contributes when a real feed/provider matches.
* **Fail-soft.** A short timeout, any HTTP error, or a missing service is a
  no-op ({}) — enrichment never blocks or crashes the fusion pipeline.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.models.alert import RawAlert

logger = structlog.get_logger()

# Alert IOC field -> enrichment ioc_type.
_IOC_FIELDS: tuple[tuple[str, str], ...] = (
    ("src_ip", "ip"),
    ("dst_ip", "ip"),
    ("domain", "domain"),
    ("url", "url"),
    ("file_hash", "hash"),
)

# Enrichment provider source name (lower-cased) -> the TI key the confidence
# scorer checks in _ti_contribution.
_SOURCE_TO_TI_KEY: dict[str, str] = {
    "virustotal": "virustotal",
    "otx": "otx",
    "alienvault otx": "otx",
    "alienvault": "otx",
    "misp": "misp",
    "taxii": "taxii",
}


class AlertEnricher:
    """Calls the enrichment service and maps results into fused.enrichments."""

    def __init__(self, *, base_url: str, timeout_seconds: float = 3.0, malicious_risk_floor: float = 50.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds
        self._risk_floor = malicious_risk_floor

    @staticmethod
    def extract_iocs(alert: RawAlert) -> list[dict[str, str]]:
        """Distinct (ioc_type, value) pairs from the alert's IOC fields."""
        seen: set[tuple[str, str]] = set()
        items: list[dict[str, str]] = []
        for field, ioc_type in _IOC_FIELDS:
            val = getattr(alert, field, None)
            if isinstance(val, str) and val.strip():
                key = (ioc_type, val.strip())
                if key not in seen:
                    seen.add(key)
                    items.append({"ioc_type": ioc_type, "value": val.strip()})
        return items

    async def enrich(self, alert: RawAlert) -> dict[str, Any]:
        """Return the enrichment dict to merge into ``fused.enrichments`` ({} on miss)."""
        items = self.extract_iocs(alert)
        if not items:
            return {}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(f"{self._base_url}/enrich/bulk", json={"items": items})
                resp.raise_for_status()
                results = resp.json().get("results", [])
        except Exception as exc:  # noqa: BLE001 — best-effort; never block fusion
            logger.debug("fuse_enrichment.failed", error=str(exc))
            return {}
        return self.to_enrichments(results if isinstance(results, list) else [])

    def to_enrichments(self, results: list[dict[str, Any]]) -> dict[str, Any]:
        """Map enrichment-service results into the scorer/vuln-boost schema."""
        enrichments: dict[str, Any] = {}
        ti_hits: list[dict[str, Any]] = []
        vulnerabilities: list[dict[str, Any]] = []
        source_matches: dict[str, set[str]] = {}
        actors: set[str] = set()
        max_risk = 0.0

        for r in results:
            if not isinstance(r, dict):
                continue
            value = str(r.get("value") or "")
            risk = _as_float(r.get("risk_score"))
            malicious_votes = _as_int(r.get("malicious_votes"))
            max_risk = max(max_risk, risk)

            for v in r.get("vulnerabilities") or []:
                if not isinstance(v, dict):
                    continue
                cve = v.get("cve")
                is_exploited = bool(v.get("exploited") or v.get("kev"))
                vulnerabilities.append(
                    {
                        "cve_id": cve,
                        "is_exploited": is_exploited,
                        "cvss_score": v.get("cvss"),
                        "kev": bool(v.get("kev")),
                        "epss": v.get("epss"),
                    }
                )
                if v.get("kev") and cve:
                    source_matches.setdefault("kev", set()).add(cve)

            classification = r.get("classification") or {}
            for actor in classification.get("threat_actors") or []:
                if isinstance(actor, str) and actor:
                    actors.add(actor)

            if not (risk >= self._risk_floor or malicious_votes > 0):
                continue

            ti_hits.append(
                {
                    "value": value,
                    "risk_score": round(risk, 1),
                    "malicious_votes": malicious_votes,
                    "tags": r.get("tags") or [],
                }
            )
            if malicious_votes > 0 and value:
                source_matches.setdefault("virustotal", set()).add(value)
            for src in r.get("sources") or []:
                name = str((src or {}).get("name", "")).strip().lower()
                key = _SOURCE_TO_TI_KEY.get(name)
                if key and value:
                    source_matches.setdefault(key, set()).add(value)

        for key, matches in source_matches.items():
            enrichments[key] = {"hit": True, "matches": sorted(m for m in matches if m)}
        if vulnerabilities:
            enrichments["vulnerabilities"] = vulnerabilities
        if ti_hits or actors or max_risk > 0:
            enrichments["threat_intel"] = {
                "iocs": ti_hits,
                "max_risk_score": round(max_risk, 1),
                "threat_actors": sorted(actors),
                "sources": sorted(source_matches.keys()),
            }
        return enrichments


def _as_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
