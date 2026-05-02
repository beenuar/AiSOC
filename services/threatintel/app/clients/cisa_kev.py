"""
CISA Known Exploited Vulnerabilities (KEV) catalog client.

Cyble Open-Source AI Security Operations Center — MIT License
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class CisaKevClient:
    """
    Fetches the CISA Known Exploited Vulnerabilities catalog and converts
    each entry into a normalized IOC-style dict for storage.
    """

    def __init__(self, url: str = _KEV_URL) -> None:
        self._url = url

    async def fetch(self) -> list[dict[str, Any]]:
        """Download and return the full KEV catalog as a list of entries."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                resp = await client.get(self._url, follow_redirects=True)
                resp.raise_for_status()
                body = resp.json()
                entries = body.get("vulnerabilities", [])
                logger.info("CISA KEV fetched", count=len(entries))
                return entries
            except Exception as exc:
                logger.error("CISA KEV fetch failed", error=str(exc))
                return []

    def to_ioc(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Convert a KEV entry to a normalized IOC dict."""
        return {
            "type": "vulnerability",
            "value": entry.get("cveID", ""),
            "description": entry.get("vulnerabilityName", ""),
            "vendor_project": entry.get("vendorProject", ""),
            "product": entry.get("product", ""),
            "required_action": entry.get("requiredAction", ""),
            "due_date": entry.get("dueDate", ""),
            "date_added": entry.get("dateAdded", ""),
            "known_ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
            "source": "cisa-kev",
            "source_ref": f"cisa-kev:{entry.get('cveID', '')}",
            "tags": ["kev", "cisa", "exploited"],
            "tlp": "white",
        }
