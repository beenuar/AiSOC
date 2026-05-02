"""
AlienVault OTX (Open Threat Exchange) client.

Cyble Open-Source AI Security Operations Center — MIT License
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_OTX_BASE = "https://otx.alienvault.com"


class OtxClient:
    """
    Async OTX REST API v1 client.

    Fetches:
    - Subscribed pulse feed (with IOC indicators)
    - Pulse details
    - Single indicator lookups
    """

    def __init__(self, api_key: str, base_url: str = _OTX_BASE) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json",
        }

    async def get_subscribed_pulses(
        self,
        modified_since: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Fetch pulses from the subscribed feed.

        Args:
            modified_since: ISO-8601 timestamp, fetch pulses modified after this time.
            limit: Max pulses per request (paginated internally).

        Returns:
            List of pulse dicts.
        """
        pulses: list[dict[str, Any]] = []
        page = 1

        async with httpx.AsyncClient(
            headers=self._headers, timeout=60.0
        ) as client:
            while True:
                params: dict[str, Any] = {"limit": limit, "page": page}
                if modified_since:
                    params["modified_since"] = modified_since

                try:
                    resp = await client.get(
                        f"{self._base_url}/api/v1/pulses/subscribed",
                        params=params,
                    )
                    resp.raise_for_status()
                    body = resp.json()
                    results = body.get("results", [])
                    pulses.extend(results)

                    if not body.get("next"):
                        break
                    page += 1
                except Exception as exc:
                    logger.error("OTX fetch failed", page=page, error=str(exc))
                    break

        logger.info("OTX pulses fetched", count=len(pulses))
        return pulses

    def extract_iocs(self, pulse: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract IOC indicators from an OTX pulse."""
        iocs: list[dict[str, Any]] = []
        pulse_id = pulse.get("id", "")
        pulse_name = pulse.get("name", "")

        for ind in pulse.get("indicators", []):
            ioc_type = self._map_indicator_type(ind.get("type", ""))
            if not ioc_type:
                continue
            iocs.append({
                "type": ioc_type,
                "value": ind.get("indicator", ""),
                "description": ind.get("description", ""),
                "tags": pulse.get("tags", []),
                "source": "otx",
                "source_ref": f"otx:{pulse_id}",
                "pulse_name": pulse_name,
                "tlp": pulse.get("tlp", "white"),
                "malware_families": pulse.get("malware_families", []),
                "attack_ids": pulse.get("attack_ids", []),
            })
        return iocs

    @staticmethod
    def _map_indicator_type(otx_type: str) -> str:
        mapping = {
            "IPv4": "ipv4-addr",
            "IPv6": "ipv6-addr",
            "domain": "domain-name",
            "hostname": "domain-name",
            "URL": "url",
            "FileHash-MD5": "file-hash:MD5",
            "FileHash-SHA1": "file-hash:SHA-1",
            "FileHash-SHA256": "file-hash:SHA-256",
            "email": "email-addr",
            "CVE": "vulnerability",
            "CIDR": "ipv4-addr",
        }
        return mapping.get(otx_type, "")
