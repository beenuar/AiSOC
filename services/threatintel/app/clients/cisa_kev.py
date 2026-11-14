"""
CISA Known Exploited Vulnerabilities (KEV) catalog client.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

#: The canonical catalog, published by CISA on cisa.gov. Tried first, always.
_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

#: CISA's own GitHub organisation publishes the identical file, and it is the
#: fallback rather than a third-party copy for exactly that reason — same
#: publisher, same schema (`catalogVersion`, `count`, `vulnerabilities[]`),
#: verified byte-for-byte in shape against the canonical URL.
#:
#: This exists because cisa.gov sits behind an edge that returns
#: `403 Access Denied` to whole networks regardless of user agent — observed
#: from a plain laptop, with curl, httpx and a browser UA all refused. Without
#: a fallback, every deployment on such a network gets a healthy threatintel
#: container, a registered feed, and permanently zero indicators: a silent
#: failure that looks exactly like "nothing has been published yet".
_KEV_FALLBACK_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"

#: cisa.gov's edge also refuses an absent or obviously-robotic user agent on
#: some paths. Identifying the client is both politer and more likely to work
#: than defaulting to `python-httpx/x.y`.
_USER_AGENT = "AiSOC/1.0 (+https://github.com/beenuar/AiSOC)"


class CisaKevClient:
    """
    Fetches the CISA Known Exploited Vulnerabilities catalog and converts
    each entry into a normalized IOC-style dict for storage.
    """

    def __init__(self, url: str = _KEV_URL, fallback_url: str | None = _KEV_FALLBACK_URL) -> None:
        self._url = url
        self._fallback_url = fallback_url

    async def fetch(self) -> list[dict[str, Any]]:
        """Download and return the full KEV catalog as a list of entries.

        Returns ``[]`` only when *every* source failed, and logs at ``error``
        when it does — a caller cannot distinguish an empty catalog from an
        unreachable one by the return value, so the log line has to carry it.
        """
        sources = [("cisa.gov", self._url)]
        if self._fallback_url:
            sources.append(("cisagov/kev-data", self._fallback_url))

        headers = {"User-Agent": _USER_AGENT, "Accept": "application/json"}
        async with httpx.AsyncClient(timeout=60.0, headers=headers) as client:
            for label, url in sources:
                try:
                    resp = await client.get(url, follow_redirects=True)
                    resp.raise_for_status()
                    entries = resp.json().get("vulnerabilities", [])
                except Exception as exc:
                    logger.warning("CISA KEV source unavailable", source=label, error=str(exc))
                    continue
                logger.info("CISA KEV fetched", source=label, count=len(entries))
                return entries

        logger.error(
            "CISA KEV fetch failed from every source; the threat-intel page will stay empty",
            sources=[label for label, _ in sources],
        )
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
