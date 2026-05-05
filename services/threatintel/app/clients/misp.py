"""
MISP client for fetching threat intelligence events and attributes.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)


class MispClient:
    """
    Async MISP REST API client.

    Supports fetching:
    - Recent events (with attributes/tags)
    - Specific event by ID
    - IOC export in text format
    """

    def __init__(
        self,
        url: str,
        api_key: str,
        verify_ssl: bool = True,
    ) -> None:
        self._base_url = url.rstrip("/")
        self._api_key = api_key
        self._verify_ssl = verify_ssl
        self._headers = {
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def get_recent_events(
        self,
        since_hours: int = 24,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Fetch MISP events published within the last N hours."""
        since_ts = int((datetime.now(UTC) - timedelta(hours=since_hours)).timestamp())
        params = {
            "timestamp": since_ts,
            "limit": limit,
            "with_attachments": 0,
            "includeEventTags": 1,
            "includeAttributeTags": 1,
        }
        async with httpx.AsyncClient(
            headers=self._headers,
            verify=self._verify_ssl,
            timeout=60.0,
        ) as client:
            try:
                resp = await client.post(
                    f"{self._base_url}/events/restSearch",
                    json={"returnFormat": "json", **params},
                )
                resp.raise_for_status()
                body = resp.json()
                events = body.get("response", [])
                if isinstance(events, dict) and "Event" in events:
                    events = [events]
                logger.info("MISP events fetched", count=len(events))
                return [e.get("Event", e) for e in events if isinstance(e, dict)]
            except Exception as exc:
                logger.error("MISP fetch failed", error=str(exc))
                return []

    async def get_event(self, event_id: str) -> dict[str, Any] | None:
        """Fetch a single MISP event by ID."""
        async with httpx.AsyncClient(headers=self._headers, verify=self._verify_ssl, timeout=30.0) as client:
            try:
                resp = await client.get(f"{self._base_url}/events/{event_id}")
                resp.raise_for_status()
                body = resp.json()
                return body.get("Event")
            except Exception as exc:
                logger.error("MISP get_event failed", event_id=event_id, error=str(exc))
                return None

    def extract_iocs(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Extract IOC attributes from a MISP event dict."""
        iocs: list[dict[str, Any]] = []
        for attr in event.get("Attribute", []):
            ioc = {
                "type": attr.get("type"),
                "value": attr.get("value"),
                "category": attr.get("category"),
                "to_ids": attr.get("to_ids", False),
                "comment": attr.get("comment", ""),
                "tags": [t.get("name") for t in attr.get("Tag", [])],
                "source": "misp",
                "source_ref": f"misp:{event.get('uuid', '')}",
                "event_info": event.get("info", ""),
                "tlp": self._extract_tlp(attr),
            }
            iocs.append(ioc)
        return iocs

    @staticmethod
    def _extract_tlp(attr: dict[str, Any]) -> str:
        for tag in attr.get("Tag", []):
            name: str = tag.get("name", "").lower()
            if name.startswith("tlp:"):
                return name.split(":", 1)[-1]
        return "white"
