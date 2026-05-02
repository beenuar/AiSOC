"""
Splunk connector.
Runs saved searches and fetches notable events from Splunk SIEM.
"""
from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector

logger = structlog.get_logger()


class SplunkConnector(BaseConnector):
    connector_id = "splunk"
    connector_name = "Splunk SIEM"

    def __init__(self, base_url: str, token: str, saved_search: str = "AiSOC_Alerts"):
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._saved_search = saved_search

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    async def test_connection(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0, verify=False) as client:
            try:
                resp = await client.get(
                    f"{self._base_url}/services/server/info",
                    headers=self._headers(),
                    params={"output_mode": "json"},
                )
                resp.raise_for_status()
                return {"success": True, "connector": self.connector_id, "version": resp.json().get("entry", [{}])[0].get("content", {}).get("version")}
            except Exception as exc:
                return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        search_query = f"search index=notable earliest=-{since_seconds}s | head 100"

        async with httpx.AsyncClient(timeout=60.0, verify=False) as client:
            # Create search job
            resp = await client.post(
                f"{self._base_url}/services/search/jobs",
                headers=self._headers(),
                data={"search": search_query, "output_mode": "json"},
            )
            resp.raise_for_status()
            sid = resp.json().get("sid")

            if not sid:
                return []

            # Wait for completion (simple polling)
            import asyncio
            for _ in range(10):
                status_resp = await client.get(
                    f"{self._base_url}/services/search/jobs/{sid}",
                    headers=self._headers(),
                    params={"output_mode": "json"},
                )
                dispatch_state = status_resp.json().get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
                if dispatch_state == "DONE":
                    break
                await asyncio.sleep(2)

            # Fetch results
            results_resp = await client.get(
                f"{self._base_url}/services/search/jobs/{sid}/results",
                headers=self._headers(),
                params={"output_mode": "json", "count": 100},
            )
            results_resp.raise_for_status()
            results = results_resp.json().get("results", [])

        return [self.normalize(r) for r in results]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        urgency_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
        return {
            "source": self.connector_id,
            "external_id": raw.get("event_id", raw.get("_cd", "")),
            "title": raw.get("source", "Splunk Notable Event"),
            "description": raw.get("description", ""),
            "severity": urgency_map.get(raw.get("urgency", "medium"), "medium"),
            "src_ip": raw.get("src", raw.get("src_ip")),
            "hostname": raw.get("host"),
            "raw_event": raw,
            "created_at": raw.get("_time"),
        }
