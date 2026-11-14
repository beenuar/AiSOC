"""GreyNoise connector.

Pulls recently-observed malicious IPs (GNQL query) from the GreyNoise API as an
alert/IOC stream, and provides IP reputation enrichment for the agent.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class GreyNoiseConnector(BaseConnector):
    connector_id = "greynoise"
    connector_name = "GreyNoise"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="GreyNoise threat intelligence — malicious IP observations (GNQL) as alerts.",
            docs_url="/docs/connectors/greynoise",
            fields=[
                Field("api_key", "secret", "API Key"),
                Field(
                    "query",
                    "string",
                    "GNQL query",
                    required=False,
                    default="classification:malicious last_seen:1d",
                    help_text="GreyNoise Query Language filter used to pull observations.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.ENRICH_IOC)

    def __init__(self, api_key: str, query: str = "classification:malicious last_seen:1d"):
        self._api_key = api_key
        self._query = query or "classification:malicious last_seen:1d"

    def _headers(self) -> dict[str, str]:
        return {"key": self._api_key, "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get("https://api.greynoise.io/ping", headers=self._headers())
                return {"success": resp.status_code < 400, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("greynoise.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    "https://api.greynoise.io/v2/experimental/gnql",
                    headers=self._headers(),
                    params={"query": self._query, "size": 200},
                )
                resp.raise_for_status()
                data = resp.json().get("data", [])
        except Exception as exc:
            logger.warning("greynoise.fetch_failed", error=str(exc))
            return []
        return [self.normalize(d) for d in data if isinstance(d, dict)]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw, dict) and "raw_event" in raw and raw.get("source") == self.connector_id:
            return raw
        classification = str(raw.get("classification", "")).lower()
        severity = "high" if classification == "malicious" else ("medium" if classification == "unknown" else "low")
        ip = raw.get("ip")
        return {
            "source": self.connector_id,
            "external_id": str(ip) if ip else "",
            "title": f"GreyNoise {classification or 'observation'}: {ip}",
            "description": raw.get("name") or raw.get("metadata", {}).get("category", ""),
            "severity": severity,
            "src_ip": ip,
            "raw_event": raw,
            "created_at": raw.get("last_seen"),
        }
