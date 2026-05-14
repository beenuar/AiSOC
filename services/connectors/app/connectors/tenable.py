"""
Tenable.io / Tenable Vulnerability Management connector.

Tenable.io uses an Access Key + Secret Key as a stable API auth pair.
We model vulnerability data as an "alert" stream of detected
vulnerabilities so the agent can treat them uniformly.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class TenableConnector(BaseConnector):
    """Tenable.io VM."""

    connector_id = "tenable_io"
    connector_name = "Tenable.io"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Tenable.io / Tenable Vulnerability Management. Pulls "
                "vulnerability findings as alerts and exposes asset and "
                "vulnerability enrichment for the agent."
            ),
            docs_url="/docs/connectors/tenable-io",
            fields=[
                Field("access_key", "string", "Access Key"),
                Field("secret_key", "secret", "Secret Key"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PIVOT_HOST,
            Capability.PIVOT_IP,
            Capability.ENRICH_VULN,
            Capability.ENRICH_ASSET,
        )

    def __init__(self, access_key: str, secret_key: str):
        self._access = access_key
        self._secret = secret_key
        self._base = "https://cloud.tenable.com"

    def _headers(self) -> dict[str, str]:
        return {
            "X-ApiKeys": f"accessKey={self._access}; secretKey={self._secret}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/server/properties",
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return {"success": True, "connector": self.connector_id}
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # Use the workbenches export filtered by last_found within the window.
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/workbenches/vulnerabilities",
                    headers=self._headers(),
                    params={
                        "filter.search_type": "and",
                        "filter.0.filter": "plugin.attributes.vpr.score",
                        "filter.0.quality": "gte",
                        "filter.0.value": "7.0",
                        "date_range": max(1, since_seconds // 86400),
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "tenable.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = (resp.json() or {}).get("vulnerabilities") or []
                return [self.normalize(i) for i in items[:200]]
        except Exception as exc:
            logger.warning("tenable.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Tenable.io exposes the CVSSv3 severity ladder (0=Info, 1=Low,
        # 2=Medium, 3=High, 4=Critical). Mirror it directly into AiSOC's
        # five-tier ladder so genuine Critical vulnerabilities are not
        # silently downgraded to High.
        sev_int = raw.get("severity")
        sev_map = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
        sev = sev_map.get(sev_int, "info")
        return {
            "source": "tenable_io",
            "category": "cloud",
            "severity": sev,
            "title": raw.get("plugin_name") or "Tenable vulnerability",
            "description": raw.get("plugin_family"),
            "alert_id": str(raw.get("plugin_id")) if raw.get("plugin_id") else None,
            "host": None,
            "raw": raw,
        }
