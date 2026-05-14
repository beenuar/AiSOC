"""
Trellix Helix (formerly FireEye Helix) connector.

Helix is Trellix's cloud-native SIEM/XDR. We pull two streams:

1. **Alerts** — ``GET /helix/id/<customer>/api/v3/alerts`` returns scored
   detections across endpoint, network, and email telemetry that Helix
   ingested.
2. **Indicators / events search** — ``POST /helix/id/<customer>/api/v3/search``
   exposes the raw lake; we use it for ``QUERY_LOGS`` so the agent can run
   ad-hoc MQL (Helix's query language).

Auth is API-key based (``x-fireeye-api-key`` header — the legacy header
name still works on Helix). Customer ID is the path-segment slug shown in
the Helix console URL after ``/helix/id/``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class TrellixHelixConnector(BaseConnector):
    """Trellix Helix XDR — alerts + ad-hoc MQL search."""

    connector_id = "trellix_helix"
    connector_name = "Trellix Helix"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Trellix Helix (formerly FireEye Helix) XDR — alerts feed plus "
                "MQL search over raw events. Customer ID is the slug shown in "
                "your Helix console URL after /helix/id/."
            ),
            docs_url="/docs/connectors/trellix-helix",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Helix base URL",
                    placeholder="https://apps.fireeye.com",
                    default="https://apps.fireeye.com",
                    help_text="Most tenants use the default. EU customers may use a regional FQDN.",
                ),
                Field(
                    "customer_id",
                    "string",
                    "Customer ID",
                    placeholder="abcd1234",
                    help_text=("The slug between '/helix/id/' and '/' in your Helix console URL. Lowercase alphanumeric."),
                ),
                Field(
                    "api_key",
                    "secret",
                    "API Key",
                    help_text="Generated under Configure → Authentication → API Keys.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.PIVOT_HOST,
            Capability.PIVOT_USER,
        )

    def __init__(self, base_url: str, customer_id: str, api_key: str):
        self._base = base_url.rstrip("/")
        self._customer = customer_id
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        return {
            "x-fireeye-api-key": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _alerts_url(self) -> str:
        return f"{self._base}/helix/id/{self._customer}/api/v3/alerts"

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    self._alerts_url(),
                    headers=self._headers(),
                    params={"limit": 1},
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
        since = datetime.now(UTC) - timedelta(seconds=since_seconds)
        events: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    self._alerts_url(),
                    headers=self._headers(),
                    params={
                        "limit": 100,
                        # Helix accepts ISO8601 with Z suffix.
                        "time_min": since.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "trellix_helix.alerts_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                for alert in (resp.json() or {}).get("data", []):
                    events.append(alert)
        except Exception as exc:
            logger.warning("trellix_helix.exception", error=str(exc))

        return [self.normalize(e) for e in events]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Trellix Helix alerts expose risk levels {critical, high, medium,
        # low, info}. Mirror critical directly into AiSOC's five-tier
        # ladder rather than collapsing it into high.
        risk = (raw.get("risk") or "").lower()
        if risk == "critical":
            severity = "critical"
        elif risk == "high":
            severity = "high"
        elif risk == "medium":
            severity = "medium"
        elif risk == "low":
            severity = "low"
        else:
            severity = "info"
        return {
            "source": "trellix_helix",
            "category": "siem",
            "severity": severity,
            "title": raw.get("name") or "Trellix Helix alert",
            "description": raw.get("description"),
            "alert_id": raw.get("id"),
            "host": raw.get("hostname"),
            "user": raw.get("username"),
            "raw": raw,
        }
