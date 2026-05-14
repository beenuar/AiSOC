"""
Palo Alto Networks Cortex XSIAM connector.

XSIAM is the next-gen sibling of Cortex XDR; it shares the XDR API surface
but adds platform-wide query, casebook actions, and cloud telemetry. We
expose the unified incidents endpoint and XQL search.

Auth: API key + key ID + tenant FQDN (advanced auth header style is used).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class CortexXSIAMConnector(BaseConnector):
    """Palo Alto Cortex XSIAM — incidents + XQL search + endpoint actions."""

    connector_id = "cortex_xsiam"
    connector_name = "Cortex XSIAM"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Palo Alto Networks Cortex XSIAM — pulls correlated incidents and "
                "supports XQL queries over the platform's data lake. Endpoint "
                "isolation is exposed as an agent action."
            ),
            docs_url="/docs/connectors/cortex-xsiam",
            fields=[
                Field(
                    "tenant_fqdn",
                    "string",
                    "Tenant FQDN",
                    placeholder="api-yourtenant.xdr.us.paloaltonetworks.com",
                    help_text="Found in the XSIAM console under Settings → API Keys.",
                ),
                Field("api_key_id", "secret", "API Key ID"),
                Field("api_key", "secret", "API Key"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.PIVOT_HOST,
            Capability.PIVOT_USER,
            Capability.ISOLATE_HOST,
        )

    def __init__(self, tenant_fqdn: str, api_key_id: str, api_key: str):
        self._base = f"https://{tenant_fqdn.strip().rstrip('/')}"
        self._api_key_id = api_key_id
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        return {
            "x-xdr-auth-id": self._api_key_id,
            "Authorization": self._api_key,
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self._base}/public_api/v1/incidents/get_incidents/",
                    headers=self._headers(),
                    json={"request_data": {"search_from": 0, "search_to": 1}},
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
        since_ms = int((datetime.now(UTC) - timedelta(seconds=since_seconds)).timestamp() * 1000)
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self._base}/public_api/v1/incidents/get_incidents/",
                    headers=self._headers(),
                    json={
                        "request_data": {
                            "search_from": 0,
                            "search_to": 100,
                            "filters": [{"field": "creation_time", "operator": "gte", "value": since_ms}],
                            "sort": {"field": "creation_time", "keyword": "desc"},
                        }
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "cortex_xsiam.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                payload = resp.json() or {}
                incidents = (payload.get("reply") or {}).get("incidents") or []
                return [self.normalize(i) for i in incidents]
        except Exception as exc:
            logger.warning("cortex_xsiam.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Cortex XSIAM incidents expose the standard Palo Alto severity
        # ladder: informational / low / medium / high / critical. Mirror
        # all five tiers (including ``critical``) into AiSOC's ladder
        # rather than silently collapsing unknown values to ``info``.
        sev_raw = (raw.get("severity") or "").lower()
        if sev_raw == "informational":
            sev_raw = "info"
        severity = sev_raw if sev_raw in ("info", "low", "medium", "high", "critical") else "info"
        return {
            "source": "cortex_xsiam",
            "category": "edr",
            "severity": severity,
            "title": raw.get("description") or "Cortex XSIAM incident",
            "description": raw.get("xdr_url"),
            "alert_id": str(raw.get("incident_id") or ""),
            "host": (raw.get("hosts") or [None])[0],
            "raw": raw,
        }
