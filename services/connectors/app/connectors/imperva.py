"""Imperva Cloud WAF connector.

Pulls security events (WAF incidents) from the Imperva Cloud Application
Security (Incapsula) API as an alert stream. Auth is an API ID + API key pair
passed as query parameters per the Imperva API convention.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_SEVERITY_BY_THREAT = {
    "SQL Injection": "high",
    "Cross Site Scripting": "high",
    "Remote File Inclusion": "high",
    "Illegal Resource Access": "medium",
    "Backdoor": "critical",
    "DDoS": "high",
}


class ImpervaConnector(BaseConnector):
    connector_id = "imperva"
    connector_name = "Imperva Cloud WAF"
    connector_category = "network"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Imperva Cloud WAF (Incapsula) security events / blocked attacks as alerts.",
            docs_url="/docs/connectors/imperva",
            fields=[
                Field("api_id", "string", "API ID"),
                Field("api_key", "secret", "API Key"),
                Field("site_id", "string", "Site ID", required=False, help_text="Optional. Limit to one protected site."),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PIVOT_IP, Capability.BLOCK_IP)

    def __init__(self, api_id: str, api_key: str, site_id: str | None = None):
        self._api_id = api_id
        self._api_key = api_key
        self._site_id = site_id or None
        self._base = "https://my.imperva.com/api/v1"

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(f"{self._base}/sites/list", data={"api_id": self._api_id, "api_key": self._api_key})
                ok = resp.status_code < 400 and resp.json().get("res") == 0
                return {"success": bool(ok), "connector": self.connector_id}
        except Exception as exc:
            logger.warning("imperva.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        data: dict[str, Any] = {"api_id": self._api_id, "api_key": self._api_key, "page_size": 200}
        if self._site_id:
            data["site_id"] = self._site_id
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(f"{self._base}/infra/stats", data=data)
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:
            logger.warning("imperva.fetch_failed", error=str(exc))
            return []
        events = payload.get("visits") or payload.get("events") or []
        return [self.normalize(e) for e in events if isinstance(e, dict)]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw, dict) and "raw_event" in raw and raw.get("source") == self.connector_id:
            return raw
        threat = (
            raw.get("threats", [{}])[0].get("attackType")
            if isinstance(raw.get("threats"), list) and raw["threats"]
            else raw.get("securitySummary")
        )
        severity = _SEVERITY_BY_THREAT.get(str(threat), "medium")
        return {
            "source": self.connector_id,
            "external_id": str(raw.get("id") or raw.get("clientIPAddress") or ""),
            "title": f"Imperva WAF: {threat or 'security event'}",
            "description": raw.get("securitySummary") or "",
            "severity": severity,
            "src_ip": raw.get("clientIPAddress"),
            "raw_event": raw,
            "created_at": raw.get("startTime"),
        }
