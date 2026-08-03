"""JumpCloud connector.

Pulls Directory Insights events (auth + admin activity) from the JumpCloud API
as an alert stream. Auth is a simple API key header (x-api-key).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class JumpCloudConnector(BaseConnector):
    connector_id = "jumpcloud"
    connector_name = "JumpCloud"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="JumpCloud Directory Insights — authentication and admin events as alerts.",
            docs_url="/docs/connectors/jumpcloud",
            fields=[Field("api_key", "secret", "API Key")],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PIVOT_USER)

    def __init__(self, api_key: str):
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        return {"x-api-key": self._api_key, "Content-Type": "application/json", "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get("https://console.jumpcloud.com/api/systemusers", headers=self._headers(), params={"limit": 1})
                return {"success": resp.status_code < 400, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("jumpcloud.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        start = (datetime.now(UTC) - timedelta(seconds=max(1, since_seconds))).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = {"service": ["all"], "start_time": start, "limit": 200, "sort": "DESC"}
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post("https://api.jumpcloud.com/insights/directory/v1/events", headers=self._headers(), json=body)
                resp.raise_for_status()
                events = resp.json()
        except Exception as exc:
            logger.warning("jumpcloud.fetch_failed", error=str(exc))
            return []
        if not isinstance(events, list):
            events = events.get("results", []) if isinstance(events, dict) else []
        return [self.normalize(e) for e in events if isinstance(e, dict)]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw, dict) and "raw_event" in raw and raw.get("source") == self.connector_id:
            return raw
        success = raw.get("success")
        event_type = str(raw.get("event_type", ""))
        # Failed auth / admin changes are the security-relevant ones.
        severity = "high" if success is False else ("medium" if "admin" in event_type else "low")
        return {
            "source": self.connector_id,
            "external_id": str(raw.get("id") or raw.get("_id") or ""),
            "title": event_type or "JumpCloud event",
            "description": raw.get("message") or "",
            "severity": severity,
            "src_ip": raw.get("client_ip"),
            "actor": (raw.get("initiated_by") or {}).get("username") if isinstance(raw.get("initiated_by"), dict) else None,
            "raw_event": raw,
            "created_at": raw.get("timestamp"),
        }
