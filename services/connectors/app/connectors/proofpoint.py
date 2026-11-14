"""
Proofpoint TAP connector.
Fetches blocked messages from the Proofpoint Targeted Attack Protection SIEM API.
"""

from __future__ import annotations

from base64 import b64encode
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_TAP_BASE = "https://tap-api-v2.proofpoint.com"

_VERDICT_SEVERITY = {
    "phish": "high",
    "malware": "high",
    "spam": "medium",
    "impostor": "high",
    "adult": "low",
    "bulk": "info",
}


class ProofpointConnector(BaseConnector):
    connector_id = "proofpoint"
    connector_name = "Proofpoint TAP"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Proofpoint Targeted Attack Protection — blocked messages via the SIEM API.",
            docs_url="/docs/connectors/proofpoint",
            fields=[
                Field("service_principal", "string", "Service Principal"),
                Field("service_secret", "secret", "Service Secret"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Proofpoint TAP — blocked messages surfaced as alerts to the agent layer.
        return (Capability.PULL_ALERTS,)

    def __init__(self, service_principal: str, service_secret: str):
        self._principal = service_principal
        self._secret = service_secret

    def _auth_header(self) -> dict[str, str]:
        creds = b64encode(f"{self._principal}:{self._secret}".encode()).decode()
        return {
            "Authorization": f"Basic {creds}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            since = (datetime.now(UTC) - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{_TAP_BASE}/v2/siem/messages/blocked",
                    headers=self._auth_header(),
                    params={"sinceTime": since, "format": "json"},
                )
                resp.raise_for_status()
            return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("proofpoint.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{_TAP_BASE}/v2/siem/messages/blocked",
                headers=self._auth_header(),
                params={"sinceTime": since, "format": "json"},
            )
            resp.raise_for_status()
            data = resp.json()

        messages = data.get("messagesBlocked", [])
        return [self.normalize(m) for m in messages]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        threats = raw.get("threatsInfoMap", [])
        classification = threats[0].get("classification", "unknown") if threats else "unknown"

        return {
            "source": self.connector_id,
            "external_id": raw.get("GUID", ""),
            "title": f"Proofpoint blocked: {raw.get('subject', 'no subject')}",
            "description": (
                f"Blocked message from {raw.get('sender', 'unknown')} "
                f"to {', '.join(raw.get('recipients', []))} — "
                f"classification: {classification}"
            ),
            "severity": _VERDICT_SEVERITY.get(classification, "medium"),
            "src_ip": raw.get("senderIP"),
            "hostname": None,
            "actor": raw.get("sender"),
            "raw_event": raw,
            "created_at": raw.get("messageTime"),
        }
