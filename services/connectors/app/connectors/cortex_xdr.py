"""
Cortex XDR (Palo Alto Networks) connector.
Fetches incidents from the Cortex XDR REST API.
"""

from __future__ import annotations

import hashlib
import secrets
import string
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# Cortex XDR natively ships a ``critical`` tier on incidents. AiSOC's
# 5-tier ladder preserves it end-to-end so P1 EDR detections keep their
# original priority.
_SEVERITY_MAP: dict[str, str] = {
    "informational": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class CortexXDRConnector(BaseConnector):
    connector_id = "cortex_xdr"
    connector_name = "Cortex XDR"
    connector_category = "edr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Palo Alto Cortex XDR incidents via the public REST API.",
            docs_url="/docs/connectors/cortex-xdr",
            fields=[
                Field("api_key_id", "secret", "API Key ID"),
                Field("api_key", "secret", "API Key"),
                Field(
                    "fqdn",
                    "string",
                    "FQDN",
                    placeholder="api-example.xdr.us.paloaltonetworks.com",
                    help_text="Fully qualified domain name of your Cortex XDR tenant.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Today the runtime only implements ``fetch_alerts`` (incidents).
        # ``ISOLATE_HOST`` / ``KILL_PROCESS`` belong here once we wire the
        # Cortex XDR Endpoints API.
        return (Capability.PULL_ALERTS,)

    def __init__(self, api_key_id: str, api_key: str, fqdn: str):
        self._api_key_id = api_key_id
        self._api_key = api_key
        self._fqdn = fqdn.rstrip("/")

    def _headers(self) -> dict[str, str]:
        nonce = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
        timestamp = str(int(datetime.now(UTC).timestamp()) * 1000)
        auth_string = f"{self._api_key}{nonce}{timestamp}"
        api_key_hash = hashlib.sha256(auth_string.encode()).hexdigest()

        return {
            "x-xdr-auth-id": str(self._api_key_id),
            "x-xdr-nonce": nonce,
            "x-xdr-timestamp": timestamp,
            "Authorization": api_key_hash,
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"https://{self._fqdn}/public_api/v1/incidents/get_incidents",
                    headers=self._headers(),
                    json={"request_data": {"filters": [], "search_from": 0, "search_to": 1}},
                )
                resp.raise_for_status()
                return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("cortex_xdr.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since_ms = int((datetime.now(UTC) - timedelta(seconds=since_seconds)).timestamp()) * 1000

        payload = {
            "request_data": {
                "filters": [
                    {
                        "field": "creation_time",
                        "operator": "gte",
                        "value": since_ms,
                    }
                ],
                "search_from": 0,
                "search_to": 100,
                "sort": {"field": "creation_time", "keyword": "desc"},
            }
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"https://{self._fqdn}/public_api/v1/incidents/get_incidents",
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            incidents = resp.json().get("reply", {}).get("incidents", [])

        return [self.normalize(i) for i in incidents]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        raw_severity = str(raw.get("severity", "medium")).lower()
        severity = _SEVERITY_MAP.get(raw_severity, "medium")

        hosts = raw.get("hosts", [])
        hostname = hosts[0] if hosts else None

        return {
            "source": self.connector_id,
            "external_id": str(raw.get("incident_id", "")),
            "title": raw.get("description", "Cortex XDR Incident"),
            "description": raw.get("description", ""),
            "severity": severity,
            "hostname": hostname,
            "mitre_techniques": raw.get("mitre_tactics_ids_and_names") or [],
            "raw_event": raw,
            "created_at": raw.get("creation_time"),
        }
