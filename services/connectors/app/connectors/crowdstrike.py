"""
CrowdStrike Falcon connector.
Fetches detections from the CrowdStrike Falcon API.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, ConnectorSchema, Field

logger = structlog.get_logger()


class CrowdStrikeConnector(BaseConnector):
    connector_id = "crowdstrike"
    connector_name = "CrowdStrike Falcon"
    connector_category = "edr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="CrowdStrike Falcon detections via the Falcon REST API.",
            docs_url="/docs/connectors/crowdstrike",
            fields=[
                Field("client_id", "string", "Client ID"),
                Field("client_secret", "secret", "Client Secret"),
                Field(
                    "base_url",
                    "string",
                    "Base URL",
                    required=False,
                    default="https://api.crowdstrike.com",
                    help_text="Override only if your tenant lives in a non-US cloud (e.g. api.eu-1.crowdstrike.com).",
                ),
            ],
        )

    def __init__(self, client_id: str, client_secret: str, base_url: str = "https://api.crowdstrike.com"):
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url
        self._access_token: str | None = None

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base_url}/oauth2/token",
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                },
            )
            resp.raise_for_status()
            self._access_token = resp.json()["access_token"]
            return self._access_token

    async def test_connection(self) -> dict[str, Any]:
        try:
            token = await self._authenticate()
            return {"success": True, "connector": self.connector_id, "authenticated": bool(token)}
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._access_token:
            await self._authenticate()

        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).isoformat()
        headers = {"Authorization": f"Bearer {self._access_token}"}

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Query detection IDs
            resp = await client.get(
                f"{self._base_url}/detects/queries/detects/v1",
                headers=headers,
                params={"filter": f"created_timestamp:>'{since}'", "limit": 100},
            )
            if resp.status_code == 401:
                await self._authenticate()
                headers = {"Authorization": f"Bearer {self._access_token}"}
                resp = await client.get(
                    f"{self._base_url}/detects/queries/detects/v1",
                    headers=headers,
                    params={"filter": f"created_timestamp:>'{since}'", "limit": 100},
                )
            resp.raise_for_status()
            detection_ids = resp.json().get("resources", [])

            if not detection_ids:
                return []

            # Fetch detection details
            details_resp = await client.post(
                f"{self._base_url}/detects/entities/summaries/GET/v1",
                headers=headers,
                json={"ids": detection_ids[:100]},
            )
            details_resp.raise_for_status()
            detections = details_resp.json().get("resources", [])

        return [self.normalize(d) for d in detections]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        severity_map = {1: "low", 2: "medium", 3: "high", 4: "critical"}
        severity = severity_map.get(raw.get("max_severity", 2), "medium")

        behaviors = raw.get("behaviors") or [{}]
        title = behaviors[0].get("display_name", "CrowdStrike Detection")

        return {
            "source": self.connector_id,
            "external_id": raw.get("detection_id", ""),
            "title": title,
            "description": f"CrowdStrike detection on {raw.get('device', {}).get('hostname', 'unknown')}",
            "severity": severity,
            "src_ip": raw.get("device", {}).get("external_ip"),
            "hostname": raw.get("device", {}).get("hostname"),
            "mitre_techniques": [b.get("technique_id", "") for b in raw.get("behaviors", []) if b.get("technique_id")],
            "raw_event": raw,
            "created_at": raw.get("created_timestamp"),
        }
