"""
Microsoft Sentinel connector.
Fetches security incidents from Microsoft Sentinel via Azure REST API.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector

logger = structlog.get_logger()

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_SENTINEL_API = "https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/incidents"


class MicrosoftSentinelConnector(BaseConnector):
    connector_id = "microsoft_sentinel"
    connector_name = "Microsoft Sentinel"

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
        resource_group: str,
        workspace: str,
    ):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._subscription_id = subscription_id
        self._resource_group = resource_group
        self._workspace = workspace
        self._access_token: str | None = None

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                _TOKEN_URL.format(tenant_id=self._tenant_id),
                data={
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://management.azure.com/.default",
                    "grant_type": "client_credentials",
                },
            )
            resp.raise_for_status()
            self._access_token = resp.json()["access_token"]
            return self._access_token

    async def test_connection(self) -> dict[str, Any]:
        try:
            await self._authenticate()
            return {"success": True, "connector": self.connector_id, "workspace": self._workspace}
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._access_token:
            await self._authenticate()

        since = (datetime.now(timezone.utc) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        api_url = _SENTINEL_API.format(
            sub_id=self._subscription_id,
            rg=self._resource_group,
            workspace=self._workspace,
        )

        headers = {"Authorization": f"Bearer {self._access_token}"}
        params = {
            "api-version": "2022-12-01-preview",
            "$filter": f"properties/lastModifiedTimeUtc ge {since}",
            "$top": 100,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(api_url, headers=headers, params=params)
            if resp.status_code == 401:
                await self._authenticate()
                headers = {"Authorization": f"Bearer {self._access_token}"}
                resp = await client.get(api_url, headers=headers, params=params)
            resp.raise_for_status()
            incidents = resp.json().get("value", [])

        return [self.normalize(i) for i in incidents]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        props = raw.get("properties", {})
        severity_map = {"Informational": "info", "Low": "low", "Medium": "medium", "High": "high"}
        return {
            "source": self.connector_id,
            "external_id": raw.get("name", ""),
            "title": props.get("title", "Sentinel Incident"),
            "description": props.get("description", ""),
            "severity": severity_map.get(props.get("severity", "Medium"), "medium"),
            "status": props.get("status"),
            "tactics": props.get("additionalData", {}).get("tactics", []),
            "alert_count": props.get("additionalData", {}).get("alertsCount", 0),
            "raw_event": props,
            "created_at": props.get("createdTimeUtc"),
        }
