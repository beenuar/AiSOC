"""
Microsoft Sentinel connector.
Fetches security incidents from Microsoft Sentinel via Azure REST API.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, ConnectorSchema, Field
from app.federated.query import UnifiedQuery
from app.federated.translators import to_kql

logger = structlog.get_logger()

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_SENTINEL_API = "https://management.azure.com/subscriptions/{sub_id}/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/incidents"
_LOGS_API = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"


class MicrosoftSentinelConnector(BaseConnector):
    connector_id = "microsoft_sentinel"
    connector_name = "Microsoft Sentinel"
    connector_category = "siem"
    supports_federated_search = True

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Microsoft Sentinel incidents via the Azure Security Insights REST API.",
            docs_url="/docs/connectors/microsoft-sentinel",
            fields=[
                Field("tenant_id", "string", "Tenant ID"),
                Field("client_id", "string", "Client ID"),
                Field("client_secret", "secret", "Client Secret"),
                Field("subscription_id", "string", "Subscription ID"),
                Field("resource_group", "string", "Resource Group"),
                Field("workspace", "string", "Workspace Name"),
            ],
        )

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

        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
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

    async def query(self, unified: UnifiedQuery) -> list[dict[str, Any]]:
        """Run a translated KQL query against Log Analytics.

        Sentinel KQL runs against the workspace's Log Analytics endpoint,
        which uses a different API base than the Security Insights REST
        endpoint used by ``fetch_alerts``. The federated layer scopes auth
        to ``api.loganalytics.io`` separately from the management API.
        """
        if not self._access_token:
            await self._authenticate()

        kql = to_kql(unified, table="CommonSecurityLog")
        async with httpx.AsyncClient(timeout=60.0) as client:
            url = _LOGS_API.format(workspace_id=self._workspace)
            headers = {
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json",
            }
            resp = await client.post(url, headers=headers, json={"query": kql})
            resp.raise_for_status()
            data = resp.json()

        # Log Analytics returns { "tables": [ { "columns": [...], "rows": [[...]] } ] }
        # Flatten the first table into a list of column-keyed dicts so the API
        # layer doesn't need to know the wire shape.
        tables = data.get("tables") or []
        if not tables:
            return []
        primary = tables[0]
        columns = [c.get("name") for c in primary.get("columns", [])]
        rows = primary.get("rows", [])
        return [dict(zip(columns, row, strict=False)) for row in rows]

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
