"""
Wiz connector.
Fetches cloud security issues from the Wiz GraphQL API.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# Wiz issues ship a native ``CRITICAL`` tier. AiSOC's 5-tier ladder
# preserves it end-to-end so P1 cloud findings keep their original priority.
_SEVERITY_MAP: dict[str, str] = {
    "INFORMATIONAL": "info",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}

_ISSUES_QUERY = """
query IssuesTable($filterBy: IssueFilters, $first: Int) {
  issues(filterBy: $filterBy, first: $first) {
    nodes {
      id
      severity
      status
      title
      description
      createdAt
      entitySnapshot {
        id
        name
        type
        cloudPlatform
        region
        subscriptionExternalId
      }
      sourceRule {
        id
        name
      }
    }
  }
}
"""


class WizConnector(BaseConnector):
    connector_id = "wiz"
    connector_name = "Wiz"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Wiz cloud security issues via the GraphQL API.",
            docs_url="/docs/connectors/wiz",
            fields=[
                Field("client_id", "string", "Client ID"),
                Field("client_secret", "secret", "Client Secret"),
                Field(
                    "api_endpoint_url",
                    "string",
                    "API Endpoint URL",
                    placeholder="https://api.us20.app.wiz.io/graphql",
                    help_text="Your tenant's GraphQL API endpoint.",
                ),
                Field(
                    "auth_url",
                    "string",
                    "Auth URL",
                    required=False,
                    default="https://auth.app.wiz.io/oauth/token",
                    help_text="OAuth2 token endpoint. Override only for gov-cloud tenants.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Wiz issues are surfaced to the agent layer as alerts (CSPM findings).
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        api_endpoint_url: str,
        auth_url: str = "https://auth.app.wiz.io/oauth/token",
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._api_url = api_endpoint_url.rstrip("/")
        self._auth_url = auth_url
        self._access_token: str | None = None

    async def _authenticate(self) -> str:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self._auth_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "audience": "wiz-api",
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
            logger.warning("wiz.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._access_token:
            await self._authenticate()

        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        headers = {"Authorization": f"Bearer {self._access_token}"}

        payload = {
            "query": _ISSUES_QUERY,
            "variables": {
                "filterBy": {
                    "status": ["OPEN", "IN_PROGRESS"],
                    "createdAt": {"after": since},
                },
                "first": 100,
            },
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(self._api_url, headers=headers, json=payload)

            if resp.status_code == 401:
                await self._authenticate()
                headers = {"Authorization": f"Bearer {self._access_token}"}
                resp = await client.post(self._api_url, headers=headers, json=payload)

            resp.raise_for_status()
            issues = resp.json().get("data", {}).get("issues", {}).get("nodes", [])

        return [self.normalize(i) for i in issues]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        raw_severity = str(raw.get("severity", "MEDIUM")).upper()
        severity = _SEVERITY_MAP.get(raw_severity, "medium")

        entity = raw.get("entitySnapshot") or {}
        rule = raw.get("sourceRule") or {}

        return {
            "source": self.connector_id,
            "external_id": raw.get("id", ""),
            "title": raw.get("title", "Wiz Issue"),
            "description": raw.get("description", ""),
            "severity": severity,
            "hostname": entity.get("name"),
            "cloud_resource": entity.get("id"),
            "cloud_platform": entity.get("cloudPlatform"),
            "cloud_region": entity.get("region"),
            "rule_name": rule.get("name"),
            "raw_event": raw,
            "created_at": raw.get("createdAt"),
        }
