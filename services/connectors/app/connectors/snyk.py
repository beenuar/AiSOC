"""
Snyk connector.
Fetches vulnerability issues from the Snyk REST API.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# Snyk issues ship a native ``critical`` tier. AiSOC's 5-tier ladder
# preserves it end-to-end so P1 supply-chain findings keep their original
# priority.
_SEVERITY_MAP: dict[str, str] = {
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


class SnykConnector(BaseConnector):
    connector_id = "snyk"
    connector_name = "Snyk"
    connector_category = "vcs"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Snyk vulnerability issues via the REST API.",
            docs_url="/docs/connectors/snyk",
            fields=[
                Field("api_token", "secret", "API Token"),
                Field(
                    "org_id",
                    "string",
                    "Organization ID",
                    help_text="Snyk organization UUID (Settings → General → Organization ID).",
                ),
                Field(
                    "base_url",
                    "string",
                    "Base URL",
                    required=False,
                    default="https://api.snyk.io",
                    help_text="Override for Snyk Enterprise on-prem or EU tenants.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Snyk surfaces vulnerability issues across SCM/SCA/IaC scans as alerts.
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        api_token: str,
        org_id: str,
        base_url: str = "https://api.snyk.io",
    ):
        self._api_token = api_token
        self._org_id = org_id
        self._base_url = base_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"token {self._api_token}",
            "Content-Type": "application/vnd.api+json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base_url}/rest/orgs/{self._org_id}",
                    headers=self._headers(),
                    params={"version": "2024-10-15"},
                )
                resp.raise_for_status()
                return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("snyk.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

        params: dict[str, Any] = {
            "version": "2024-10-15",
            "limit": 100,
            "created_after": since,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self._base_url}/rest/orgs/{self._org_id}/issues",
                headers=self._headers(),
                params=params,
            )
            resp.raise_for_status()
            issues = resp.json().get("data", [])

        return [self.normalize(i) for i in issues]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        attrs = raw.get("attributes", {})
        raw_severity = str(attrs.get("effective_severity_level", "medium")).lower()
        severity = _SEVERITY_MAP.get(raw_severity, "medium")

        coordinates = attrs.get("coordinates") or [{}]
        first_coord = coordinates[0] if coordinates else {}

        return {
            "source": self.connector_id,
            "external_id": raw.get("id", ""),
            "title": attrs.get("title", "Snyk Issue"),
            "description": attrs.get("description", ""),
            "severity": severity,
            "hostname": first_coord.get("representations", [{}])[0].get("dependency", {}).get("package_name")
            if first_coord.get("representations")
            else None,
            "cve": attrs.get("problems", [{}])[0].get("id") if attrs.get("problems") else None,
            "raw_event": raw,
            "created_at": attrs.get("created_at"),
        }
