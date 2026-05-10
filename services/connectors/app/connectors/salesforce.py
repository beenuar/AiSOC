"""
Salesforce Event Monitoring connector.

Salesforce surfaces audit and event-monitoring data through the
EventLogFile and SetupAuditTrail SObjects. Auth is OAuth 2.0 (web
flow) into a connected app, but for a self-hosted schema we expose
the username/password + security token + client_id/client_secret pair
that drives the JWT/Refresh-Token flow used in headless ingestion.

We also advertise OAuth so click-and-connect can flow through Salesforce's
hosted login.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import (
    BaseConnector,
    Capability,
    ConnectorSchema,
    Field,
    OAuthHints,
)

logger = structlog.get_logger()


class SalesforceConnector(BaseConnector):
    """Salesforce Event Monitoring + Setup Audit Trail."""

    connector_id = "salesforce"
    connector_name = "Salesforce"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Salesforce Event Monitoring + Setup Audit Trail. Pulls "
                "EventLogFile entries (logins, API usage, report exports) and "
                "SetupAuditTrail (admin config changes)."
            ),
            docs_url="/docs/connectors/salesforce",
            fields=[
                Field(
                    "instance_url",
                    "string",
                    "My Domain URL",
                    placeholder="https://yourcorp.my.salesforce.com",
                ),
                Field("client_id", "string", "Connected App Consumer Key"),
                Field("client_secret", "secret", "Connected App Consumer Secret"),
                Field(
                    "refresh_token",
                    "secret",
                    "Refresh Token",
                    required=False,
                    help_text="Provided automatically when you connect via OAuth.",
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://login.salesforce.com/services/oauth2/authorize",
                token_url="https://login.salesforce.com/services/oauth2/token",
                scopes=["api", "refresh_token", "offline_access"],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_AUDIT,
            Capability.QUERY_LOGS,
            Capability.PIVOT_USER,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(
        self,
        instance_url: str,
        client_id: str,
        client_secret: str,
        refresh_token: str | None = None,
    ):
        self._instance = instance_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._refresh_token = refresh_token

    async def _bearer(self) -> str | None:
        if not self._refresh_token:
            return None
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self._instance}/services/oauth2/token",
                    data={
                        "grant_type": "refresh_token",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "refresh_token": self._refresh_token,
                    },
                )
                if resp.status_code == 200:
                    return (resp.json() or {}).get("access_token")
                logger.warning(
                    "salesforce.refresh_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return None
        except Exception as exc:
            logger.warning("salesforce.refresh_exception", error=str(exc))
            return None

    async def test_connection(self) -> dict[str, Any]:
        if not self._refresh_token:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "no refresh_token; complete the OAuth flow first",
            }
        token = await self._bearer()
        if not token:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "could not refresh access token",
            }
        return {"success": True, "connector": self.connector_id}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        token = await self._bearer()
        if not token:
            return []
        since_iso = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        soql = (
            "SELECT Id, Action, Section, CreatedDate, CreatedBy.Name, Display "
            f"FROM SetupAuditTrail WHERE CreatedDate >= {since_iso} "
            "ORDER BY CreatedDate DESC LIMIT 200"
        )
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._instance}/services/data/v60.0/query",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                    params={"q": soql},
                )
                if resp.status_code != 200:
                    logger.warning(
                        "salesforce.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = (resp.json() or {}).get("records") or []
                return [self.normalize(i) for i in items]
        except Exception as exc:
            logger.warning("salesforce.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": "salesforce",
            "category": "saas",
            "severity": "info",
            "title": f"Salesforce: {raw.get('Action') or 'setup audit event'}",
            "description": raw.get("Display"),
            "alert_id": raw.get("Id"),
            "host": None,
            "raw": raw,
        }
