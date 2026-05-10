"""
Auth0 Logs connector.

Auth0 exposes tenant logs at /api/v2/logs. Auth is via a Management
API token issued from a Machine-to-Machine application authorized
against the Management API. The connector takes domain + client
credentials and exchanges them at runtime.
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


class Auth0Connector(BaseConnector):
    """Auth0 tenant logs."""

    connector_id = "auth0"
    connector_name = "Auth0"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=("Auth0 tenant logs. Pulls login events, MFA events, and admin actions via the Management API."),
            docs_url="/docs/connectors/auth0",
            fields=[
                Field(
                    "domain",
                    "string",
                    "Auth0 Domain",
                    placeholder="yourcorp.us.auth0.com",
                ),
                Field("client_id", "string", "M2M Client ID"),
                Field("client_secret", "secret", "M2M Client Secret"),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://AUTH0_DOMAIN/authorize",
                token_url="https://AUTH0_DOMAIN/oauth/token",
                scopes=["read:logs", "read:logs_users"],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_AUDIT,
            Capability.PIVOT_USER,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(self, domain: str, client_id: str, client_secret: str):
        self._domain = domain
        self._client_id = client_id
        self._client_secret = client_secret
        self._base = f"https://{domain}"

    async def _bearer(self) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self._base}/oauth/token",
                    json={
                        "grant_type": "client_credentials",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                        "audience": f"{self._base}/api/v2/",
                    },
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    return (resp.json() or {}).get("access_token")
                logger.warning(
                    "auth0.token_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return None
        except Exception as exc:
            logger.warning("auth0.token_exception", error=str(exc))
            return None

    async def test_connection(self) -> dict[str, Any]:
        token = await self._bearer()
        if not token:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "could not exchange client credentials for management token",
            }
        return {"success": True, "connector": self.connector_id}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        token = await self._bearer()
        if not token:
            return []
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/api/v2/logs",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                    params={
                        "q": f"date:[{since} TO *]",
                        "per_page": 100,
                        "sort": "date:-1",
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "auth0.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = resp.json() or []
                return [self.normalize(i) for i in items]
        except Exception as exc:
            logger.warning("auth0.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        type_code = (raw.get("type") or "").lower()
        # Auth0 type codes: 'f' = failed login, 's' = success, 'fu' = failed user, etc.
        sev = "high" if type_code.startswith("f") else "info"
        return {
            "source": "auth0",
            "category": "iam",
            "severity": sev,
            "title": f"Auth0 event: {raw.get('description') or type_code}",
            "description": raw.get("user_name") or raw.get("ip"),
            "alert_id": raw.get("_id") or raw.get("log_id"),
            "host": None,
            "raw": raw,
        }
