"""
Mimecast email security connector.

Mimecast's classic API uses signed requests with App Key + Access Key +
Secret Key. The newer 2.0 API uses Bearer tokens via OAuth client
credentials. We expose the 2.0 client_id / client_secret pair, which
keeps schema simple and matches the path Mimecast steers customers
toward post-2024.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class MimecastConnector(BaseConnector):
    """Mimecast (Email Security 2.0 API)."""

    connector_id = "mimecast"
    connector_name = "Mimecast"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=("Mimecast Email Security 2.0 API. Pulls held messages, SIEM events, and URL protect verdicts as alerts."),
            docs_url="/docs/connectors/mimecast",
            fields=[
                Field(
                    "region",
                    "select",
                    "Region",
                    options=[
                        {"value": "us", "label": "United States"},
                        {"value": "eu", "label": "Europe"},
                        {"value": "de", "label": "Germany"},
                        {"value": "au", "label": "Australia"},
                        {"value": "za", "label": "South Africa"},
                        {"value": "uk", "label": "United Kingdom"},
                    ],
                ),
                Field("client_id", "string", "Client ID"),
                Field("client_secret", "secret", "Client Secret"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PULL_AUDIT,
            Capability.PIVOT_USER,
            Capability.ENRICH_DOMAIN,
        )

    def __init__(self, region: str, client_id: str, client_secret: str):
        # Mimecast 2.0 uses a single api.services.mimecast.com endpoint;
        # region is informational for now (used for support/UI).
        self._region = region
        self._client_id = client_id
        self._client_secret = client_secret
        self._base = "https://api.services.mimecast.com"

    async def _bearer(self) -> str | None:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self._base}/oauth/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                if resp.status_code == 200:
                    return (resp.json() or {}).get("access_token")
                logger.warning(
                    "mimecast.token_failed",
                    status=resp.status_code,
                    body=resp.text[:300],
                )
                return None
        except Exception as exc:
            logger.warning("mimecast.token_exception", error=str(exc))
            return None

    async def test_connection(self) -> dict[str, Any]:
        token = await self._bearer()
        if not token:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "could not exchange client credentials for bearer",
            }
        return {
            "success": True,
            "connector": self.connector_id,
            "region": self._region,
        }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        token = await self._bearer()
        if not token:
            return []
        end = datetime.now(UTC)
        start = end - timedelta(seconds=since_seconds)
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/api/ttp/url/get-logs",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                    },
                    params={
                        "from": start.strftime("%Y-%m-%dT%H:%M:%S+0000"),
                        "to": end.strftime("%Y-%m-%dT%H:%M:%S+0000"),
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "mimecast.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = (resp.json() or {}).get("data") or []
                return [self.normalize(i) for i in items]
        except Exception as exc:
            logger.warning("mimecast.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = (raw.get("action") or "").lower()
        sev = "high" if action in ("blocked", "block") else "medium"
        return {
            "source": "mimecast",
            "category": "saas",
            "severity": sev,
            "title": raw.get("category") or "Mimecast URL verdict",
            "description": raw.get("url"),
            "alert_id": raw.get("id"),
            "host": None,
            "raw": raw,
        }
