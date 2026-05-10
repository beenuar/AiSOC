"""
1Password Events connector.
Fetches sign-in attempt events from the 1Password Events Reporting API.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class OnePasswordConnector(BaseConnector):
    connector_id = "onepassword"
    connector_name = "1Password Events"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="1Password sign-in attempts via the Events Reporting API.",
            docs_url="/docs/connectors/onepassword",
            fields=[
                Field("api_token", "secret", "API Token (Bearer)"),
                Field(
                    "base_url",
                    "string",
                    "Events API Base URL",
                    required=False,
                    default="https://events.1password.com",
                    help_text="Override only for 1Password Business accounts on a non-default region.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # 1Password Events API streams sign-ins / item usage / audit events.
        return (Capability.PULL_AUDIT,)

    def __init__(
        self,
        api_token: str,
        base_url: str = "https://events.1password.com",
    ):
        self._api_token = api_token
        self._base_url = base_url.rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            since = (datetime.now(UTC) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{self._base_url}/api/v1/signinattempts",
                    headers=self._headers(),
                    json={"limit": 1, "start_time": since},
                )
                resp.raise_for_status()
            return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("onepassword.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

        events: list[dict[str, Any]] = []
        cursor: str | None = None

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                body: dict[str, Any] = {"limit": 100, "start_time": since}
                if cursor:
                    body["cursor"] = cursor

                resp = await client.post(
                    f"{self._base_url}/api/v1/signinattempts",
                    headers=self._headers(),
                    json=body,
                )
                resp.raise_for_status()
                data = resp.json()
                items = data.get("items", [])
                events.extend(items)

                cursor = data.get("cursor")
                if not data.get("has_more") or not cursor:
                    break

        return [self.normalize(e) for e in events]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        category = raw.get("category", "success")
        severity = "info"
        if category == "credentials_failed":
            severity = "medium"
        elif category in ("mfa_failed", "modern_version_failed"):
            severity = "high"
        elif category == "firewall_failed":
            severity = "high"

        client_info = raw.get("client", {}) or {}

        return {
            "source": self.connector_id,
            "external_id": raw.get("uuid", ""),
            "title": f"1Password sign-in: {category}",
            "description": (
                f"Sign-in attempt ({category}) by "
                f"{raw.get('target_user', {}).get('email', 'unknown')} "
                f"from {client_info.get('ip_address', 'unknown')}"
            ),
            "severity": severity,
            "src_ip": client_info.get("ip_address"),
            "hostname": None,
            "actor": raw.get("target_user", {}).get("email"),
            "raw_event": raw,
            "created_at": raw.get("timestamp"),
        }
