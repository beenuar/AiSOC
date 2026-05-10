"""
Slack Audit Logs connector (Enterprise Grid).

Uses the Slack Audit Logs API at audit.slack.com/api. Auth is via an
OrgLevel OAuth Bot token with `auditlogs:read` scope. The token is
issued from a Slack Enterprise Grid app.

We support OAuth provisioning via the Slack OAuth flow.
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


class SlackAuditConnector(BaseConnector):
    """Slack Enterprise Grid Audit Logs."""

    connector_id = "slack_audit"
    connector_name = "Slack Audit Logs"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Slack Enterprise Grid Audit Logs. Pulls workspace and org-level "
                "audit events (logins, channel changes, file shares, app installs). "
                "Requires the auditlogs:read scope on an Org-level Slack app."
            ),
            docs_url="/docs/connectors/slack-audit",
            fields=[
                Field(
                    "access_token",
                    "secret",
                    "Org-level access token",
                    help_text=("OrgLevel OAuth bot token with the auditlogs:read scope, issued from a Slack Enterprise Grid app."),
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="https://slack.com/oauth/v2/authorize",
                token_url="https://slack.com/api/oauth.v2.access",
                scopes=["auditlogs:read"],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_AUDIT,
            Capability.PIVOT_USER,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(self, access_token: str):
        self._token = access_token
        self._base = "https://api.slack.com/audit/v1"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/actions",
                    headers=self._headers(),
                )
                if resp.status_code == 200:
                    return {"success": True, "connector": self.connector_id}
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        oldest = int((datetime.now(UTC) - timedelta(seconds=since_seconds)).timestamp())
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/logs",
                    headers=self._headers(),
                    params={"oldest": oldest, "limit": 200},
                )
                if resp.status_code != 200:
                    logger.warning(
                        "slack_audit.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = (resp.json() or {}).get("entries") or []
                return [self.normalize(i) for i in items]
        except Exception as exc:
            logger.warning("slack_audit.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = raw.get("action") or "audit_event"
        actor = ((raw.get("actor") or {}).get("user") or {}).get("name")
        return {
            "source": "slack_audit",
            "category": "saas",
            "severity": "info",
            "title": f"Slack: {action}",
            "description": f"actor={actor}" if actor else None,
            "alert_id": raw.get("id"),
            "host": None,
            "raw": raw,
        }
