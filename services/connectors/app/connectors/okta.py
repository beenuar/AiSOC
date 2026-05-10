"""
Okta connector.
Fetches system log events (suspicious activity, failed logins, MFA push spam).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()


class OktaConnector(BaseConnector):
    connector_id = "okta"
    connector_name = "Okta Identity"
    connector_category = "iam"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Okta system log events (auth, MFA, account locks, blocked requests).",
            docs_url="/docs/connectors/okta",
            fields=[
                Field(
                    "domain",
                    "string",
                    "Okta Domain",
                    placeholder="https://yourorg.okta.com",
                ),
                Field("api_token", "secret", "API Token"),
            ],
            # Hosted OAuth (Workstream 2): Okta supports OIDC + OAuth 2.0
            # for service apps. The {domain} placeholder is rewritten in
            # /api/v1/oauth/start using the per-instance ``domain`` field
            # (or the OAuth app credential's authorize_url override for
            # custom auth servers).
            oauth=OAuthHints(
                supported_in_hosted=True,
                authorize_url="{domain}/oauth2/v1/authorize",
                token_url="{domain}/oauth2/v1/token",
                scopes=[
                    "okta.logs.read",
                    "okta.users.read",
                    "okta.groups.read",
                    "offline_access",
                ],
            ),
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Okta System Log streams identity audit events (logins, MFA, admin actions).
        # WS-E3: Live Okta Management API response actions now wired
        # via services/actions/app/clients/okta_client.py
        return (
            Capability.PULL_AUDIT,
            Capability.DISABLE_USER,
            Capability.RESET_PASSWORD,
            Capability.SUSPEND_SESSION,
            Capability.FORCE_MFA,
            Capability.REVOKE_SESSION,
        )

    def __init__(self, domain: str, api_token: str):
        self._domain = domain.rstrip("/")
        self._api_token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"SSWS {self._api_token}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(
                    f"{self._domain}/api/v1/org",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()
                return {"success": True, "connector": self.connector_id, "org": data.get("name")}
            except Exception as exc:
                return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # Focus on security-relevant event types
        security_events = [
            "user.authentication.auth_via_mfa",
            "user.session.start",
            "policy.evaluate_sign_on",
            "user.account.lock",
            "security.request.blocked",
        ]

        events: list[dict] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            for event_type in security_events:
                resp = await client.get(
                    f"{self._domain}/api/v1/logs",
                    headers=self._headers(),
                    params={
                        "since": since,
                        "eventType": event_type,
                        "limit": 50,
                    },
                )
                if resp.status_code == 200:
                    events.extend(resp.json())

        return [self.normalize(e) for e in events]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        outcome = raw.get("outcome", {})
        result = outcome.get("result", "SUCCESS")
        severity = "info"
        if result in ("FAILURE", "DENY"):
            severity = "medium"
        if raw.get("eventType") in ("user.account.lock", "security.request.blocked"):
            severity = "high"

        actor = raw.get("actor", {})
        client_info = raw.get("client", {})

        return {
            "source": self.connector_id,
            "external_id": raw.get("uuid", ""),
            "title": raw.get("displayMessage", "Okta Event"),
            "description": f"{raw.get('eventType')} - {outcome.get('reason', result)}",
            "severity": severity,
            "src_ip": client_info.get("ipAddress"),
            "actor": actor.get("displayName"),
            "actor_email": actor.get("alternateId"),
            "event_type": raw.get("eventType"),
            "raw_event": raw,
            "created_at": raw.get("published"),
        }
