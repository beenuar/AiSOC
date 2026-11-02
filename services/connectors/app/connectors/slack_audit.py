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

    #: Actions that are a compromise or a control being removed, not routine
    #: workspace traffic. Slack's audit-log action reference is the source;
    #: `scripts/vendor_event_vocabulary.py` transcribes the whole list and a
    #: gate refuses a rule naming an action that is not in it.
    _HIGH_RISK_ACTIONS = frozenset(
        {
            "organization_export_started",
            "organization_public_url_updated",
            "pref.allow_message_deletion",
            "pref.sso_setting_changed",
            "pref.two_factor_auth_changed",
            "role_change_to_admin",
            "role_change_to_owner",
            "user_session_invalidation_disabled",
            "workspace_public_url_updated",
        }
    )
    _MEDIUM_RISK_ACTIONS = frozenset(
        {
            "app_installed",
            "app_scopes_expanded",
            "app_token_rotated",
            "channel_converted_to_private",
            "external_shared_channel_connected",
            "file_downloaded",
            "guest_created",
            "user_channel_join",
        }
    )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Flatten Slack's three-level audit entry into the engine's namespace.

        The engine flattens `raw_event` exactly one level, and every
        discriminating value in a Slack audit entry sits two or three levels
        down: the signing-in user is `actor.user.email`, the address is
        `context.ip_address`, the app's scopes are `entity.app.scopes`. This
        method read `actor.user.name` for a description string and discarded
        the rest, so a rule clausing on any of them compared `None` and could
        never fire — the same shape as the Okta `outcome.result` defect.

        Lifted names follow the ones the rest of the corpus already uses
        (`src_ip`, `actor_email`, `user_agent`) so a cross-source rule does
        not need a Slack-specific spelling.
        """
        action = raw.get("action") or "audit_event"
        actor_block = (raw.get("actor") or {}).get("user") or {}
        context = raw.get("context") or {}
        entity = raw.get("entity") or {}
        entity_type = entity.get("type")
        # Slack keys the described object by its own type: a channel entity
        # carries `entity.channel`, an app entity `entity.app`. Reading the
        # keyed block rather than guessing keeps one path for all of them.
        entity_block = entity.get(entity_type) if isinstance(entity_type, str) else None
        entity_block = entity_block if isinstance(entity_block, dict) else {}
        app_block = entity_block if entity_type == "app" else {}
        channel_block = entity_block if entity_type == "channel" else {}

        severity = "info"
        if action in self._HIGH_RISK_ACTIONS:
            severity = "high"
        elif action in self._MEDIUM_RISK_ACTIONS:
            severity = "medium"

        created = raw.get("date_create")
        created_iso: str | None = None
        if isinstance(created, int | float):
            created_iso = datetime.fromtimestamp(created, tz=UTC).isoformat()
        elif isinstance(created, str):
            created_iso = created

        return {
            "source": "slack_audit",
            "category": "saas",
            "severity": severity,
            "title": f"Slack: {action}",
            "description": f"actor={actor_block.get('name')}; action={action}; entity={entity_type}",
            "alert_id": raw.get("id"),
            "external_id": raw.get("id"),
            "host": None,
            "event_type": f"slack.{action}",
            "action": action,
            "actor": actor_block.get("name"),
            "actor_email": actor_block.get("email"),
            "actor_id": actor_block.get("id"),
            "src_ip": context.get("ip_address"),
            "user_agent": context.get("ua"),
            "entity_type": entity_type,
            "entity_id": entity_block.get("id"),
            "entity_name": entity_block.get("name"),
            "app_scopes": app_block.get("scopes"),
            "app_is_distributed": app_block.get("is_distributed"),
            "channel_privacy": channel_block.get("privacy"),
            "channel_is_shared": channel_block.get("is_shared"),
            "channel_is_org_shared": channel_block.get("is_org_shared"),
            "raw_event": raw,
            "created_at": created_iso,
        }
