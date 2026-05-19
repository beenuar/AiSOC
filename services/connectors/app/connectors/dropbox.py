"""
Dropbox Business audit-log connector.

Dropbox exposes ``POST /2/team_log/get_events`` for team admins, which
returns the team event log: file shares, downloads, member additions
and removals, group changes, OAuth app authorisations, sign-in events,
sharing-policy changes. Auth is a long-lived team admin OAuth token.

Pagination: cursor via ``/2/team_log/get_events/continue``.

Severity collapse:
  * ``team_member_create_team_invite_link``,
    ``shared_content_change_link_audience`` (to public),
    ``account_external_password_unmask`` → high
  * ``app_link_team`` / ``app_unlink_team`` → high
  * member role changes → high
  * sign-in failures → medium; sign-in success from new device → low
  * file/folder sharing events → medium
  * everything else → info
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_BASE = "https://api.dropboxapi.com"
_PER_PAGE = 1000
_MAX_PAGES = 20


class DropboxConnector(BaseConnector):
    """Dropbox Business team event log."""

    connector_id = "dropbox"
    connector_name = "Dropbox Business"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Dropbox Business team event log: sharing, sign-in, " "member role changes, OAuth-app authorisations, " "policy edits."
            ),
            docs_url="/docs/connectors/dropbox",
            fields=[
                Field(
                    "team_admin_token",
                    "secret",
                    "Team admin token",
                    help_text=(
                        "OAuth 2.0 token for a Dropbox Business app "
                        "with the ``team_data.governance.read`` and "
                        "``events.read`` scopes."
                    ),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_AUDIT,
            Capability.PIVOT_USER,
            Capability.READ_AUDIT_TRAIL,
        )

    def __init__(self, team_admin_token: str):
        self._token = team_admin_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    f"{_BASE}/2/team/get_info",
                    headers=self._headers(),
                    content="null",
                )
                if resp.status_code == 200:
                    info = resp.json() or {}
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "team": info.get("name"),
                        "members": info.get("num_provisioned_users"),
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        from datetime import UTC, datetime, timedelta

        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_PAGES):
                if cursor:
                    body: dict[str, Any] = {"cursor": cursor}
                    url = f"{_BASE}/2/team_log/get_events/continue"
                else:
                    body = {
                        "limit": _PER_PAGE,
                        "time": {"start_time": since},
                    }
                    url = f"{_BASE}/2/team_log/get_events"
                resp = await client.post(url, headers=self._headers(), json=body)
                if resp.status_code != 200:
                    logger.warning(
                        "dropbox.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break
                payload = resp.json() or {}
                events = payload.get("events") or []
                for ev in events:
                    out.append(self.normalize(ev))
                if not payload.get("has_more"):
                    break
                cursor = payload.get("cursor")
                if not cursor:
                    break
        return out

    _HIGH_RISK_EVENT_PREFIXES = (
        "account_external_password_unmask",
        "team_member_create_team_invite_link",
        "shared_content_change_link_audience_to_public",
        "shared_content_remove_member",
        "app_link_team",
        "member_change_admin_role",
        "team_folder_change_status",
        "sso_change_policy",
    )
    _MEDIUM_RISK_EVENT_PREFIXES = (
        "shared_",
        "shared_content_",
        "shared_link_",
        "shmodel_",
        "login_fail",
        "login_success_with_two_factor",
        "device_link",
        "group_create",
        "group_delete",
        "member_change_status",
        "member_change_email",
    )

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        event_type = (raw.get("event_type") or {}).get(".tag") or raw.get("event_type", "")
        if isinstance(event_type, dict):
            event_type = event_type.get(".tag", "")
        category = (
            (raw.get("event_category") or {}).get(".tag") if isinstance(raw.get("event_category"), dict) else raw.get("event_category", "")
        )  # noqa: E501
        actor = raw.get("actor") or {}
        # actor is a tagged-union; flatten
        actor_user = (actor.get("user") or {}) if isinstance(actor, dict) else {}
        actor_email = actor_user.get("email")
        severity = "info"
        if any(event_type.startswith(p) for p in self._MEDIUM_RISK_EVENT_PREFIXES):
            severity = "medium"
        if any(event_type.startswith(p) for p in self._HIGH_RISK_EVENT_PREFIXES):
            severity = "high"
        # logins: failures bump to medium, success from new device → low
        if event_type == "login_fail":
            severity = "medium"
        if event_type == "login_success" and "device" in (raw.get("event_type") or {}).get(".tag", ""):
            severity = "low" if severity == "info" else severity
        return {
            "source": self.connector_id,
            "external_id": raw.get("event_id") or "",
            "title": event_type or "Dropbox event",
            "description": (f"event={event_type}; category={category}; " f"actor={actor_email}"),
            "severity": severity,
            "actor": actor_email or actor_user.get("display_name"),
            "actor_email": actor_email,
            "src_ip": (raw.get("origin") or {}).get("geo_location", {}).get("ip_address"),
            "event_type": f"dropbox.{event_type}" if event_type else "dropbox.event",
            "raw_event": raw,
            "created_at": raw.get("timestamp"),
        }
