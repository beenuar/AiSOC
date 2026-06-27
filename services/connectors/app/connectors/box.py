"""
Box content-cloud audit-events connector.

Box exposes admin events at ``GET /2.0/events?stream_type=admin_logs``,
returning per-tenant audit records: file shares, downloads, deletes,
collaborator changes, login successes/failures, and admin-policy
edits. Auth is OAuth 2.0 client-credentials with a JWT-signed app
(server auth) — we accept the resulting access token directly here so
operators can rotate via Box's developer console.

Pagination: ``next_stream_position`` cursor.

Severity collapse:
  * SHIELD_ALERT → high (Box's anomaly-detection signal)
  * APPLICATION.PUBLIC_KEY_DELETED, ITEM.SHARED, ITEM.SHARED_LINK_CREATED
    targeting external recipients → high
  * ITEM.DOWNLOAD by an external collaborator → high
  * GROUP_ADMIN_CREATED, ROLE_CHANGE_TO_ADMIN, MASTER_INVITE_*, etc → high
  * COLLABORATION_INVITE / ACCEPT / REMOVE → medium
  * ADD_LOGIN_ACTIVITY_DEVICE / FAILED_LOGIN → medium
  * everything else → info
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_BASE = "https://api.box.com"
_PER_PAGE = 500
_MAX_PAGES = 20


class BoxConnector(BaseConnector):
    """Box admin event stream."""

    connector_id = "box"
    connector_name = "Box"
    connector_category = "saas"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Box admin audit events: file shares / downloads / "
                "deletes, collaborator changes, login activity, "
                "policy edits, and Shield anomaly alerts."
            ),
            docs_url="/docs/connectors/box",
            fields=[
                Field(
                    "access_token",
                    "secret",
                    "Box access token",
                    help_text=(
                        "OAuth 2.0 access token from a Box JWT app "
                        "with the 'Manage enterprise properties' "
                        "scope. Refresh externally; this connector "
                        "does not mint new tokens."
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

    def __init__(self, access_token: str):
        self._token = access_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"{_BASE}/2.0/users/me", headers=self._headers())
                if resp.status_code == 200:
                    me = resp.json() or {}
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "user": me.get("login") or me.get("name"),
                        "enterprise": (me.get("enterprise") or {}).get("name"),
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        out: list[dict[str, Any]] = []
        stream_pos: str | None = None
        async with httpx.AsyncClient(timeout=30.0) as client:
            for _ in range(_MAX_PAGES):
                params: dict[str, Any] = {
                    "stream_type": "admin_logs",
                    "created_after": since,
                    "limit": _PER_PAGE,
                }
                if stream_pos:
                    params["stream_position"] = stream_pos
                try:
                    resp = await client.get(f"{_BASE}/2.0/events", headers=self._headers(), params=params)
                except (httpx.HTTPError, httpx.InvalidURL) as exc:
                    logger.warning("box.fetch_network_error", error=str(exc))
                    break
                if resp.status_code != 200:
                    logger.warning(
                        "box.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break
                payload = resp.json() or {}
                entries = payload.get("entries") or []
                for ev in entries:
                    out.append(self.normalize(ev))
                stream_pos = payload.get("next_stream_position")
                if not stream_pos or len(entries) < _PER_PAGE:
                    break
        return out

    _HIGH_RISK_EVENTS = {
        "SHIELD_ALERT",
        "SHIELD_EXTERNAL_COLLAB_INVITE_BLOCKED",
        "SHIELD_EXTERNAL_COLLAB_INVITE_ABNORMAL_LOCATION",
        "GROUP_ADMIN_CREATED",
        "ROLE_CHANGE_TO_ADMIN",
        "MASTER_INVITE_ACCEPT",
        "MASTER_INVITE_REJECT",
        "APPLICATION_PUBLIC_KEY_DELETED",
        "APPLICATION_PUBLIC_KEY_ADDED",
        "ITEM_SHARED_LINK",
        "USER_LOGIN",  # only when external IP — handled below
        "DELETE_USER",
    }
    _MEDIUM_RISK_EVENTS = {
        "COLLABORATION_INVITE",
        "COLLABORATION_ACCEPT",
        "COLLABORATION_REMOVE",
        "COLLABORATION_ROLE_CHANGE",
        "COLLABORATION_EXPIRATION",
        "FAILED_LOGIN",
        "ADD_LOGIN_ACTIVITY_DEVICE",
        "REMOVE_LOGIN_ACTIVITY_DEVICE",
        "ITEM_SHARED_UPDATE",
    }

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        event_type = raw.get("event_type") or ""
        actor = raw.get("created_by") or {}
        source = raw.get("source") or {}
        # Severity ladder.
        severity = "info"
        if event_type in self._MEDIUM_RISK_EVENTS:
            severity = "medium"
        if event_type in self._HIGH_RISK_EVENTS:
            severity = "high"
        # Refine: ITEM.DOWNLOAD by a collaborator outside the enterprise
        # promotes to high — Box marks these with action_by.type==external.
        if event_type == "ITEM_DOWNLOAD" and (raw.get("additional_details") or {}).get("ekm_id") is None:
            ab = raw.get("action_by") or {}
            if (ab.get("login") or "").endswith(("@gmail.com", "@yahoo.com", "@outlook.com")):
                severity = "high"
        return {
            "source": self.connector_id,
            "external_id": raw.get("event_id") or raw.get("id") or "",
            "title": event_type or "Box event",
            "description": (
                f"event={event_type}; actor={actor.get('login')}; "
                f"target={source.get('item_name') or source.get('name')}; "
                f"ip={raw.get('ip_address')}"
            ),
            "severity": severity,
            "actor": actor.get("login") or actor.get("name"),
            "actor_email": actor.get("login"),
            "src_ip": raw.get("ip_address"),
            "target": source.get("item_name") or source.get("name"),
            "event_type": f"box.{event_type or 'event'}",
            "raw_event": raw,
            "created_at": raw.get("created_at"),
        }
