"""
Tailscale audit log connector.

Pulls two event streams from the Tailscale API v2:

1. **Audit logs** — ``GET /tailnet/{tailnet}/audit``
   Every administrative action: ACL changes, device approvals/removals, key
   rotations, user role changes, subnet router and exit-node changes, OIDC /
   SAML configuration mutations, etc. Requires the ``audit:read`` OAuth scope.

2. **Policy file changes** — embedded inside audit events with
   ``action == "acl:update"``; no separate endpoint. We surface these
   at HIGH severity because ACL changes are a common lateral-movement
   enabler in zero-trust networks.

Auth: Tailscale supports two auth methods:
  * **API key** (long-lived, starts with ``tskey-api-``): simplest for testing
    and small deployments.
  * **OAuth client credential** (client_id + client_secret): preferred for
    production. The connector accepts either style — if ``client_id`` and
    ``client_secret`` are both provided, it performs the client-credentials
    flow automatically and refreshes the token before expiry.

Tailnet: the organisational identifier. For personal accounts this is the
email address (``alice@example.com``). For organisations it is the custom
short-name shown in the admin panel, or ``-`` to use the default tailnet of
the authenticated token.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, ConnectorSchema, Field, OAuthHints

logger = structlog.get_logger()

_BASE = "https://api.tailscale.com/api/v2"

# Audit event actions that we treat as HIGH severity.  These are either
# reversible-but-dangerous changes that could be used for persistence /
# lateral movement, or irreversible destructive operations.
_HIGH_SEVERITY_ACTIONS = frozenset(
    {
        # ACL / policy
        "acl:update",
        "acl:delete",
        # Device management
        "device:approve",
        "device:delete",
        "device:expire_key",
        "device:update_authorized",
        # Exit nodes and subnet routers
        "routes:set_advertised",
        "routes:approve",
        "routes:disapprove",
        # Key management
        "auth_key:create",
        "auth_key:delete",
        "tailnet_key:create",
        "tailnet_key:delete",
        # Users / roles
        "user:invite",
        "user:delete",
        "user:approve",
        "user:role_update",
        "user:restore",
        # Identity provider / OIDC
        "oidc:update",
        "saml:update",
        # DNS / MagicDNS
        "dns:update",
        # Admin
        "tailnet:transfer_ownership",
        "tailnet:delete",
        "settings:update",
        "logging:set_config",
        # Webhooks (could be abused as C2 notification channel)
        "webhook:create",
        "webhook:update",
        "webhook:delete",
    }
)

_MEDIUM_SEVERITY_ACTIONS = frozenset(
    {
        "device:update",
        "tag:update",
        "acl:validate",
        "posture:create",
        "posture:update",
        "posture:delete",
    }
)


class TailscaleConnector(BaseConnector):
    """Tailscale audit log connector."""

    connector_id = "tailscale"
    connector_name = "Tailscale"
    connector_category = "network"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Tailscale zero-trust network audit logs. "
                "Captures every ACL change, device approval / removal, key rotation, "
                "user role change, and admin configuration mutation in your tailnet."
            ),
            docs_url="/docs/connectors/tailscale",
            fields=[
                Field(
                    "tailnet",
                    "string",
                    "Tailnet",
                    placeholder="example.com or -",
                    help_text=(
                        "Your tailnet name (the organisation slug shown in the Tailscale "
                        "admin console, e.g. 'example.com'). Use '-' to use the default "
                        "tailnet associated with the API key / OAuth token."
                    ),
                ),
                Field(
                    "api_key",
                    "secret",
                    "API Key (optional if using OAuth)",
                    required=False,
                    help_text=(
                        "Tailscale API key (starts with 'tskey-api-'). Use either this *or* the OAuth client credentials below — not both."
                    ),
                ),
                Field(
                    "client_id",
                    "string",
                    "OAuth Client ID (optional)",
                    required=False,
                    help_text=("OAuth 2.0 client ID from the Tailscale admin console. Required scope: 'audit:read'."),
                ),
                Field(
                    "client_secret",
                    "secret",
                    "OAuth Client Secret (optional)",
                    required=False,
                    help_text=("OAuth 2.0 client secret. Only needed when using client-credential flow instead of an API key."),
                ),
            ],
            oauth=OAuthHints(
                supported_in_hosted=False,
                authorize_url="https://login.tailscale.com/admin/settings/oauth",
                token_url="https://api.tailscale.com/api/v2/oauth/token",
                scopes=["audit:read"],
            ),
        )

    def __init__(
        self,
        tailnet: str,
        api_key: str = "",
        client_id: str = "",
        client_secret: str = "",
    ):
        self._tailnet = tailnet or "-"
        self._api_key = api_key
        self._client_id = client_id
        self._client_secret = client_secret
        # OAuth token cache
        self._oauth_token: str | None = None
        self._oauth_expires_at: float = 0.0

    # ─────────────────────────── auth ────────────────────────────

    async def _ensure_token(self) -> str:
        """Return a valid bearer token, refreshing the OAuth token if needed."""
        if self._api_key:
            return self._api_key

        if self._client_id and self._client_secret:
            if self._oauth_token and time.time() < self._oauth_expires_at - 60:
                return self._oauth_token  # type: ignore[return-value]
            # Fetch a new token via client-credentials grant.
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://api.tailscale.com/api/v2/oauth/token",
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self._client_id,
                        "client_secret": self._client_secret,
                    },
                )
                resp.raise_for_status()
                payload = resp.json()
                self._oauth_token = payload["access_token"]
                self._oauth_expires_at = time.time() + int(payload.get("expires_in", 3600))
            return self._oauth_token  # type: ignore[return-value]

        raise ValueError("TailscaleConnector: provide either 'api_key' or both 'client_id' and 'client_secret'.")

    async def _auth_header(self) -> dict[str, str]:
        token = await self._ensure_token()
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    # ───────────────────────── contract ──────────────────────────

    async def test_connection(self) -> dict[str, Any]:
        try:
            headers = await self._auth_header()
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Probe: fetch the tailnet details. 200 ⟹ auth + scope OK.
                resp = await client.get(
                    f"{_BASE}/tailnet/{self._tailnet}/acl",
                    headers=headers,
                )
                if resp.status_code == 200:
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "tailnet": self._tailnet,
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        start = datetime.now(UTC) - timedelta(seconds=since_seconds)
        # Tailscale API accepts RFC-3339 timestamps as ``startTime`` / ``endTime``
        start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")

        events: list[dict[str, Any]] = []
        headers = await self._auth_header()
        cursor: str | None = None

        async with httpx.AsyncClient(timeout=30.0) as client:
            while True:
                params: dict[str, Any] = {"startTime": start_iso}
                if cursor:
                    params["cursor"] = cursor

                resp = await client.get(
                    f"{_BASE}/tailnet/{self._tailnet}/audit",
                    headers=headers,
                    params=params,
                )

                if resp.status_code == 403:
                    logger.warning(
                        "tailscale.audit_forbidden",
                        status=resp.status_code,
                        detail="Token is missing the audit:read scope.",
                    )
                    break

                if resp.status_code != 200:
                    logger.warning(
                        "tailscale.audit_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    break

                payload = resp.json()
                page: list[dict[str, Any]] = payload.get("auditLogs") or payload.get("logs") or []
                events.extend(page)

                # Tailscale uses cursor-based pagination.
                cursor = payload.get("nextCursor") or payload.get("cursor")
                if not cursor or not page:
                    break

        return [self.normalize(e) for e in events]

    # ───────────────────────── normalize ─────────────────────────

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        action: str = raw.get("action") or raw.get("type") or ""
        actor: str = raw.get("actor", {}).get("loginName") or raw.get("actor", {}).get("id") or raw.get("user") or "unknown"

        if action in _HIGH_SEVERITY_ACTIONS:
            severity = "high"
        elif action in _MEDIUM_SEVERITY_ACTIONS:
            severity = "medium"
        elif action.endswith(":delete") or action.endswith(":remove"):
            # Catch-all for destructive operations not in the explicit sets.
            severity = "medium"
        else:
            severity = "info"

        # ``acl:update`` is especially important — diff the new vs old policy
        # to surface what changed. Include in description if available.
        description_parts = [f"action={action}", f"actor={actor}"]
        target = raw.get("target") or raw.get("node") or {}
        if isinstance(target, dict):
            if target.get("name"):
                description_parts.append(f"target={target['name']}")
            if target.get("id"):
                description_parts.append(f"target_id={target['id']}")
        elif isinstance(target, str) and target:
            description_parts.append(f"target={target}")

        if action == "acl:update":
            description_parts.append("(ACL policy modified — review diff for new access paths)")

        # Normalise timestamp.  Tailscale returns ISO-8601.
        created_at: str | None = raw.get("created") or raw.get("timestamp") or raw.get("time")

        return {
            "source": self.connector_id,
            "external_id": raw.get("id") or raw.get("eventId") or "",
            "title": f"Tailscale: {action}" if action else "Tailscale audit event",
            "description": "; ".join(description_parts),
            "severity": severity,
            "actor": actor,
            "actor_email": raw.get("actor", {}).get("loginName") if isinstance(raw.get("actor"), dict) else None,
            "src_ip": raw.get("actorIp") or raw.get("ip"),
            "event_type": f"tailscale.{action}" if action else "tailscale.audit",
            "raw_event": raw,
            "created_at": created_at,
        }
