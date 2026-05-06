"""
Okta Connector — AiSOC Reference Plugin
========================================
Connects to the Okta Management API to perform identity-related actions
during incident response and enrichment workflows.

Supported actions (set `action` in payload):
  - get_user            : Fetch user profile by email or Okta user ID.
  - list_sessions       : List active sessions for a user.
  - suspend_user        : Suspend (lock) a user account.
  - unsuspend_user      : Unsuspend (unlock) a user account.
  - clear_user_sessions : Force-logout all active sessions.
  - clear_mfa_factors   : Delete all enrolled MFA factors.

Configuration keys (env or plugin config):
  OKTA_DOMAIN   — e.g. acme.okta.com
  OKTA_API_TOKEN — SSWS token

Usage:
  payload = {
      "action": "suspend_user",
      "user_id": "jdoe@example.com",
  }
  context = {
      "config": {
          "okta_domain": "acme.okta.com",
          "api_token": "<SSWS token>",
      }
  }
"""
from __future__ import annotations

import os
from typing import Any

try:
    import httpx
    _HTTPX = True
except ModuleNotFoundError:
    _HTTPX = False


class Plugin:
    """Okta Connector plugin."""

    # ── Lifecycle ────────────────────────────────────────────────────────────

    def _client(self, context: dict) -> "httpx.AsyncClient":
        cfg = context.get("config", {})
        domain = cfg.get("okta_domain") or os.getenv("OKTA_DOMAIN", "")
        token = cfg.get("api_token") or os.getenv("OKTA_API_TOKEN", "")
        if not domain or not token:
            raise ValueError("okta_domain and api_token are required")
        base_url = f"https://{domain}/api/v1"
        headers = {
            "Authorization": f"SSWS {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        return httpx.AsyncClient(base_url=base_url, headers=headers, timeout=30)

    # ── Dispatch ─────────────────────────────────────────────────────────────

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _HTTPX:
            return {"error": "httpx not installed; run `pip install httpx`"}

        action = payload.get("action", "get_user")
        user_id = payload.get("user_id", "")

        async with self._client(context) as client:
            match action:
                case "get_user":
                    result = await self._get_user(client, user_id)
                case "list_sessions":
                    result = await self._list_sessions(client, user_id)
                case "suspend_user":
                    result = await self._suspend_user(client, user_id)
                case "unsuspend_user":
                    result = await self._unsuspend_user(client, user_id)
                case "clear_user_sessions":
                    result = await self._clear_sessions(client, user_id)
                case "clear_mfa_factors":
                    result = await self._clear_mfa(client, user_id)
                case _:
                    result = {"error": f"Unknown action: {action}"}
        return result

    # ── Actions ───────────────────────────────────────────────────────────────

    async def _get_user(self, client: "httpx.AsyncClient", user_id: str) -> dict:
        r = await client.get(f"/users/{user_id}")
        r.raise_for_status()
        user = r.json()
        return {
            "user_id": user.get("id"),
            "login": user.get("profile", {}).get("login"),
            "email": user.get("profile", {}).get("email"),
            "status": user.get("status"),
            "last_login": user.get("lastLogin"),
            "raw": user,
        }

    async def _list_sessions(self, client: "httpx.AsyncClient", user_id: str) -> dict:
        r = await client.get(f"/users/{user_id}/sessions")
        r.raise_for_status()
        sessions = r.json()
        return {"session_count": len(sessions), "sessions": sessions}

    async def _suspend_user(self, client: "httpx.AsyncClient", user_id: str) -> dict:
        r = await client.post(f"/users/{user_id}/lifecycle/suspend")
        r.raise_for_status()
        return {"action": "suspend_user", "user_id": user_id, "status": "suspended"}

    async def _unsuspend_user(self, client: "httpx.AsyncClient", user_id: str) -> dict:
        r = await client.post(f"/users/{user_id}/lifecycle/unsuspend")
        r.raise_for_status()
        return {"action": "unsuspend_user", "user_id": user_id, "status": "active"}

    async def _clear_sessions(self, client: "httpx.AsyncClient", user_id: str) -> dict:
        r = await client.delete(f"/users/{user_id}/sessions")
        r.raise_for_status()
        return {"action": "clear_user_sessions", "user_id": user_id, "sessions_cleared": True}

    async def _clear_mfa(self, client: "httpx.AsyncClient", user_id: str) -> dict:
        # Enumerate enrolled factors and delete each
        r = await client.get(f"/users/{user_id}/factors")
        r.raise_for_status()
        factors = r.json()
        deleted = []
        for factor in factors:
            fid = factor.get("id")
            dr = await client.delete(f"/users/{user_id}/factors/{fid}")
            if dr.status_code in (200, 204):
                deleted.append(fid)
        return {"action": "clear_mfa_factors", "user_id": user_id, "factors_deleted": deleted}
