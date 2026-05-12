"""GitHub Audit Log connector for AiSOC.

Pulls org audit log events, secret-scanning alerts, and user activity from
the GitHub REST API for use in identity / supply-chain investigations.

Required config (passed in via context["config"]):
  - org: GitHub organization slug
  - token: PAT or fine-grained token with read:audit_log scope
  - base_url: optional GHES base URL (defaults to https://api.github.com)

Payload shape:
  {
    "action": "fetch_audit" | "list_secret_alerts" | "get_user_events"
              | "list_members",
    "since": "YYYY-MM-DDTHH:MM:SSZ",   # optional cursor for fetch_audit
    "username": "octocat",              # required for get_user_events
    "phrase": "action:org.invite"       # optional GitHub audit log search phrase
  }
"""
from __future__ import annotations

from typing import Any

try:
    import httpx

    _HTTPX = True
except ImportError:
    _HTTPX = False


class Plugin:
    """GitHub Audit Log connector plugin."""

    def _client(self, context: dict[str, Any]) -> httpx.AsyncClient:
        config = context.get("config") or {}
        if "org" not in config or "token" not in config:
            raise ValueError("org and token are required in plugin config")
        base_url = (config.get("base_url") or "https://api.github.com").rstrip("/")
        headers = {
            "Authorization": f"Bearer {config['token']}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        return httpx.AsyncClient(base_url=base_url, headers=headers, timeout=30)

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _HTTPX:
            return {"error": "httpx not installed; run `pip install httpx`"}

        action = payload.get("action", "fetch_audit")
        config = context.get("config") or {}
        org = config.get("org", "")

        async with self._client(context) as client:
            if action == "fetch_audit":
                params: dict[str, Any] = {"per_page": 100}
                if phrase := payload.get("phrase"):
                    params["phrase"] = phrase
                if since := payload.get("since"):
                    params["after"] = since
                resp = await client.get(f"/orgs/{org}/audit-log", params=params)
                resp.raise_for_status()
                return {"action": action, "events": resp.json()}
            if action == "list_secret_alerts":
                resp = await client.get(
                    f"/orgs/{org}/secret-scanning/alerts", params={"per_page": 100}
                )
                resp.raise_for_status()
                return {"action": action, "alerts": resp.json()}
            if action == "get_user_events":
                username = payload.get("username", "")
                resp = await client.get(
                    f"/users/{username}/events/orgs/{org}", params={"per_page": 100}
                )
                resp.raise_for_status()
                return {"action": action, "username": username, "events": resp.json()}
            if action == "list_members":
                resp = await client.get(f"/orgs/{org}/members", params={"per_page": 100})
                resp.raise_for_status()
                return {"action": action, "members": resp.json()}
            return {"error": f"Unknown action: {action}"}
