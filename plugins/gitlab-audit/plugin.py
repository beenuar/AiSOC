"""GitLab audit connector plugin for AiSOC."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx


class Plugin:
    """GitLab audit events connector."""

    def _base(self, context: dict[str, Any]) -> str:
        config = context.get("config") or {}
        return (config.get("base_url") or "https://gitlab.com").rstrip("/")

    def _headers(self, context: dict[str, Any]) -> dict[str, str]:
        config = context.get("config") or {}
        if not config.get("token"):
            raise ValueError("token is required")
        return {
            "PRIVATE-TOKEN": config["token"],
            "Accept": "application/json",
        }

    def _path(self, context: dict[str, Any]) -> str:
        config = context.get("config") or {}
        scope = config.get("scope") or "instance"
        scope_id = config.get("scope_id")
        if scope == "group":
            if not scope_id:
                raise ValueError("scope_id required for group scope")
            return f"/api/v4/groups/{scope_id}/audit_events"
        if scope == "project":
            if not scope_id:
                raise ValueError("scope_id required for project scope")
            return f"/api/v4/projects/{scope_id}/audit_events"
        return "/api/v4/audit_events"

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        try:
            headers = self._headers(context)
            path = self._path(context)
        except ValueError as exc:
            return {"error": str(exc)}

        base = self._base(context)
        action = payload.get("action", "fetch_events")
        since = payload.get("since") or (
            datetime.now(UTC) - timedelta(minutes=15)
        ).isoformat()

        try:
            async with httpx.AsyncClient(
                timeout=30.0, base_url=base, headers=headers
            ) as client:
                if action == "test_connection":
                    resp = await client.get(path, params={"per_page": 1})
                    resp.raise_for_status()
                    return {"connected": True, "status": resp.status_code}

                if action == "fetch_events":
                    params = {
                        "created_after": since,
                        "per_page": payload.get("limit", 100),
                    }
                    resp = await client.get(path, params=params)
                    resp.raise_for_status()
                    events = resp.json()
                    for event in events:
                        event["_aisoc_source"] = "gitlab-audit"
                    return {
                        "action": action,
                        "since": since,
                        "scope": (context.get("config") or {}).get("scope") or "instance",
                        "events": events,
                    }

                return {"error": f"Unknown action: {action}"}
        except httpx.HTTPStatusError as exc:
            return {
                "error": f"gitlab error: {exc.response.status_code}",
                "body": exc.response.text[:512],
            }
        except httpx.HTTPError as exc:
            return {"error": f"gitlab request failed: {exc}"}
