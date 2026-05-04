"""PagerDuty paging action plugin for AiSOC."""
from __future__ import annotations

from typing import Any

import httpx

EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"
API_BASE = "https://api.pagerduty.com"


class Plugin:
    """PagerDuty paging plugin (Events API v2 + REST API)."""

    async def _post(self, url: str, headers: dict[str, str], body: dict) -> dict:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, headers=headers, json=body)
            resp.raise_for_status()
            return resp.json()

    async def _get(self, url: str, headers: dict[str, str]) -> dict:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        config = context.get("config") or {}
        routing_key = config.get("routing_key")
        if not routing_key:
            return {"error": "routing_key is required"}

        action = payload.get("action", "trigger_incident")
        dedup_key = payload.get("dedup_key")

        try:
            if action == "trigger_incident":
                summary = payload.get("summary") or "AiSOC alert"
                severity = (
                    payload.get("severity")
                    or config.get("default_severity")
                    or "error"
                )
                event = {
                    "routing_key": routing_key,
                    "event_action": "trigger",
                    "dedup_key": dedup_key,
                    "payload": {
                        "summary": summary,
                        "severity": severity,
                        "source": payload.get("source") or "aisoc",
                        "component": payload.get("component"),
                        "group": payload.get("group"),
                        "class": payload.get("class"),
                        "custom_details": payload.get("custom_details") or {},
                    },
                }
                result = await self._post(EVENTS_URL, {}, event)
                return {"action": action, "ok": True, "result": result}

            if action in ("acknowledge_incident", "resolve_incident"):
                if not dedup_key:
                    return {"error": "dedup_key required for ack/resolve"}
                event_action = (
                    "acknowledge"
                    if action == "acknowledge_incident"
                    else "resolve"
                )
                result = await self._post(
                    EVENTS_URL,
                    {},
                    {
                        "routing_key": routing_key,
                        "event_action": event_action,
                        "dedup_key": dedup_key,
                    },
                )
                return {"action": action, "ok": True, "result": result}

            if action == "list_incidents":
                token = config.get("api_token")
                if not token:
                    return {
                        "error": "api_token is required for list_incidents",
                    }
                headers = {
                    "Authorization": f"Token token={token}",
                    "Accept": "application/vnd.pagerduty+json;version=2",
                }
                params = []
                if payload.get("statuses"):
                    for s in payload["statuses"]:
                        params.append(f"statuses[]={s}")
                else:
                    params.append("statuses[]=triggered")
                    params.append("statuses[]=acknowledged")
                qs = "&".join(params)
                data = await self._get(f"{API_BASE}/incidents?{qs}", headers)
                return {"action": action, "incidents": data.get("incidents", [])}

            return {"error": f"Unknown action: {action}"}
        except httpx.HTTPStatusError as exc:
            return {
                "error": f"pagerduty error: {exc.response.status_code}",
                "body": exc.response.text[:512],
            }
        except httpx.HTTPError as exc:
            return {"error": f"pagerduty request failed: {exc}"}
