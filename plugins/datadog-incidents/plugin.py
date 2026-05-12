"""Datadog incidents/signals connector plugin for AiSOC."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx


class Plugin:
    """Datadog connector for incidents + security signals."""

    def _base_url(self, context: dict[str, Any]) -> str:
        site = (context.get("config") or {}).get("site") or "datadoghq.com"
        return f"https://api.{site}"

    def _headers(self, context: dict[str, Any]) -> dict[str, str]:
        config = context.get("config") or {}
        if not config.get("api_key") or not config.get("app_key"):
            raise ValueError("api_key and app_key are required")
        return {
            "DD-API-KEY": config["api_key"],
            "DD-APPLICATION-KEY": config["app_key"],
            "Content-Type": "application/json",
        }

    async def _get(self, url: str, headers: dict[str, str], params: dict | None = None):
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            return resp.json()

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        action = payload.get("action", "fetch_events")
        try:
            headers = self._headers(context)
        except ValueError as exc:
            return {"error": str(exc)}

        base = self._base_url(context)

        try:
            if action == "test_connection":
                data = await self._get(f"{base}/api/v1/validate", headers)
                return {"connected": bool(data.get("valid")), "raw": data}

            if action == "list_incidents":
                params = {"page[size]": payload.get("limit", 50)}
                data = await self._get(
                    f"{base}/api/v2/incidents", headers, params=params
                )
                return {"incidents": data.get("data", [])}

            if action == "list_signals":
                since = payload.get("since") or (
                    datetime.now(UTC) - timedelta(hours=1)
                ).isoformat()
                params = {
                    "filter[from]": since,
                    "page[limit]": payload.get("limit", 50),
                }
                data = await self._get(
                    f"{base}/api/v2/security_monitoring/signals",
                    headers,
                    params=params,
                )
                return {"signals": data.get("data", [])}

            if action == "fetch_events":
                feeds = (context.get("config") or {}).get(
                    "feeds", ["incidents", "security_signals"]
                )
                events: list[dict[str, Any]] = []
                if "incidents" in feeds:
                    inc = await self._get(f"{base}/api/v2/incidents", headers)
                    for item in inc.get("data", []):
                        item["_aisoc_feed"] = "incidents"
                        events.append(item)
                if "security_signals" in feeds:
                    since = payload.get("since") or (
                        datetime.now(UTC) - timedelta(hours=1)
                    ).isoformat()
                    sigs = await self._get(
                        f"{base}/api/v2/security_monitoring/signals",
                        headers,
                        params={"filter[from]": since, "page[limit]": 100},
                    )
                    for item in sigs.get("data", []):
                        item["_aisoc_feed"] = "security_signals"
                        events.append(item)
                return {"events": events}

            return {"error": f"Unknown action: {action}"}
        except httpx.HTTPStatusError as exc:
            return {
                "error": f"datadog api error: {exc.response.status_code}",
                "body": exc.response.text[:512],
            }
        except httpx.HTTPError as exc:
            return {"error": f"datadog request failed: {exc}"}
