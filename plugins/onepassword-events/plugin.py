"""1Password Events connector plugin for AiSOC.

Pulls events from the 1Password Events API across three feeds:
  - signinattempts
  - itemusages
  - auditevents

Required config:
  - api_token (1Password Events API token)
  - region (com, ca, or eu, default com)
  - feeds (list of feed names; defaults to all three)

Payload shape:
  {
    "action": "test_connection" | "fetch_events",
    "feed": "signinattempts" | "itemusages" | "auditevents",
    "since": "ISO-8601 timestamp",
    "limit": 100
  }
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

try:
    import httpx

    _HTTPX = True
except ImportError:
    _HTTPX = False


_REGION_HOSTS = {
    "com": "https://events.1password.com",
    "ca": "https://events.1password.ca",
    "eu": "https://events.1password.eu",
}

_FEED_PATHS = {
    "signinattempts": "/api/v1/signinattempts",
    "itemusages": "/api/v1/itemusages",
    "auditevents": "/api/v1/auditevents",
}


class Plugin:
    """1Password Events connector plugin."""

    def _client(self, context: dict[str, Any]) -> httpx.AsyncClient:
        config = context.get("config") or {}
        if "api_token" not in config:
            raise ValueError("api_token is required in plugin config")
        region = (config.get("region") or "com").lower()
        base = _REGION_HOSTS.get(region, _REGION_HOSTS["com"])
        return httpx.AsyncClient(
            base_url=base,
            headers={
                "Authorization": f"Bearer {config['api_token']}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _HTTPX:
            return {"error": "httpx not installed; run `pip install httpx`"}

        action = payload.get("action", "fetch_events")

        async with self._client(context) as client:
            if action == "test_connection":
                resp = await client.post(
                    _FEED_PATHS["signinattempts"],
                    json={
                        "limit": 1,
                        "start_time": (
                            datetime.now(UTC) - timedelta(minutes=5)
                        ).isoformat(),
                    },
                )
                return {"connected": resp.status_code in (200, 401)}

            if action == "fetch_events":
                config = context.get("config") or {}
                feeds = payload.get("feed_list") or config.get(
                    "feeds", ["signinattempts", "itemusages", "auditevents"]
                )
                if isinstance(feeds, str):
                    feeds = [feeds]
                since = payload.get("since") or (
                    datetime.now(UTC) - timedelta(minutes=15)
                ).isoformat()
                limit = int(payload.get("limit", 200))

                results: dict[str, list[dict[str, Any]]] = {}
                for feed in feeds:
                    path = _FEED_PATHS.get(feed)
                    if not path:
                        continue
                    resp = await client.post(
                        path,
                        json={"limit": limit, "start_time": since},
                    )
                    resp.raise_for_status()
                    body = resp.json()
                    results[feed] = body.get("items") or []

                return {
                    "action": action,
                    "since": since,
                    "feeds": list(results.keys()),
                    "events_per_feed": {k: len(v) for k, v in results.items()},
                    "events": results,
                }

            return {"error": f"Unknown action: {action}"}
