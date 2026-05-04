"""Cloudflare WAF action plugin for AiSOC.

Supported actions:
  - block_ip: add IP to account-level access rules (block mode)
  - unblock_ip: remove IP from account-level access rules
  - set_under_attack: toggle Under Attack security level for a zone
  - purge_cache: purge everything for a zone
  - list_rules: list firewall access rules for the configured account

Required config:
  - api_token (Cloudflare API token with appropriate scopes)
  - account_id (required for IP block actions)
  - zone_id (default zone for zone-scoped actions)

Payload shape:
  {
    "action": "block_ip" | "unblock_ip" | "set_under_attack"
              | "purge_cache" | "list_rules",
    "ip": "1.2.3.4",
    "zone_id": "...",         # overrides config.zone_id
    "level": "under_attack"  # for set_under_attack
  }
"""
from __future__ import annotations

from typing import Any

try:
    import httpx

    _HTTPX = True
except ImportError:
    _HTTPX = False


_API_BASE = "https://api.cloudflare.com/client/v4"


class Plugin:
    """Cloudflare WAF action plugin."""

    def _client(self, context: dict[str, Any]) -> "httpx.AsyncClient":
        config = context.get("config") or {}
        if "api_token" not in config:
            raise ValueError("api_token is required in plugin config")
        return httpx.AsyncClient(
            base_url=_API_BASE,
            headers={
                "Authorization": f"Bearer {config['api_token']}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _HTTPX:
            return {"error": "httpx not installed; run `pip install httpx`"}

        config = context.get("config") or {}
        action = payload.get("action", "list_rules")
        zone_id = payload.get("zone_id") or config.get("zone_id", "")
        account_id = config.get("account_id", "")

        async with self._client(context) as client:
            if action == "block_ip":
                if not account_id:
                    return {"error": "account_id is required for block_ip"}
                resp = await client.post(
                    f"/accounts/{account_id}/firewall/access_rules/rules",
                    json={
                        "mode": "block",
                        "configuration": {
                            "target": "ip",
                            "value": payload.get("ip", ""),
                        },
                        "notes": payload.get("note", "blocked by AiSOC"),
                    },
                )
                resp.raise_for_status()
                return {"action": action, "result": resp.json()}
            if action == "unblock_ip":
                if not account_id:
                    return {"error": "account_id is required for unblock_ip"}
                listing = await client.get(
                    f"/accounts/{account_id}/firewall/access_rules/rules",
                    params={
                        "configuration.target": "ip",
                        "configuration.value": payload.get("ip", ""),
                    },
                )
                listing.raise_for_status()
                rule_id = next(
                    (r["id"] for r in listing.json().get("result", [])),
                    None,
                )
                if not rule_id:
                    return {"action": action, "ip": payload.get("ip"), "removed": False}
                resp = await client.delete(
                    f"/accounts/{account_id}/firewall/access_rules/rules/{rule_id}"
                )
                resp.raise_for_status()
                return {"action": action, "ip": payload.get("ip"), "removed": True}
            if action == "set_under_attack":
                if not zone_id:
                    return {"error": "zone_id is required for set_under_attack"}
                level = payload.get("level", "under_attack")
                resp = await client.patch(
                    f"/zones/{zone_id}/settings/security_level",
                    json={"value": level},
                )
                resp.raise_for_status()
                return {"action": action, "zone_id": zone_id, "level": level}
            if action == "purge_cache":
                if not zone_id:
                    return {"error": "zone_id is required for purge_cache"}
                resp = await client.post(
                    f"/zones/{zone_id}/purge_cache",
                    json={"purge_everything": True},
                )
                resp.raise_for_status()
                return {"action": action, "zone_id": zone_id, "purged": True}
            if action == "list_rules":
                if not account_id:
                    return {"error": "account_id is required for list_rules"}
                resp = await client.get(
                    f"/accounts/{account_id}/firewall/access_rules/rules",
                    params={"per_page": 100},
                )
                resp.raise_for_status()
                return {"action": action, "rules": resp.json().get("result", [])}
            return {"error": f"Unknown action: {action}"}
