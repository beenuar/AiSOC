"""Tailscale ACL action plugin for AiSOC.

Supported actions:
  - list_devices: list all devices in the tailnet
  - get_device: fetch a single device by ID
  - delete_device: remove a device from the tailnet (forces re-auth)
  - get_acl: retrieve the current tailnet ACL policy (HuJSON)
  - update_acl: push a new ACL policy

Required config:
  - tailnet (e.g. example.com)
  - api_key (Tailscale API key, tskey-api-...)

Payload shape:
  {
    "action": "list_devices" | "get_device" | "delete_device"
              | "get_acl" | "update_acl",
    "device_id": "...",
    "acl": "<HuJSON string>"   # for update_acl
  }
"""
from __future__ import annotations

from typing import Any

try:
    import httpx

    _HTTPX = True
except ImportError:
    _HTTPX = False


_API_BASE = "https://api.tailscale.com/api/v2"


class Plugin:
    """Tailscale ACL action plugin."""

    def _client(self, context: dict[str, Any]) -> httpx.AsyncClient:
        config = context.get("config") or {}
        if "tailnet" not in config or "api_key" not in config:
            raise ValueError("tailnet and api_key are required in plugin config")
        return httpx.AsyncClient(
            base_url=_API_BASE,
            auth=(config["api_key"], ""),
            timeout=30,
        )

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _HTTPX:
            return {"error": "httpx not installed; run `pip install httpx`"}

        config = context.get("config") or {}
        tailnet = config.get("tailnet", "")
        action = payload.get("action", "list_devices")

        async with self._client(context) as client:
            if action == "list_devices":
                resp = await client.get(f"/tailnet/{tailnet}/devices")
                resp.raise_for_status()
                return {"action": action, "devices": resp.json().get("devices", [])}
            if action == "get_device":
                device_id = payload.get("device_id", "")
                resp = await client.get(f"/device/{device_id}")
                resp.raise_for_status()
                return {"action": action, "device": resp.json()}
            if action == "delete_device":
                device_id = payload.get("device_id", "")
                resp = await client.delete(f"/device/{device_id}")
                resp.raise_for_status()
                return {"action": action, "device_id": device_id, "deleted": True}
            if action == "get_acl":
                resp = await client.get(
                    f"/tailnet/{tailnet}/acl",
                    headers={"Accept": "application/hujson"},
                )
                resp.raise_for_status()
                return {"action": action, "acl": resp.text}
            if action == "update_acl":
                acl = payload.get("acl", "")
                resp = await client.post(
                    f"/tailnet/{tailnet}/acl",
                    content=acl,
                    headers={"Content-Type": "application/hujson"},
                )
                resp.raise_for_status()
                return {"action": action, "updated": True}
            return {"error": f"Unknown action: {action}"}
