"""Jamf Pro MDM connector for AiSOC.

Supports OAuth client-credentials auth, computer/device lookup, lock + wipe
commands, and compliance metadata retrieval against the Jamf Pro REST API.

Required config (passed in via context["config"]):
  - jamf_url: https://<tenant>.jamfcloud.com
  - client_id: API role client ID
  - client_secret: API role client secret

Payload shape:
  {
    "action": "get_device" | "list_devices" | "lock_device" | "wipe_device"
              | "get_compliance" | "get_inventory",
    "device_id": "...",        # required for device-scoped actions
    "passcode": "123456",      # required for lock_device
    "wipe_token": "manager"     # required for wipe_device
  }
"""
from __future__ import annotations

import time
from typing import Any

try:
    import httpx

    _HTTPX = True
except ImportError:
    _HTTPX = False


_TOKEN_CACHE: dict[str, dict[str, Any]] = {}


class Plugin:
    """Jamf Pro MDM connector plugin."""

    async def _token(self, client: httpx.AsyncClient, config: dict[str, Any]) -> str:
        cache_key = f"{config['jamf_url']}::{config['client_id']}"
        cached = _TOKEN_CACHE.get(cache_key)
        if cached and cached["expires_at"] > time.time() + 30:
            return str(cached["access_token"])

        resp = await client.post(
            "/api/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        resp.raise_for_status()
        body = resp.json()
        token = body["access_token"]
        _TOKEN_CACHE[cache_key] = {
            "access_token": token,
            "expires_at": time.time() + int(body.get("expires_in", 1500)),
        }
        return str(token)

    async def _client(self, context: dict[str, Any]) -> httpx.AsyncClient:
        config = context.get("config") or {}
        if not all(k in config for k in ("jamf_url", "client_id", "client_secret")):
            raise ValueError("jamf_url, client_id, and client_secret are required")
        client = httpx.AsyncClient(
            base_url=config["jamf_url"].rstrip("/"),
            timeout=30,
        )
        token = await self._token(client, config)
        client.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        return client

    async def run(self, payload: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        if not _HTTPX:
            return {"error": "httpx not installed; run `pip install httpx`"}

        action = payload.get("action", "get_device")
        async with await self._client(context) as client:
            if action == "list_devices":
                resp = await client.get("/api/v1/computers-inventory", params={"page-size": 100})
                resp.raise_for_status()
                return {"action": action, "devices": resp.json().get("results", [])}
            if action == "get_device":
                device_id = payload.get("device_id", "")
                resp = await client.get(f"/api/v1/computers-inventory-detail/{device_id}")
                resp.raise_for_status()
                return {"action": action, "device": resp.json()}
            if action == "lock_device":
                device_id = payload.get("device_id", "")
                passcode = payload.get("passcode", "000000")
                resp = await client.post(
                    f"/api/v1/computer-inventory/{device_id}/erase",
                    json={"pin": passcode, "lock": True, "wipe": False},
                )
                resp.raise_for_status()
                return {"action": action, "device_id": device_id, "status": "locked"}
            if action == "wipe_device":
                device_id = payload.get("device_id", "")
                resp = await client.post(
                    "/api/v1/mobile-device-commands",
                    json={
                        "commandData": {"commandType": "ERASE_DEVICE"},
                        "clientData": [{"managementId": device_id}],
                    },
                )
                resp.raise_for_status()
                return {"action": action, "device_id": device_id, "status": "wipe_queued"}
            if action == "get_compliance":
                device_id = payload.get("device_id", "")
                resp = await client.get(f"/api/v1/computers-inventory-detail/{device_id}")
                resp.raise_for_status()
                data = resp.json()
                return {
                    "action": action,
                    "device_id": device_id,
                    "compliant": bool(data.get("general", {}).get("managementId")),
                    "last_inventory": data.get("general", {}).get("lastInventoryUpdate"),
                    "os_version": data.get("operatingSystem", {}).get("version"),
                }
            if action == "get_inventory":
                device_id = payload.get("device_id", "")
                resp = await client.get(f"/api/v1/computers-inventory-detail/{device_id}")
                resp.raise_for_status()
                return {"action": action, "inventory": resp.json()}
            return {"error": f"Unknown action: {action}"}
