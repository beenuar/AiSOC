"""
Zscaler connector.
Fetches web security logs from Zscaler Internet Access (ZIA).
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_SEVERITY_MAP = {
    "Allow": "info",
    "Caution": "low",
    "Block": "medium",
    "Quarantine": "high",
    "Isolate": "high",
}


class ZscalerConnector(BaseConnector):
    connector_id = "zscaler"
    connector_name = "Zscaler Internet Access"
    connector_category = "network"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Zscaler Internet Access web security logs via the ZIA API.",
            docs_url="/docs/connectors/zscaler",
            fields=[
                Field("api_key", "secret", "API Key"),
                Field(
                    "cloud",
                    "string",
                    "ZIA Cloud",
                    required=False,
                    default="zscloud.net",
                    help_text="ZIA cloud domain (e.g. zscloud.net, zscaler.net).",
                ),
                Field("username", "string", "Admin Username"),
                Field("password", "secret", "Admin Password"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Zscaler ZIA — web policy / proxy logs surfaced as alerts when blocks
        # / quarantines fire. Today the runtime only implements ``fetch_alerts``.
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        api_key: str,
        username: str,
        password: str,
        cloud: str = "zscloud.net",
    ):
        self._api_key = api_key
        self._cloud = cloud
        self._username = username
        self._password = password
        self._base_url = f"https://zsapi.{cloud}"
        self._jsessionid: str | None = None

    def _obfuscate_api_key(self) -> tuple[str, str]:
        now = str(int(time.time() * 1000))
        n = now[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for _i, ch in enumerate(r):
            key += self._api_key[int(ch)]
        return key, now

    async def _authenticate(self) -> None:
        obf_key, timestamp = self._obfuscate_api_key()
        payload = {
            "apiKey": obf_key,
            "username": self._username,
            "password": self._password,
            "timestamp": timestamp,
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/v1/authenticatedSession",
                json=payload,
            )
            resp.raise_for_status()
            self._jsessionid = resp.cookies.get("JSESSIONID") or resp.json().get("JSESSIONID")
            if not self._jsessionid:
                for cookie in resp.cookies.jar:
                    if cookie.name == "JSESSIONID":
                        self._jsessionid = cookie.value
                        break

    async def test_connection(self) -> dict[str, Any]:
        try:
            await self._authenticate()
            return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("zscaler.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        if not self._jsessionid:
            await self._authenticate()

        end_time = int(datetime.now(UTC).timestamp())
        start_time = end_time - since_seconds

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._base_url}/api/v1/webApplicationRules",
                cookies={"JSESSIONID": self._jsessionid or ""},
                json={
                    "startTime": start_time,
                    "endTime": end_time,
                    "category": "any",
                    "subcategory": "any",
                    "action": "any",
                    "pageSize": 100,
                },
            )
            if resp.status_code == 401:
                await self._authenticate()
                resp = await client.post(
                    f"{self._base_url}/api/v1/webApplicationRules",
                    cookies={"JSESSIONID": self._jsessionid or ""},
                    json={
                        "startTime": start_time,
                        "endTime": end_time,
                        "category": "any",
                        "subcategory": "any",
                        "action": "any",
                        "pageSize": 100,
                    },
                )
            resp.raise_for_status()
            logs = resp.json() if isinstance(resp.json(), list) else resp.json().get("data", [])

        return [self.normalize(e) for e in logs]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        action = raw.get("action", "Allow")
        return {
            "source": self.connector_id,
            "external_id": str(raw.get("id", raw.get("transactionId", ""))),
            "title": f"Zscaler: {action} — {raw.get('url', raw.get('hostname', 'unknown'))}",
            "description": (
                f"Policy action {action} for "
                f"{raw.get('url', raw.get('hostname', 'unknown'))} "
                f"(category: {raw.get('urlCategory', 'unknown')})"
            ),
            "severity": _SEVERITY_MAP.get(action, "info"),
            "src_ip": raw.get("clientPublicIP") or raw.get("clientPrivateIP"),
            "hostname": raw.get("hostname") or raw.get("serverIP"),
            "actor": raw.get("login") or raw.get("user"),
            "raw_event": raw,
            "created_at": raw.get("datetime") or raw.get("timestamp"),
        }
