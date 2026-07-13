"""Devo SIEM alerts connector.

Pulls triggered **alerts** from the Devo Alerting API and folds each into the
common AiSOC alert shape. Devo alert `severity` (1–5 or a named level) maps
onto the five-tier ladder.

Auth is a Devo API standalone token. The API host is region-specific
(operator-supplied).
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_LIMIT = 200
_NAMED = {
    "informational": "info",
    "info": "info",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "very high": "critical",
    "critical": "critical",
}


class DevoConnector(BaseConnector):
    """Devo SIEM alerts."""

    connector_id = "devo"
    connector_name = "Devo"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull triggered alerts from the Devo Alerting API. Devo alert "
                "severity (1-5 or named) maps to the five-tier ladder. Auth is "
                "a Devo standalone API token."
            ),
            docs_url="/docs/connectors/devo",
            fields=[
                Field("api_url", "string", "Alerting API URL", placeholder="https://api-us.devo.com/alerts"),
                Field("api_token", "secret", "Standalone API Token"),
                Field("verify_tls", "boolean", "Verify TLS certificate", required=False, default=True),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.QUERY_LOGS)

    def __init__(self, api_url: str, api_token: str, verify_tls: bool = True) -> None:
        self._base = api_url.rstrip("/")
        self._token = api_token
        self._verify = bool(verify_tls)

    def _headers(self) -> dict[str, str]:
        return {"standAloneToken": self._token, "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify) as client:
                resp = await client.get(f"{self._base}/v1/alerts", headers=self._headers(), params={"size": 1})
            if resp.status_code == 200:
                return {"success": True, "connector": self.connector_id}
            return {"success": False, "connector": self.connector_id, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            import time  # noqa: PLC0415

            to_ms = int(time.time() * 1000)
            from_ms = to_ms - since_seconds * 1000
            async with httpx.AsyncClient(timeout=30.0, verify=self._verify) as client:
                resp = await client.get(
                    f"{self._base}/v1/alerts",
                    headers=self._headers(),
                    params={"from": from_ms, "to": to_ms, "size": _LIMIT},
                )
            if resp.status_code != 200:
                logger.warning("devo.fetch_failed", status=resp.status_code)
                return out
            body = resp.json() or {}
            for alert in body.get("object") or body.get("alerts") or []:
                out.append(self.normalize(alert))
        except Exception as exc:  # noqa: BLE001
            logger.warning("devo.fetch_error", error=str(exc))
        return out

    @staticmethod
    def _severity(raw_sev: Any) -> str:
        if isinstance(raw_sev, str):
            return _NAMED.get(raw_sev.strip().lower(), "medium")
        try:
            n = int(raw_sev)
        except (TypeError, ValueError):
            return "medium"
        return {1: "info", 2: "low", 3: "medium", 4: "high", 5: "critical"}.get(n, "medium")

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        ctx = raw.get("context") or {}
        return {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": self._severity(raw.get("severity")),
            "title": raw.get("summary") or raw.get("name") or f"Devo alert {raw.get('alertId')}",
            "description": (f"context={raw.get('context')}; status={raw.get('status')}; priority={raw.get('priority')}"),
            "external_id": str(raw.get("alertId") or raw.get("id") or ""),
            "src_ip": ctx.get("srcIp") or ctx.get("src_ip"),
            "username": ctx.get("username") or ctx.get("user"),
            "event_type": f"devo.alert.{raw.get('name') or 'triggered'}",
            "created_at": raw.get("createDate") or raw.get("timestamp"),
            "raw": raw,
        }
