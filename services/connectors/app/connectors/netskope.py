"""Netskope SASE / SWG alerts connector.

Pulls **alerts** (DLP, malware, anomaly, policy) from the Netskope REST API v2
(`/api/v2/events/data/alert`) and folds each into the common AiSOC alert shape.
Netskope's `severity` string maps onto the five-tier ladder; malware and DLP
alert types are floored at `high` so they can't be under-rated.

Auth is a Netskope API v2 token scoped to the alerts endpoint. The tenant host
is operator-supplied.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_LIMIT = 200
_SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info", "informational": "info"}
_HIGH_FLOOR_TYPES = {"malware", "dlp", "compromised_credential", "compromised credential"}


class NetskopeConnector(BaseConnector):
    """Netskope SASE alerts."""

    connector_id = "netskope"
    connector_name = "Netskope"
    connector_category = "network"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull DLP / malware / anomaly / policy alerts from the Netskope "
                "REST API v2. Alert severity maps to the five-tier ladder; "
                "malware and DLP alerts are floored at high. Auth is a Netskope "
                "API v2 token."
            ),
            docs_url="/docs/connectors/netskope",
            fields=[
                Field("tenant_url", "string", "Tenant URL", placeholder="https://tenant.goskope.com"),
                Field("api_token", "secret", "API v2 Token"),
                Field("verify_tls", "boolean", "Verify TLS certificate", required=False, default=True),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PIVOT_USER, Capability.PIVOT_IP)

    def __init__(self, tenant_url: str, api_token: str, verify_tls: bool = True) -> None:
        self._base = tenant_url.rstrip("/")
        self._token = api_token
        self._verify = bool(verify_tls)

    def _headers(self) -> dict[str, str]:
        return {"Netskope-Api-Token": self._token, "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify) as client:
                resp = await client.get(
                    f"{self._base}/api/v2/events/data/alert",
                    headers=self._headers(),
                    params={"limit": 1},
                )
            if resp.status_code == 200:
                return {"success": True, "connector": self.connector_id}
            return {"success": False, "connector": self.connector_id, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=self._verify) as client:
                resp = await client.get(
                    f"{self._base}/api/v2/events/data/alert",
                    headers=self._headers(),
                    params={"limit": _LIMIT, "timeperiod": max(3600, since_seconds)},
                )
            if resp.status_code != 200:
                logger.warning("netskope.fetch_failed", status=resp.status_code)
                return out
            body = resp.json() or {}
            for alert in body.get("result") or body.get("data") or []:
                out.append(self.normalize(alert))
        except Exception as exc:  # noqa: BLE001
            logger.warning("netskope.fetch_error", error=str(exc))
        return out

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        alert_type = str(raw.get("alert_type") or raw.get("alert_name") or "").lower()
        sev = _SEV_MAP.get(str(raw.get("severity") or "").lower(), "medium")
        if any(t in alert_type for t in _HIGH_FLOOR_TYPES) and sev in ("info", "low", "medium"):
            sev = "high"
        return {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": sev,
            "title": raw.get("alert_name") or f"Netskope {alert_type or 'alert'}",
            "description": (
                f"alert_type={raw.get('alert_type')}; " f"app={raw.get('app')}; action={raw.get('action')}; " f"policy={raw.get('policy')}"
            ),
            "external_id": str(raw.get("_id") or raw.get("alert_id") or ""),
            "username": raw.get("user"),
            "src_ip": raw.get("srcip") or raw.get("src_ip"),
            "actor": raw.get("user"),
            "event_type": f"netskope.alert.{alert_type or 'event'}",
            "created_at": raw.get("timestamp"),
            "raw": raw,
        }
