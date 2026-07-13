"""Exabeam (Advanced Analytics / Fusion SIEM) notable-sessions connector.

Pulls **notable user sessions** — the risk-scored session timelines Exabeam is
known for — via the Exabeam API and folds each into the common AiSOC alert
shape. Exabeam's per-session `riskScore` (0–150+) maps onto the five-tier
severity ladder.

Auth is an API key + secret (cluster-scoped). The cluster host is
operator-supplied.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_LIMIT = 200


class ExabeamConnector(BaseConnector):
    """Exabeam notable sessions."""

    connector_id = "exabeam"
    connector_name = "Exabeam"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull notable, risk-scored user sessions from Exabeam Advanced "
                "Analytics / Fusion SIEM. Session riskScore maps to the "
                "five-tier severity ladder. Auth is an API key + secret."
            ),
            docs_url="/docs/connectors/exabeam",
            fields=[
                Field("base_url", "string", "Cluster URL", placeholder="https://cluster.exabeam.com"),
                Field("api_key", "secret", "API Key ID"),
                Field("api_secret", "secret", "API Secret"),
                Field("verify_tls", "boolean", "Verify TLS certificate", required=False, default=True),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PIVOT_USER)

    def __init__(self, base_url: str, api_key: str, api_secret: str, verify_tls: bool = True) -> None:
        self._base = base_url.rstrip("/")
        self._key = api_key
        self._secret = api_secret
        self._verify = bool(verify_tls)

    def _headers(self) -> dict[str, str]:
        return {"ExaAuthToken": f"{self._key}:{self._secret}", "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify) as client:
                resp = await client.get(f"{self._base}/uba/api/ping", headers=self._headers())
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
                    f"{self._base}/uba/api/users/sequences/notable",
                    headers=self._headers(),
                    params={"numberOfResults": _LIMIT, "unit": "second", "num": since_seconds},
                )
            if resp.status_code != 200:
                logger.warning("exabeam.fetch_failed", status=resp.status_code)
                return out
            body = resp.json() or {}
            for sess in body.get("sessions") or body.get("users") or []:
                out.append(self.normalize(sess))
        except Exception as exc:  # noqa: BLE001
            logger.warning("exabeam.fetch_error", error=str(exc))
        return out

    @staticmethod
    def _severity_from_risk(risk: Any) -> str:
        try:
            r = float(risk)
        except (TypeError, ValueError):
            return "medium"
        if r >= 150:
            return "critical"
        if r >= 90:
            return "high"
        if r >= 40:
            return "medium"
        if r >= 10:
            return "low"
        return "info"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        user = raw.get("username") or raw.get("user")
        return {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": self._severity_from_risk(raw.get("riskScore") or raw.get("risk_score")),
            "title": f"Exabeam notable session for {user or 'user'}",
            "description": (
                f"session_id={raw.get('sessionId') or raw.get('session_id')}; "
                f"riskScore={raw.get('riskScore') or raw.get('risk_score')}; "
                f"rules={raw.get('numOfReasons') or raw.get('num_of_reasons')}"
            ),
            "external_id": str(raw.get("sessionId") or raw.get("session_id") or ""),
            "username": user,
            "actor": user,
            "event_type": "exabeam.notable_session",
            "created_at": raw.get("startTime") or raw.get("start_time"),
            "raw": raw,
        }
