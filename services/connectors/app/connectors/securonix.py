"""Securonix (Next-Gen SIEM / UEBA) incidents connector.

Pulls **incidents** from the Securonix incident API and folds each into the
common AiSOC alert shape. Securonix incident `priority` (Low/Medium/High/
Critical) maps directly onto the five-tier ladder.

Auth is a Securonix API token issued from the tenant. The tenant host is
operator-supplied.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_PRIORITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "none": "info",
    "informational": "info",
}


class SecuronixConnector(BaseConnector):
    """Securonix Next-Gen SIEM incidents."""

    connector_id = "securonix"
    connector_name = "Securonix"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull incidents from Securonix Next-Gen SIEM / UEBA. Incident "
                "priority (Low/Medium/High/Critical) maps directly to the "
                "five-tier severity ladder. Auth is a tenant API token."
            ),
            docs_url="/docs/connectors/securonix",
            fields=[
                Field("tenant_url", "string", "Tenant URL", placeholder="https://tenant.securonix.net/Snypr"),
                Field("api_token", "secret", "API Token"),
                Field("verify_tls", "boolean", "Verify TLS certificate", required=False, default=True),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PIVOT_USER)

    def __init__(self, tenant_url: str, api_token: str, verify_tls: bool = True) -> None:
        self._base = tenant_url.rstrip("/")
        self._token = api_token
        self._verify = bool(verify_tls)

    def _headers(self) -> dict[str, str]:
        return {"token": self._token, "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify) as client:
                resp = await client.get(
                    f"{self._base}/ws/incident/get",
                    headers=self._headers(),
                    params={"type": "metaInfo"},
                )
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
                    f"{self._base}/ws/incident/get",
                    headers=self._headers(),
                    params={"type": "list", "from": from_ms, "to": to_ms, "rangeType": "updated"},
                )
            if resp.status_code != 200:
                logger.warning("securonix.fetch_failed", status=resp.status_code)
                return out
            body = resp.json() or {}
            incidents = (((body.get("result") or {}).get("data") or {}).get("incidentItems")) or []
            for inc in incidents:
                out.append(self.normalize(inc))
        except Exception as exc:  # noqa: BLE001
            logger.warning("securonix.fetch_error", error=str(exc))
        return out

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        priority = str(raw.get("priority") or "").lower()
        entity = raw.get("entity") or raw.get("violator")
        return {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": _PRIORITY_MAP.get(priority, "medium"),
            "title": raw.get("incidentType") or f"Securonix incident {raw.get('incidentId')}",
            "description": (
                f"priority={raw.get('priority')}; " f"status={raw.get('status')}; " f"reason={raw.get('reason')}; " f"entity={entity}"
            ),
            "external_id": str(raw.get("incidentId") or ""),
            "username": entity if raw.get("entityType") == "Users" else None,
            "actor": entity,
            "event_type": "securonix.incident",
            "created_at": raw.get("lastUpdateDate"),
            "raw": raw,
        }
