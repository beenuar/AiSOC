"""Zeek / Suricata NDR connector (JSON log spool pull).

Pulls network-detection events that a Zeek (`notice.log`, `conn.log`) or
Suricata (`eve.json` alerts) sensor has exported as JSON to an HTTP spool
endpoint, and folds each into the common AiSOC alert shape. Suricata alert
`severity` (1=highest … 3) and Zeek `notice` types map onto the five-tier
ladder.

The sensor spool endpoint + token are operator-supplied. One instance can serve
either engine via the `engine` selector.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_LIMIT = 500
# Suricata alert.severity: 1 = highest priority.
_SURICATA_SEV = {1: "high", 2: "medium", 3: "low"}
# Zeek notice types that warrant elevation.
_ZEEK_HIGH_NOTES = ("scan::", "intel::", "ssl::invalid", "sqlinjection", "teamcymru", "heartbleed")


class ZeekSuricataConnector(BaseConnector):
    """Zeek / Suricata network detection (NDR)."""

    connector_id = "zeek_suricata"
    connector_name = "Zeek / Suricata NDR"
    connector_category = "ndr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull network-detection events from a Zeek (notice.log) or "
                "Suricata (eve.json alert) sensor's JSON spool. Suricata alert "
                "severity (1=highest) and Zeek notice types map to the "
                "five-tier ladder."
            ),
            docs_url="/docs/connectors/zeek_suricata",
            fields=[
                Field(
                    "engine",
                    "select",
                    "Sensor engine",
                    options=[
                        {"value": "suricata", "label": "Suricata (eve.json)"},
                        {"value": "zeek", "label": "Zeek (notice.log)"},
                    ],
                ),
                Field("spool_url", "string", "Spool URL", placeholder="https://ndr-sensor.internal/spool"),
                Field("api_token", "secret", "Spool token"),
                Field("verify_tls", "boolean", "Verify TLS certificate", required=False, default=True),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PIVOT_IP)

    def __init__(self, engine: str, spool_url: str, api_token: str, verify_tls: bool = True) -> None:
        engine = (engine or "").lower()
        if engine not in ("suricata", "zeek"):
            raise ValueError(f"zeek_suricata: unknown engine '{engine}' (need 'suricata' or 'zeek')")
        self._engine = engine
        self._base = spool_url.rstrip("/")
        self._token = api_token
        self._verify = bool(verify_tls)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify) as client:
                resp = await client.get(self._base, headers=self._headers(), params={"engine": self._engine, "limit": 1})
            if resp.status_code == 200:
                return {"success": True, "connector": self.connector_id, "engine": self._engine}
            return {"success": False, "connector": self.connector_id, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=self._verify) as client:
                resp = await client.get(
                    self._base,
                    headers=self._headers(),
                    params={"engine": self._engine, "limit": _LIMIT, "since": since_seconds},
                )
            if resp.status_code != 200:
                logger.warning("zeek_suricata.fetch_failed", status=resp.status_code)
                return out
            body = resp.json() or {}
            events = body.get("events") if isinstance(body, dict) else body
            for ev in events or []:
                out.append(self.normalize(ev))
        except Exception as exc:  # noqa: BLE001
            logger.warning("zeek_suricata.fetch_error", error=str(exc))
        return out

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if self._engine == "suricata":
            return self._normalize_suricata(raw)
        return self._normalize_zeek(raw)

    def _normalize_suricata(self, raw: dict[str, Any]) -> dict[str, Any]:
        alert = raw.get("alert") or {}
        sev = _SURICATA_SEV.get(int(alert.get("severity", 3)) if str(alert.get("severity", "")).isdigit() else 3, "low")
        return {
            "source": self.connector_id,
            "stream": "suricata",
            "category": self.connector_category,
            "severity": sev,
            "title": alert.get("signature") or "Suricata alert",
            "description": (f"category={alert.get('category')}; sid={alert.get('signature_id')}; proto={raw.get('proto')}"),
            "external_id": str(raw.get("flow_id") or alert.get("signature_id") or ""),
            "src_ip": raw.get("src_ip"),
            "dst_ip": raw.get("dest_ip"),
            "event_type": "zeek_suricata.suricata.alert",
            "created_at": raw.get("timestamp"),
            "raw": raw,
        }

    def _normalize_zeek(self, raw: dict[str, Any]) -> dict[str, Any]:
        note = str(raw.get("note") or "").lower()
        severity = "medium" if any(h in note for h in _ZEEK_HIGH_NOTES) else "low"
        return {
            "source": self.connector_id,
            "stream": "zeek",
            "category": self.connector_category,
            "severity": severity,
            "title": raw.get("note") or "Zeek notice",
            "description": raw.get("msg") or raw.get("sub"),
            "external_id": str(raw.get("uid") or ""),
            "src_ip": raw.get("id.orig_h") or raw.get("src"),
            "dst_ip": raw.get("id.resp_h") or raw.get("dst"),
            "event_type": "zeek_suricata.zeek.notice",
            "created_at": raw.get("ts"),
            "raw": raw,
        }
