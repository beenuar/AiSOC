"""IBM QRadar SIEM offenses connector.

Pulls open **offenses** from the QRadar REST API (`GET /api/siem/offenses`)
and folds each into the common AiSOC alert shape. QRadar's `magnitude` (1–10)
is the closest analogue to a severity signal, so we map it onto the five-tier
ladder (`info|low|medium|high|critical`) rather than collapsing everything to a
single level.

Auth is a QRadar **SEC token** (Authorization header `SEC: <token>`), the
service-account model QRadar recommends for API clients. The console host is
operator-supplied; we default TLS verification on but allow self-signed
consoles via a toggle (many QRadar deployments use an internal CA).
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_MAX_OFFENSES = 200


class QRadarConnector(BaseConnector):
    """IBM QRadar SIEM offenses."""

    connector_id = "qradar"
    connector_name = "IBM QRadar"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Pull open offenses from IBM QRadar via the REST API "
                "(/api/siem/offenses). Offense magnitude (1-10) maps to the "
                "five-tier severity ladder. Auth is a QRadar SEC token."
            ),
            docs_url="/docs/connectors/qradar",
            fields=[
                Field("console_url", "string", "Console URL", placeholder="https://qradar.example.com"),
                Field("sec_token", "secret", "SEC Token", help_text="QRadar authorized-service SEC token."),
                Field(
                    "verify_tls",
                    "boolean",
                    "Verify TLS certificate",
                    required=False,
                    default=True,
                    help_text="Disable only for consoles using an internal/self-signed CA.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.QUERY_LOGS)

    def __init__(self, console_url: str, sec_token: str, verify_tls: bool = True) -> None:
        self._base = console_url.rstrip("/")
        self._token = sec_token
        self._verify = bool(verify_tls)

    def _headers(self) -> dict[str, str]:
        return {"SEC": self._token, "Accept": "application/json", "Version": "12.0"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify) as client:
                resp = await client.get(
                    f"{self._base}/api/siem/offenses",
                    headers=self._headers(),
                    params={"Range": "items=0-0"},
                )
            if resp.status_code in (200, 206):
                return {"success": True, "connector": self.connector_id}
            return {"success": False, "connector": self.connector_id, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since_ms = 0
        # QRadar filters on epoch-ms; pull offenses updated in the window.
        try:
            import time  # noqa: PLC0415

            since_ms = int((time.time() - since_seconds) * 1000)
        except Exception:  # noqa: BLE001
            since_ms = 0
        out: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=self._verify) as client:
                resp = await client.get(
                    f"{self._base}/api/siem/offenses",
                    headers={**self._headers(), "Range": f"items=0-{_MAX_OFFENSES - 1}"},
                    params={"filter": f"last_updated_time > {since_ms} and status = OPEN"},
                )
            if resp.status_code not in (200, 206):
                logger.warning("qradar.fetch_failed", status=resp.status_code)
                return out
            for off in resp.json() or []:
                out.append(self.normalize(off))
        except Exception as exc:  # noqa: BLE001
            logger.warning("qradar.fetch_error", error=str(exc))
        return out

    @staticmethod
    def _severity_from_magnitude(magnitude: Any) -> str:
        try:
            m = int(magnitude)
        except (TypeError, ValueError):
            return "medium"
        if m >= 9:
            return "critical"
        if m >= 7:
            return "high"
        if m >= 4:
            return "medium"
        if m >= 2:
            return "low"
        return "info"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": self._severity_from_magnitude(raw.get("magnitude")),
            "title": raw.get("description") or f"QRadar offense {raw.get('id')}",
            "description": (
                f"offense_type={raw.get('offense_type')}; "
                f"magnitude={raw.get('magnitude')}; "
                f"event_count={raw.get('event_count')}; "
                f"status={raw.get('status')}"
            ),
            "external_id": str(raw.get("id") or ""),
            "src_ip": (raw.get("offense_source") if raw.get("offense_source_summary") == "IP" else None),
            "event_type": f"qradar.offense.{raw.get('offense_type', 'unknown')}",
            "created_at": raw.get("start_time"),
            "raw": raw,
        }
