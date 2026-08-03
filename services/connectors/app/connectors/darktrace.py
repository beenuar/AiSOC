"""Darktrace connector.

Pulls model breaches from the Darktrace Threat Visualizer API as an alert
stream. Darktrace signs each request with an HMAC-SHA1 of
``requestPath\\npublicToken\\ndate`` using the private token (DTAPI scheme).
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class DarktraceConnector(BaseConnector):
    connector_id = "darktrace"
    connector_name = "Darktrace"
    connector_category = "ndr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Darktrace NDR model breaches as alerts (Threat Visualizer API).",
            docs_url="/docs/connectors/darktrace",
            fields=[
                Field("base_url", "string", "Appliance URL", placeholder="https://darktrace.example.com"),
                Field("public_token", "secret", "Public Token"),
                Field("private_token", "secret", "Private Token"),
                Field(
                    "ssl_verify",
                    "boolean",
                    "Verify SSL certificate",
                    required=False,
                    default=True,
                    help_text="Disable only for self-signed certificates on a private appliance.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PIVOT_HOST, Capability.PIVOT_IP)

    def __init__(self, base_url: str, public_token: str, private_token: str, ssl_verify: bool = True):
        self._base = base_url.rstrip("/")
        self._public = public_token
        self._private = private_token
        self._ssl_verify = ssl_verify

    def _signed_headers(self, request_path: str) -> dict[str, str]:
        date = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
        # DTAPI request signature — HMAC (not password hashing), the vendor scheme.
        message = f"{request_path}\n{self._public}\n{date}"
        signature = hmac.new(self._private.encode(), message.encode(), hashlib.sha1).hexdigest()
        return {"DTAPI-Token": self._public, "DTAPI-Date": date, "DTAPI-Signature": signature}

    async def test_connection(self) -> dict[str, Any]:
        path = "/status"
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._ssl_verify) as client:
                resp = await client.get(f"{self._base}{path}", headers=self._signed_headers(path))
                return {"success": resp.status_code < 400, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("darktrace.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        path = "/modelbreaches"
        query = f"?minscore=0.3&starttime={int((datetime.now(UTC).timestamp() - max(1, since_seconds)) * 1000)}"
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=self._ssl_verify) as client:
                resp = await client.get(f"{self._base}{path}{query}", headers=self._signed_headers(path + query))
                resp.raise_for_status()
                breaches = resp.json()
        except Exception as exc:
            logger.warning("darktrace.fetch_failed", error=str(exc))
            return []
        return [self.normalize(b) for b in breaches if isinstance(b, dict)]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw, dict) and "raw_event" in raw and raw.get("source") == self.connector_id:
            return raw
        try:
            score = float(raw.get("score", 0.0))
        except (TypeError, ValueError):
            score = 0.0
        severity = "critical" if score >= 0.9 else ("high" if score >= 0.7 else ("medium" if score >= 0.4 else "low"))
        model = (raw.get("model") or {}).get("then", {}) if isinstance(raw.get("model"), dict) else {}
        device = raw.get("device") or {}
        return {
            "source": self.connector_id,
            "external_id": str(raw.get("pbid") or ""),
            "title": model.get("name") or "Darktrace model breach",
            "description": model.get("description") or "",
            "severity": severity,
            "src_ip": device.get("ip") if isinstance(device, dict) else None,
            "hostname": device.get("hostname") if isinstance(device, dict) else None,
            "raw_event": raw,
            "created_at": raw.get("time"),
        }
