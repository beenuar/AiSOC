"""Generic syslog / CEF listener connector.

A first-class connector for the long tail of appliances that only speak
syslog + ArcSight CEF (firewalls, proxies, legacy IDS, custom gear). A syslog
receiver (or the operator's existing rsyslog/syslog-ng) writes messages to an
HTTP spool endpoint; this connector pulls them and folds each into the common
AiSOC alert shape. The value is the **CEF parser** in ``parse_cef`` +
``normalize`` — it maps the CEF header (``deviceVendor|deviceProduct|
name|severity``) and the extension key=value pairs onto the AiSOC alert shape,
including CEF severity (0-10) → the five-tier ladder.

The spool endpoint + token are operator-supplied. Raw (non-CEF) syslog lines
are still ingested at ``info`` with the message preserved.
"""

from __future__ import annotations

import re
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_LIMIT = 500
# CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
_CEF_RE = re.compile(r"CEF:\d+\|(?P<hdr>(?:[^|\\]|\\.)*(?:\|(?:[^|\\]|\\.)*){6})\|(?P<ext>.*)$")


def _cef_severity(value: Any) -> str:
    """CEF severity: 0-3 low, 4-6 medium, 7-8 high, 9-10 very-high; also
    accepts the named forms Low/Medium/High/Very-High."""
    if isinstance(value, str) and not value.strip().isdigit():
        named = value.strip().lower()
        return {"unknown": "info", "low": "low", "medium": "medium", "high": "high", "very-high": "critical", "very high": "critical"}.get(
            named, "medium"
        )
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "medium"
    if n >= 9:
        return "critical"
    if n >= 7:
        return "high"
    if n >= 4:
        return "medium"
    if n >= 1:
        return "low"
    return "info"


def parse_cef(line: str) -> dict[str, Any] | None:
    """Parse a CEF line into {vendor, product, name, severity, ext:{...}}.

    Returns ``None`` for non-CEF input so the caller can fall back to raw
    syslog handling.
    """
    idx = line.find("CEF:")
    if idx < 0:
        return None
    body = line[idx:]
    # Split the 7 pipe-delimited header fields, honoring backslash escapes.
    parts = re.split(r"(?<!\\)\|", body, maxsplit=7)
    if len(parts) < 8:
        return None
    _, vendor, product, version, sig_id, name, severity, extension = parts[:8]
    ext: dict[str, str] = {}
    # Extension is space-separated key=value; values may contain spaces up to
    # the next " key=" token.
    for m in re.finditer(r"(\w+)=((?:[^=]|=(?!\w+=))*?)(?=\s+\w+=|$)", extension.strip()):
        ext[m.group(1)] = m.group(2).strip()
    return {
        "device_vendor": vendor.replace("\\|", "|"),
        "device_product": product.replace("\\|", "|"),
        "device_version": version,
        "signature_id": sig_id,
        "name": name.replace("\\|", "|"),
        "severity": severity,
        "ext": ext,
    }


class SyslogCefConnector(BaseConnector):
    """Generic syslog / CEF listener."""

    connector_id = "syslog_cef"
    connector_name = "Syslog / CEF"
    connector_category = "network"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Generic listener for appliances that speak syslog + ArcSight "
                "CEF. A syslog receiver writes messages to a spool endpoint; "
                "this connector parses the CEF header + extension and maps CEF "
                "severity (0-10) to the five-tier ladder. Non-CEF lines are "
                "ingested at info."
            ),
            docs_url="/docs/connectors/syslog_cef",
            fields=[
                Field("spool_url", "string", "Spool URL", placeholder="https://syslog-receiver.internal/spool"),
                Field("api_token", "secret", "Spool token"),
                Field("verify_tls", "boolean", "Verify TLS certificate", required=False, default=True),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.PULL_LOGS)

    def __init__(self, spool_url: str, api_token: str, verify_tls: bool = True) -> None:
        self._base = spool_url.rstrip("/")
        self._token = api_token
        self._verify = bool(verify_tls)

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify) as client:
                resp = await client.get(self._base, headers=self._headers(), params={"limit": 1})
            if resp.status_code == 200:
                return {"success": True, "connector": self.connector_id}
            return {"success": False, "connector": self.connector_id, "error": f"HTTP {resp.status_code}"}
        except Exception as exc:  # noqa: BLE001
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        try:
            async with httpx.AsyncClient(timeout=30.0, verify=self._verify) as client:
                resp = await client.get(self._base, headers=self._headers(), params={"limit": _LIMIT, "since": since_seconds})
            if resp.status_code != 200:
                logger.warning("syslog_cef.fetch_failed", status=resp.status_code)
                return out
            body = resp.json() or {}
            lines = body.get("messages") if isinstance(body, dict) else body
            for line in lines or []:
                # Each spool item is either a raw string or {"message": "..."}.
                msg = line.get("message") if isinstance(line, dict) else str(line)
                out.append(self.normalize({"message": msg, "_meta": line if isinstance(line, dict) else {}}))
        except Exception as exc:  # noqa: BLE001
            logger.warning("syslog_cef.fetch_error", error=str(exc))
        return out

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        message = raw.get("message") or ""
        cef = parse_cef(message)
        if cef is None:
            return {
                "source": self.connector_id,
                "category": self.connector_category,
                "severity": "info",
                "title": (message[:120] or "Syslog message"),
                "description": message[:500],
                "external_id": "",
                "event_type": "syslog_cef.raw",
                "raw": raw,
            }
        ext = cef["ext"]
        return {
            "source": self.connector_id,
            "category": self.connector_category,
            "severity": _cef_severity(cef["severity"]),
            "title": cef["name"] or f"{cef['device_vendor']} {cef['device_product']}",
            "description": (f"vendor={cef['device_vendor']}; product={cef['device_product']}; sig={cef['signature_id']}"),
            "external_id": cef["signature_id"],
            "src_ip": ext.get("src") or ext.get("sourceAddress"),
            "dst_ip": ext.get("dst") or ext.get("destinationAddress"),
            "username": ext.get("suser") or ext.get("sourceUserName"),
            "actor": ext.get("suser") or ext.get("sourceUserName"),
            "event_type": f"syslog_cef.{(cef['device_product'] or 'cef').lower().replace(' ', '_')}",
            "raw": raw,
        }
