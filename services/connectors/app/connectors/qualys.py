"""Qualys VMDR connector.

Pulls detected vulnerabilities (host detections) from the Qualys VMDR API as an
alert stream. Qualys uses HTTP Basic auth against a regional API gateway
(e.g. https://qualysapi.qg2.apps.qualys.com).
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# Qualys severity is 1..5 (5 = most severe). Map to the AiSOC five-tier ladder;
# a native 5 stays critical rather than collapsing into high.
_SEVERITY_MAP = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}


class QualysConnector(BaseConnector):
    connector_id = "qualys"
    connector_name = "Qualys VMDR"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Qualys Vulnerability Management (VMDR) host detections as alerts.",
            docs_url="/docs/connectors/qualys",
            fields=[
                Field("base_url", "string", "API URL", placeholder="https://qualysapi.qg2.apps.qualys.com"),
                Field("username", "string", "API Username"),
                Field("password", "secret", "API Password"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (Capability.PULL_ALERTS, Capability.ENRICH_VULN, Capability.ENRICH_ASSET)

    def __init__(self, base_url: str, username: str, password: str):
        self._base = base_url.rstrip("/")
        self._auth = (username, password)

    def _headers(self) -> dict[str, str]:
        return {"X-Requested-With": "AiSOC", "Accept": "application/json"}

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, auth=self._auth) as client:
                resp = await client.get(
                    f"{self._base}/api/2.0/fo/activity_log/", headers=self._headers(), params={"action": "list", "truncation_limit": 1}
                )
                return {"success": resp.status_code < 400, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("qualys.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        try:
            async with httpx.AsyncClient(timeout=30.0, auth=self._auth) as client:
                resp = await client.get(
                    f"{self._base}/api/2.0/fo/asset/host/vm/detection/",
                    headers=self._headers(),
                    params={"action": "list", "severities": "4,5", "output_format": "JSON", "truncation_limit": 200},
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("qualys.fetch_failed", error=str(exc))
            return []
        hosts = _extract_host_list(data)
        return [self.normalize(d) for h in hosts for d in _host_detections(h)]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        if isinstance(raw, dict) and "raw_event" in raw and raw.get("source") == self.connector_id:
            return raw
        try:
            sev = _SEVERITY_MAP.get(int(raw.get("SEVERITY", raw.get("severity", 3))), "medium")
        except (TypeError, ValueError):
            sev = "medium"
        qid = raw.get("QID") or raw.get("qid")
        return {
            "source": self.connector_id,
            "external_id": str(qid) if qid else "",
            "title": raw.get("_title") or (f"Qualys QID {qid}" if qid else "Qualys detection"),
            "description": raw.get("RESULTS") or raw.get("results") or "",
            "severity": sev,
            "src_ip": raw.get("_ip"),
            "hostname": raw.get("_dns"),
            "raw_event": raw,
            "created_at": raw.get("LAST_FOUND_DATETIME") or raw.get("last_found_datetime"),
        }


def _extract_host_list(data: Any) -> list[dict[str, Any]]:
    try:
        hosts = data["ServiceResponse"]["data"]  # newer schema
    except (KeyError, TypeError):
        hosts = None
    if isinstance(hosts, list):
        return [h.get("HostAsset", h) if isinstance(h, dict) else {} for h in hosts]
    # Legacy: HOST_LIST_VM_DETECTION_OUTPUT
    try:
        raw_hosts = data["HOST_LIST_VM_DETECTION_OUTPUT"]["RESPONSE"]["HOST_LIST"]["HOST"]
    except (KeyError, TypeError):
        return []
    return raw_hosts if isinstance(raw_hosts, list) else [raw_hosts]


def _host_detections(host: dict[str, Any]) -> list[dict[str, Any]]:
    ip = host.get("IP") or host.get("address")
    dns = host.get("DNS") or host.get("dnsHostName")
    det = host.get("DETECTION_LIST", {}).get("DETECTION") if isinstance(host.get("DETECTION_LIST"), dict) else None
    dets = det if isinstance(det, list) else ([det] if isinstance(det, dict) else [host])
    for d in dets:
        if isinstance(d, dict):
            d["_ip"], d["_dns"] = ip, dns
    return [d for d in dets if isinstance(d, dict)]
