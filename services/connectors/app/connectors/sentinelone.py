"""
SentinelOne connector.
Fetches threat detections from the SentinelOne Management Console API.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_PER_PAGE = 100
# Bound on pages per poll so a misbehaving cursor cannot loop forever.
_MAX_PAGES = 50

_SEVERITY_MAP = {
    "Undefined": "info",
    "Info": "info",
    "Low": "low",
    "Medium": "medium",
    "High": "high",
    # SentinelOne natively ships a ``Critical`` severity. Preserve it on the
    # AiSOC side so P1 EDR detections stay in the dedicated critical band
    # rather than getting collapsed into ``high``.
    "Critical": "critical",
}

# ``threatInfo.confidenceLevel`` is the agent's verdict, not a severity
# ladder: the API reports ``malicious`` or ``suspicious``. None of the keys
# above can match it, so without this map every threat landed on the
# ``medium`` default and a malicious detection ranked level with a
# suspicious one.
_CONFIDENCE_SEVERITY = {
    "malicious": "high",
    "suspicious": "medium",
}


def _severity(confidence: Any) -> str:
    value = str(confidence or "")
    return _CONFIDENCE_SEVERITY.get(value.lower()) or _SEVERITY_MAP.get(value, "medium")


class SentinelOneConnector(BaseConnector):
    connector_id = "sentinelone"
    connector_name = "SentinelOne"
    connector_category = "edr"

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Response actions are executed by services/actions SentinelOneClient
        # (contain_host / lift_containment / quarantine_file are all live). PID
        # kill + run_script are unsupported by the S1 API, so they're omitted.
        return (
            Capability.PULL_ALERTS,
            Capability.ISOLATE_HOST,
            Capability.UNISOLATE_HOST,
            Capability.QUARANTINE_FILE,
        )

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="SentinelOne threat detections via the Management Console API.",
            docs_url="/docs/connectors/sentinelone",
            fields=[
                Field("api_token", "secret", "API Token"),
                Field(
                    "base_url",
                    "string",
                    "Base URL",
                    placeholder="https://usea1-partners.sentinelone.net",
                ),
                Field(
                    "site_id",
                    "string",
                    "Site ID",
                    required=False,
                    help_text="Optional. Limits results to a single site.",
                ),
            ],
        )

    def __init__(self, api_token: str, base_url: str, site_id: str | None = None):
        self._api_token = api_token
        self._base_url = base_url.rstrip("/")
        self._site_id = site_id or None

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"APIToken {self._api_token}",
            "Accept": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base_url}/web/api/v2.1/system/info",
                    headers=self._headers(),
                )
                resp.raise_for_status()
                return {"success": True, "connector": self.connector_id}
        except Exception as exc:
            logger.warning("sentinelone.test_connection.failed", error=str(exc))
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
        params: dict[str, Any] = {
            "createdAt__gte": since,
            "limit": _PER_PAGE,
        }
        if self._site_id:
            params["siteIds"] = self._site_id

        threats: list[dict[str, Any]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            # The threats endpoint is cursor-paginated. Reading only the first
            # page dropped every threat past the 100th in a poll window, and the
            # next poll's window starts later, so those threats were never read.
            for _ in range(_MAX_PAGES):
                resp = await client.get(
                    f"{self._base_url}/web/api/v2.1/threats",
                    headers=self._headers(),
                    params=params,
                )
                resp.raise_for_status()
                body = resp.json()
                page = body.get("data") or []
                threats.extend(page)
                cursor = (body.get("pagination") or {}).get("nextCursor")
                if not cursor or not page:
                    break
                params["cursor"] = cursor
            else:
                logger.warning("sentinelone.fetch_alerts.page_cap_reached", pages=_MAX_PAGES, threats=len(threats))

        return [self.normalize(t) for t in threats]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        threat_info = raw.get("threatInfo", {})
        agent_info = raw.get("agentRealtimeInfo", {}) or raw.get("agentDetectionInfo", {})

        return {
            "source": self.connector_id,
            "external_id": raw.get("id", ""),
            "title": threat_info.get("threatName", "SentinelOne Threat"),
            "description": (
                f"{threat_info.get('classification', 'unknown')} — "
                f"{threat_info.get('threatName', 'unknown')} on "
                f"{agent_info.get('agentComputerName', 'unknown')}"
            ),
            "severity": _severity(threat_info.get("confidenceLevel")),
            "src_ip": agent_info.get("agentIpV4", agent_info.get("externalIp")),
            "hostname": agent_info.get("agentComputerName"),
            "actor": threat_info.get("processUser"),
            "raw_event": raw,
            "created_at": threat_info.get("createdAt"),
        }
