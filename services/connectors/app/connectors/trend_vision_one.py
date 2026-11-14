"""
Trend Micro Vision One (XDR) connector.

Vision One is Trend's XDR platform with several feeds. We expose:

1. **Workbench alerts** — ``GET /v3.0/workbench/alerts`` (correlated cases).
2. **Detection events** — ``GET /v3.0/oat/detections`` (Observed Attack Techniques).
3. **Endpoint inventory + isolation** — ``POST /v3.0/response/endpoints/{action}``
   for ISOLATE / UNISOLATE.

Auth: Bearer token. Trend regions are explicit hostnames — pick from the
dropdown to match your console region.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors._paging import read_linked_pages
from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_REGION_HOSTS: dict[str, str] = {
    "us": "https://api.xdr.trendmicro.com",
    "eu": "https://api.eu.xdr.trendmicro.com",
    "in": "https://api.in.xdr.trendmicro.com",
    "jp": "https://api.xdr.trendmicro.co.jp",
    "sg": "https://api.sg.xdr.trendmicro.com",
    "au": "https://api.au.xdr.trendmicro.com",
}


class TrendVisionOneConnector(BaseConnector):
    """Trend Micro Vision One XDR — alerts + OAT detections + endpoint actions."""

    connector_id = "trend_vision_one"
    connector_name = "Trend Vision One"
    connector_category = "edr"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Trend Micro Vision One XDR. Pulls Workbench alerts and OAT "
                "(Observed Attack Technique) detections. Supports endpoint "
                "isolation as an agent capability."
            ),
            docs_url="/docs/connectors/trend-vision-one",
            fields=[
                Field(
                    "region",
                    "select",
                    "Region",
                    options=[
                        {"value": "us", "label": "United States"},
                        {"value": "eu", "label": "Europe"},
                        {"value": "in", "label": "India"},
                        {"value": "jp", "label": "Japan"},
                        {"value": "sg", "label": "Singapore"},
                        {"value": "au", "label": "Australia"},
                    ],
                    help_text="Vision One has region-specific hostnames; using the wrong one returns 401.",
                ),
                Field(
                    "api_token",
                    "secret",
                    "API Token",
                    help_text=("Bearer token issued from Vision One console: Administration → API Keys."),
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.PULL_AUDIT,
            Capability.PIVOT_HOST,
            Capability.ISOLATE_HOST,
            Capability.UNISOLATE_HOST,
        )

    def __init__(self, region: str, api_token: str):
        if region not in _REGION_HOSTS:
            raise ValueError(f"unknown Trend Vision One region: {region!r}")
        self._region = region
        self._base = _REGION_HOSTS[region]
        self._api_token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Content-Type": "application/json;charset=utf-8",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/v3.0/workbench/alerts",
                    headers=self._headers(),
                    params={"top": 1},
                )
                if resp.status_code == 200:
                    return {"success": True, "connector": self.connector_id, "region": self._region}
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = datetime.now(UTC) - timedelta(seconds=since_seconds)
        since_iso = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        events: list[dict[str, Any]] = []

        # Both feeds answer a capped page plus ``nextLink``, the complete URL of
        # the next one, and Trend's own SDK keeps requesting it until it is no
        # longer returned. The poll window opens where the last one closed, so a
        # page left unread here is never requested again.
        feeds = (
            (
                "workbench",
                "/v3.0/workbench/alerts",
                {"startDateTime": since_iso, "top": 100, "orderBy": "createdDateTime"},
            ),
            ("oat", "/v3.0/oat/detections", {"detectedStartDateTime": since_iso, "top": 100}),
        )
        async with httpx.AsyncClient(timeout=30.0) as client:
            for stream, path, params in feeds:
                try:
                    first = await client.get(f"{self._base}{path}", headers=self._headers(), params=params)
                    if first.status_code != 200:
                        logger.warning(
                            "trend_vision_one.feed_failed",
                            stream=stream,
                            status=first.status_code,
                            body=first.text[:300],
                        )
                        continue
                    items = await read_linked_pages(
                        client,
                        first,
                        link_field="nextLink",
                        items_field="items",
                        headers=self._headers(),
                        feed=f"trend_vision_one.{stream}",
                    )
                except Exception as exc:
                    logger.warning("trend_vision_one.feed_exception", stream=stream, error=str(exc))
                    continue
                for item in items:
                    item["_aisoc_stream"] = stream
                    events.append(item)

        return [self.normalize(e) for e in events]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Trend Vision One workbench alerts and Observed Attack Techniques
        # expose a 4- or 5-tier severity. Mirror critical → critical so the
        # highest-impact detections survive into AiSOC's ladder instead of
        # being downgraded to high.
        sev_raw = (raw.get("severity") or raw.get("riskLevel") or "").lower()
        if sev_raw == "critical":
            severity = "critical"
        elif sev_raw == "high":
            severity = "high"
        elif sev_raw == "medium":
            severity = "medium"
        elif sev_raw == "low":
            severity = "low"
        else:
            severity = "info"
        title = raw.get("model") or raw.get("eventName") or "Trend Vision One detection"
        return {
            "source": "trend_vision_one",
            "category": "edr",
            "severity": severity,
            "title": title,
            "description": raw.get("description"),
            "alert_id": raw.get("id") or raw.get("uuid"),
            "host": (raw.get("impactScope") or {}).get("entityValue"),
            "raw_event": raw,
        }
