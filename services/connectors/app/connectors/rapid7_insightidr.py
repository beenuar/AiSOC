"""
Rapid7 InsightIDR connector.

InsightIDR is Rapid7's cloud SIEM/XDR. We use the Investigations API and
the Log Search API.

Auth: API key (organization-scoped) on a region-specific base.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_REGION_HOSTS: dict[str, str] = {
    "us": "https://us.api.insight.rapid7.com",
    "us2": "https://us2.api.insight.rapid7.com",
    "us3": "https://us3.api.insight.rapid7.com",
    "eu": "https://eu.api.insight.rapid7.com",
    "ca": "https://ca.api.insight.rapid7.com",
    "au": "https://au.api.insight.rapid7.com",
    "ap": "https://ap.api.insight.rapid7.com",
}


class Rapid7InsightIDRConnector(BaseConnector):
    """Rapid7 InsightIDR — investigations + log search."""

    connector_id = "rapid7_insightidr"
    connector_name = "Rapid7 InsightIDR"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=("Rapid7 InsightIDR cloud SIEM/XDR. Pulls investigations and supports log search across collected sources."),
            docs_url="/docs/connectors/rapid7-insightidr",
            fields=[
                Field(
                    "region",
                    "select",
                    "Region",
                    options=[
                        {"value": "us", "label": "United States (us)"},
                        {"value": "us2", "label": "United States 2 (us2)"},
                        {"value": "us3", "label": "United States 3 (us3)"},
                        {"value": "eu", "label": "Europe (eu)"},
                        {"value": "ca", "label": "Canada (ca)"},
                        {"value": "au", "label": "Australia (au)"},
                        {"value": "ap", "label": "Asia Pacific (ap)"},
                    ],
                ),
                Field("api_key", "secret", "Insight API Key"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.PIVOT_HOST,
            Capability.PIVOT_USER,
        )

    def __init__(self, region: str, api_key: str):
        if region not in _REGION_HOSTS:
            raise ValueError(f"unknown InsightIDR region: {region!r}")
        self._region = region
        self._base = _REGION_HOSTS[region]
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        return {
            "X-Api-Key": self._api_key,
            "Accept-Version": "investigations-preview",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/idr/v2/investigations",
                    headers=self._headers(),
                    params={"size": 1},
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
        since_iso = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/idr/v2/investigations",
                    headers=self._headers(),
                    params={"start_time": since_iso, "size": 100, "sort": "created_time,desc"},
                )
                if resp.status_code != 200:
                    logger.warning(
                        "rapid7_insightidr.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = (resp.json() or {}).get("data") or []
                return [self.normalize(i) for i in items]
        except Exception as exc:
            logger.warning("rapid7_insightidr.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Rapid7 InsightIDR investigations carry priority
        # {LOW, MEDIUM, HIGH, CRITICAL, UNSPECIFIED}. Mirror critical
        # directly into AiSOC's five-tier severity ladder rather than
        # silently downgrading to ``info``.
        prio = (raw.get("priority") or "").lower()
        severity = prio if prio in ("info", "low", "medium", "high", "critical") else "info"
        return {
            "source": "rapid7_insightidr",
            "category": "siem",
            "severity": severity,
            "title": raw.get("title") or "InsightIDR investigation",
            "description": raw.get("disposition"),
            "alert_id": raw.get("rrn") or raw.get("id"),
            "host": None,
            "raw": raw,
        }
