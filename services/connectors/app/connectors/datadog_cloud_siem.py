"""
Datadog Cloud SIEM connector.

Datadog Cloud SIEM exposes Security Signals and supports log search.
Auth is via API Key + Application Key. The base host is region-specific.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_REGION_HOSTS: dict[str, str] = {
    "us1": "https://api.datadoghq.com",
    "us3": "https://api.us3.datadoghq.com",
    "us5": "https://api.us5.datadoghq.com",
    "eu1": "https://api.datadoghq.eu",
    "ap1": "https://api.ap1.datadoghq.com",
    "us1-fed": "https://api.ddog-gov.com",
}


class DatadogCloudSIEMConnector(BaseConnector):
    """Datadog Cloud SIEM."""

    connector_id = "datadog_cloud_siem"
    connector_name = "Datadog Cloud SIEM"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=("Datadog Cloud SIEM. Pulls Security Signals and supports log search across the Datadog logs platform."),
            docs_url="/docs/connectors/datadog-cloud-siem",
            fields=[
                Field(
                    "site",
                    "select",
                    "Datadog site",
                    options=[
                        {"value": "us1", "label": "US1 (datadoghq.com)"},
                        {"value": "us3", "label": "US3 (us3.datadoghq.com)"},
                        {"value": "us5", "label": "US5 (us5.datadoghq.com)"},
                        {"value": "eu1", "label": "EU1 (datadoghq.eu)"},
                        {"value": "ap1", "label": "AP1 (ap1.datadoghq.com)"},
                        {"value": "us1-fed", "label": "US1-FED (ddog-gov.com)"},
                    ],
                ),
                Field("api_key", "secret", "API Key"),
                Field("application_key", "secret", "Application Key"),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.PIVOT_HOST,
            Capability.PIVOT_USER,
            Capability.PIVOT_IP,
        )

    def __init__(self, site: str, api_key: str, application_key: str):
        if site not in _REGION_HOSTS:
            raise ValueError(f"unknown Datadog site: {site!r}")
        self._site = site
        self._base = _REGION_HOSTS[site]
        self._api_key = api_key
        self._app_key = application_key

    def _headers(self) -> dict[str, str]:
        return {
            "DD-API-KEY": self._api_key,
            "DD-APPLICATION-KEY": self._app_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/api/v2/security_monitoring/signals",
                    headers=self._headers(),
                    params={"page[limit]": 1},
                )
                if resp.status_code == 200:
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "site": self._site,
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/api/v2/security_monitoring/signals",
                    headers=self._headers(),
                    params={
                        "filter[from]": since,
                        "page[limit]": 100,
                        "sort": "-timestamp",
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "datadog_cloud_siem.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = (resp.json() or {}).get("data") or []
                return [self.normalize(i) for i in items]
        except Exception as exc:
            logger.warning("datadog_cloud_siem.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Datadog Cloud SIEM signal severities cover the standard
        # info/low/medium/high/critical ladder. Mirror critical directly
        # so the highest-impact signals survive into AiSOC's ladder
        # instead of being collapsed to high.
        attrs = raw.get("attributes") or {}
        sev_raw = (attrs.get("severity") or "").lower()
        sev = sev_raw if sev_raw in ("info", "low", "medium", "high", "critical") else "medium"
        title = attrs.get("title") or attrs.get("message") or "Datadog security signal"
        return {
            "source": "datadog_cloud_siem",
            "category": "siem",
            "severity": sev,
            "title": title,
            "description": attrs.get("message"),
            "alert_id": raw.get("id"),
            "host": None,
            "raw": raw,
        }
