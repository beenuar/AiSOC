"""
Sumo Logic Cloud SIEM connector.

Sumo Logic CSE has a dedicated SIEM API at https://api.<deployment>.sumologic.com/api/sec/v1
Auth: HTTP Basic with access ID + access key.

We pull insights/signals and support search jobs against the platform's
log store.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_DEPLOYMENT_HOSTS: dict[str, str] = {
    "us1": "https://api.sumologic.com",
    "us2": "https://api.us2.sumologic.com",
    "eu": "https://api.eu.sumologic.com",
    "au": "https://api.au.sumologic.com",
    "de": "https://api.de.sumologic.com",
    "jp": "https://api.jp.sumologic.com",
    "ca": "https://api.ca.sumologic.com",
    "in": "https://api.in.sumologic.com",
    "fed": "https://api.fed.sumologic.com",
}


class SumoLogicConnector(BaseConnector):
    """Sumo Logic Cloud SIEM Enterprise (CSE)."""

    connector_id = "sumo_logic"
    connector_name = "Sumo Logic Cloud SIEM"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Sumo Logic Cloud SIEM Enterprise (CSE). Pulls insights and signals, and supports log search jobs across the platform."
            ),
            docs_url="/docs/connectors/sumo-logic",
            fields=[
                Field(
                    "deployment",
                    "select",
                    "Deployment",
                    options=[
                        {"value": "us1", "label": "United States (us1)"},
                        {"value": "us2", "label": "United States 2 (us2)"},
                        {"value": "eu", "label": "Europe (eu)"},
                        {"value": "au", "label": "Australia (au)"},
                        {"value": "de", "label": "Germany (de)"},
                        {"value": "jp", "label": "Japan (jp)"},
                        {"value": "ca", "label": "Canada (ca)"},
                        {"value": "in", "label": "India (in)"},
                        {"value": "fed", "label": "Sumo Logic FedRAMP (fed)"},
                    ],
                ),
                Field("access_id", "string", "Access ID"),
                Field("access_key", "secret", "Access Key"),
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

    def __init__(self, deployment: str, access_id: str, access_key: str):
        if deployment not in _DEPLOYMENT_HOSTS:
            raise ValueError(f"unknown Sumo Logic deployment: {deployment!r}")
        self._deployment = deployment
        self._base = _DEPLOYMENT_HOSTS[deployment]
        self._access_id = access_id
        self._access_key = access_key

    def _headers(self) -> dict[str, str]:
        token = base64.b64encode(f"{self._access_id}:{self._access_key}".encode()).decode()
        return {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base}/api/sec/v1/insights",
                    headers=self._headers(),
                    params={"limit": 1},
                )
                if resp.status_code == 200:
                    return {
                        "success": True,
                        "connector": self.connector_id,
                        "deployment": self._deployment,
                    }
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": f"HTTP {resp.status_code}: {resp.text[:300]}",
                }
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        since_iso = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%S")
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base}/api/sec/v1/insights",
                    headers=self._headers(),
                    params={"q": f"created:>{since_iso}", "limit": 100},
                )
                if resp.status_code != 200:
                    logger.warning(
                        "sumo_logic.fetch_failed",
                        status=resp.status_code,
                        body=resp.text[:300],
                    )
                    return []
                items = (resp.json() or {}).get("data", {}).get("objects") or []
                return [self.normalize(i) for i in items]
        except Exception as exc:
            logger.warning("sumo_logic.fetch_exception", error=str(exc))
            return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Sumo Logic Cloud SIEM insights carry severity {info, low, medium,
        # high, critical}. Accept critical so genuine critical insights
        # survive AiSOC's five-tier severity ladder.
        sev_raw = (raw.get("severity") or "").lower()
        sev = sev_raw if sev_raw in ("info", "low", "medium", "high", "critical") else "medium"
        return {
            "source": "sumo_logic",
            "category": "siem",
            "severity": sev,
            "title": raw.get("name") or "Sumo Logic CSE insight",
            "description": raw.get("description"),
            "alert_id": raw.get("id"),
            "host": None,
            "raw": raw,
        }
