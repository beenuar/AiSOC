"""
Google Chronicle (SecOps SIEM) connector.

Chronicle's modern API is the SecOps Chronicle API on Google Cloud
(`chronicle.googleapis.com`). Auth is via a service account JSON key.

For our self-describing schema we capture the project, customer ID,
region, and the service account JSON. Capability execution uses the
Chronicle SDK / google-auth at runtime.
"""

from __future__ import annotations

from typing import Any

import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

_REGION_CHOICES = [
    {"value": "us", "label": "United States (us)"},
    {"value": "europe", "label": "Europe (europe)"},
    {"value": "asia-southeast1", "label": "Asia Southeast 1 (asia-southeast1)"},
    {"value": "asia-northeast1", "label": "Asia Northeast 1 (asia-northeast1)"},
    {"value": "australia-southeast1", "label": "Australia Southeast 1"},
]


class ChronicleConnector(BaseConnector):
    """Google Chronicle SecOps SIEM."""

    connector_id = "chronicle"
    connector_name = "Google Chronicle"
    connector_category = "siem"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Google Chronicle SecOps SIEM. Pulls detections and supports "
                "UDM searches. Auth is via a Google Cloud service account JSON "
                "key with chronicle.* roles."
            ),
            docs_url="/docs/connectors/chronicle",
            fields=[
                Field("region", "select", "Region", options=_REGION_CHOICES),
                Field("project_id", "string", "GCP Project ID"),
                Field(
                    "customer_id",
                    "string",
                    "Chronicle Customer ID",
                    help_text="UUID of your Chronicle tenant.",
                ),
                Field(
                    "service_account_json",
                    "secret",
                    "Service Account JSON",
                    help_text="Paste the entire service-account JSON key.",
                ),
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

    def __init__(
        self,
        region: str,
        project_id: str,
        customer_id: str,
        service_account_json: str,
    ):
        self._region = region
        self._project_id = project_id
        self._customer_id = customer_id
        self._service_account_json = service_account_json

    async def test_connection(self) -> dict[str, Any]:
        # We don't pull google-auth into the cold-path connector layer for a
        # smoke test. The dispatcher / agent layer wires the SDK at runtime.
        # Here we only validate that we have the structural credentials.
        if not (self._project_id and self._customer_id and self._service_account_json):
            return {
                "success": False,
                "connector": self.connector_id,
                "error": "missing project_id, customer_id, or service_account_json",
            }
        return {
            "success": True,
            "connector": self.connector_id,
            "note": "structural validation only; full Chronicle SDK probe runs in agent layer",
        }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # Live alert ingestion happens via the agent runtime (Chronicle SDK).
        # Returning [] here keeps the connector cold-poll safe.
        return []

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        # Chronicle SecOps detections expose the standard
        # info/low/medium/high/critical ladder. Accept ``critical`` so
        # the highest-impact detections survive into AiSOC's
        # five-tier severity ladder.
        sev = (raw.get("severity") or "").lower()
        if sev not in ("info", "low", "medium", "high", "critical"):
            sev = "medium"
        return {
            "source": "chronicle",
            "category": "siem",
            "severity": sev,
            "title": raw.get("rule_name") or "Chronicle detection",
            "description": raw.get("description"),
            "alert_id": raw.get("id"),
            "host": None,
            "raw": raw,
        }
