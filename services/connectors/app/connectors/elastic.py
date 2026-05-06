"""
Elastic SIEM connector.

Federated-search-first: the Elastic deployments most AiSOC customers run today
already have their own native dashboards and pipelines for alert ingestion, so
this connector exists primarily to give the federated layer a way to run ES|QL
against the customer's existing Elasticsearch cluster without exfiltrating logs
into AiSOC's own data plane.

``fetch_alerts`` is intentionally a thin wrapper over ES|QL on the
``.alerts-security.alerts-*`` index pattern so a tenant who *does* want
Elastic-side alerts to flow into the fusion engine can opt in by enabling the
connector's poll schedule.
"""

from __future__ import annotations

import base64
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, ConnectorSchema, Field
from app.federated.query import UnifiedQuery
from app.federated.translators import to_esql

logger = structlog.get_logger()


class ElasticConnector(BaseConnector):
    connector_id = "elastic"
    connector_name = "Elastic SIEM"
    connector_category = "siem"
    supports_federated_search = True

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Elastic Security via the ES|QL search API. Federated-search ready.",
            docs_url="/docs/connectors/elastic",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Elasticsearch URL",
                    placeholder="https://elastic.example.com:9200",
                    help_text="Cluster endpoint, not Kibana.",
                ),
                Field("api_key", "secret", "API Key", required=False),
                Field("username", "string", "Username", required=False),
                Field("password", "secret", "Password", required=False),
                Field(
                    "index",
                    "string",
                    "Default Index Pattern",
                    required=False,
                    default="logs-*",
                ),
                Field(
                    "ssl_verify",
                    "boolean",
                    "Verify SSL certificate",
                    required=False,
                    default=True,
                    help_text="Disable only for self-signed certificates in private deployments.",
                ),
            ],
        )

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        index: str = "logs-*",
        ssl_verify: bool = True,
    ):
        if not api_key and not (username and password):
            raise ValueError("Elastic connector requires either api_key or username+password")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._username = username
        self._password = password
        self._index = index
        self._ssl_verify = ssl_verify

    def _headers(self) -> dict[str, str]:
        if self._api_key:
            return {
                "Authorization": f"ApiKey {self._api_key}",
                "Content-Type": "application/json",
            }
        # Basic auth fallback for older self-hosted deployments.
        token = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
        return {
            "Authorization": f"Basic {token}",
            "Content-Type": "application/json",
        }

    async def test_connection(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0, verify=self._ssl_verify) as client:
            try:
                resp = await client.get(f"{self._base_url}/", headers=self._headers())
                resp.raise_for_status()
                info = resp.json()
                return {
                    "success": True,
                    "connector": self.connector_id,
                    "version": info.get("version", {}).get("number"),
                    "cluster_name": info.get("cluster_name"),
                }
            except Exception as exc:
                logger.warning("elastic.test_connection.failed", error_type=type(exc).__name__)
                return {"success": False, "connector": self.connector_id, "error": "Connection failed"}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        # Elastic Security stores detection rule alerts in this hidden index pattern.
        esql = f"FROM .alerts-security.alerts-* | WHERE @timestamp > NOW() - {since_seconds} seconds | LIMIT 100"
        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            resp = await client.post(
                f"{self._base_url}/_query",
                headers=self._headers(),
                json={"query": esql},
            )
            resp.raise_for_status()
            data = resp.json()

        rows = self._rows_from_esql(data)
        return [self.normalize(r) for r in rows]

    async def query(self, unified: UnifiedQuery) -> list[dict[str, Any]]:
        """Run a translated ES|QL query and return raw rows.

        Mirrors the Splunk and Sentinel implementations: rows go back to the
        API layer untouched so the federated merger can tag each one with the
        originating connector id.
        """
        esql = to_esql(unified, index=self._index)
        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            resp = await client.post(
                f"{self._base_url}/_query",
                headers=self._headers(),
                json={"query": esql},
            )
            resp.raise_for_status()
            data = resp.json()
        return self._rows_from_esql(data)

    @staticmethod
    def _rows_from_esql(data: dict[str, Any]) -> list[dict[str, Any]]:
        """Flatten the ES|QL ``columns``/``values`` shape into row dicts.

        ES|QL responses look like::

            {
              "columns": [{"name": "@timestamp", "type": "date"}, ...],
              "values": [["2026-05-01T00:00:00Z", ...], ...]
            }

        We zip them together so the API layer never has to know the shape.
        """
        columns = [c.get("name") for c in data.get("columns", [])]
        values = data.get("values", [])
        return [dict(zip(columns, row, strict=False)) for row in values]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        severity_map = {"low": "low", "medium": "medium", "high": "high", "critical": "high"}
        severity = str(raw.get("kibana.alert.severity") or raw.get("severity") or "medium").lower()
        return {
            "source": self.connector_id,
            "external_id": raw.get("kibana.alert.uuid") or raw.get("_id", ""),
            "title": raw.get("kibana.alert.rule.name") or raw.get("rule.name") or "Elastic Alert",
            "description": raw.get("kibana.alert.reason") or raw.get("message", ""),
            "severity": severity_map.get(severity, "medium"),
            "raw_event": raw,
            "created_at": raw.get("@timestamp"),
        }
