"""
Splunk connector.
Runs saved searches and fetches notable events from Splunk SIEM.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field
from app.federated.query import UnifiedQuery
from app.federated.translators import to_spl

logger = structlog.get_logger()


class SplunkConnector(BaseConnector):
    connector_id = "splunk"
    connector_name = "Splunk SIEM"
    connector_category = "siem"
    supports_federated_search = True

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="Splunk Enterprise / Cloud notable events via the REST API.",
            docs_url="/docs/connectors/splunk",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Splunk URL",
                    placeholder="https://splunk.example.com:8089",
                    help_text="Management port (default 8089), not the web UI port.",
                ),
                Field("token", "secret", "HEC / API Token"),
                Field(
                    "saved_search",
                    "string",
                    "Saved Search Name",
                    required=False,
                    default="AiSOC_Alerts",
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

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Splunk surfaces notable events (alerts) and supports federated SPL
        # search over indexes — the latter maps to QUERY_LOGS.
        # WS-E5: Live Splunk REST API response actions now wired
        # via services/actions/app/clients/splunk_client.py
        return (
            Capability.PULL_ALERTS,
            Capability.QUERY_LOGS,
            Capability.SEARCH_SIEM,
            Capability.CREATE_NOTABLE_EVENT,
        )

    def __init__(
        self,
        base_url: str,
        token: str,
        saved_search: str = "AiSOC_Alerts",
        ssl_verify: bool = True,
    ):
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._saved_search = saved_search
        self._ssl_verify = ssl_verify

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/x-www-form-urlencoded",
        }

    async def test_connection(self) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=15.0, verify=self._ssl_verify) as client:
            try:
                resp = await client.get(
                    f"{self._base_url}/services/server/info",
                    headers=self._headers(),
                    params={"output_mode": "json"},
                )
                resp.raise_for_status()
                version = resp.json().get("entry", [{}])[0].get("content", {}).get("version")
                return {"success": True, "connector": self.connector_id, "version": version}
            except Exception as exc:
                logger.warning("splunk.test_connection.failed", error_type=type(exc).__name__)
                return {"success": False, "connector": self.connector_id, "error": "Connection failed"}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        search_query = f"search index=notable earliest=-{since_seconds}s | head 100"

        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            # Create search job
            resp = await client.post(
                f"{self._base_url}/services/search/jobs",
                headers=self._headers(),
                data={"search": search_query, "output_mode": "json"},
            )
            resp.raise_for_status()
            sid = resp.json().get("sid")

            if not sid:
                return []

            # Wait for completion (simple polling)
            import asyncio

            for _ in range(10):
                status_resp = await client.get(
                    f"{self._base_url}/services/search/jobs/{sid}",
                    headers=self._headers(),
                    params={"output_mode": "json"},
                )
                dispatch_state = status_resp.json().get("entry", [{}])[0].get("content", {}).get("dispatchState", "")
                if dispatch_state == "DONE":
                    break
                await asyncio.sleep(2)

            # Fetch results
            results_resp = await client.get(
                f"{self._base_url}/services/search/jobs/{sid}/results",
                headers=self._headers(),
                params={"output_mode": "json", "count": 100},
            )
            results_resp.raise_for_status()
            results = results_resp.json().get("results", [])

        return [self.normalize(r) for r in results]

    async def query(self, unified: UnifiedQuery) -> list[dict[str, Any]]:
        """Run a translated SPL search and return raw rows.

        We deliberately do *not* call ``normalize`` here because federated
        search returns rows for analyst pivoting, not alerts that should
        flow into the fusion engine. The API layer wraps each row with
        connector identity so downstream consumers can tell sources apart.
        """
        index = self._saved_search if self._saved_search.startswith("index=") else "notable"
        spl = to_spl(unified, index=index)
        async with httpx.AsyncClient(timeout=60.0, verify=self._ssl_verify) as client:
            resp = await client.post(
                f"{self._base_url}/services/search/jobs",
                headers=self._headers(),
                data={"search": spl, "output_mode": "json", "exec_mode": "oneshot"},
            )
            resp.raise_for_status()
            return list(resp.json().get("results", []))

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        urgency_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "info"}
        return {
            "source": self.connector_id,
            "external_id": raw.get("event_id", raw.get("_cd", "")),
            "title": raw.get("source", "Splunk Notable Event"),
            "description": raw.get("description", ""),
            "severity": urgency_map.get(raw.get("urgency", "medium"), "medium"),
            "src_ip": raw.get("src", raw.get("src_ip")),
            "hostname": raw.get("host"),
            "raw_event": raw,
            "created_at": raw.get("_time"),
        }
