"""
Elastic Security / Elasticsearch client for SIEM response actions.

Supports: run ES|QL search, update watcher alert, create/update detection rule, enable/disable rule.

Credentials expected in ActionRequest.parameters:
    elastic_url: str          e.g. "https://my-cluster.es.io:9243"
    elastic_api_key: str      Base64-encoded API key ("id:api_key")
    elastic_username: str     (alternative to api_key)
    elastic_password: str
    kibana_url: str           e.g. "https://my-cluster.kb.io:9243"  (required for rules/watchers)
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class ElasticClient:
    """Async client for Elastic Security response actions."""

    def __init__(
        self,
        es_url: str,
        api_key: str | None = None,
        username: str | None = None,
        password: str | None = None,
        kibana_url: str | None = None,
    ) -> None:
        self._es_url = es_url.rstrip("/")
        self._kibana_url = (kibana_url or es_url).rstrip("/")
        self._api_key = api_key
        self._username = username
        self._password = password

    def _es_headers(self) -> dict[str, str]:
        if self._api_key:
            return {"Authorization": f"ApiKey {self._api_key}", "Content-Type": "application/json"}
        return {"Content-Type": "application/json"}

    def _auth(self) -> tuple[str, str] | None:
        if self._username and self._password:
            return (self._username, self._password)
        return None

    def _kibana_headers(self) -> dict[str, str]:
        headers = dict(self._es_headers())
        headers["kbn-xsrf"] = "true"
        return headers

    async def run_esql_search(
        self,
        query: str,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Execute an ES|QL query and return results as list of column-keyed dicts."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self._es_url}/_query",
                headers=self._es_headers(),
                auth=self._auth(),  # type: ignore[arg-type]
                json={"query": query, "accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
            columns = [col["name"] for col in data.get("columns", [])]
            rows = data.get("values", [])
            results = [dict(zip(columns, row, strict=False)) for row in rows]
            logger.info("elastic.esql.complete", query=query[:80], results=len(results))
            return results

    async def run_dsl_search(
        self,
        index: str,
        query: dict[str, Any],
        size: int = 500,
    ) -> list[dict[str, Any]]:
        """Execute a DSL search query and return hits."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(
                f"{self._es_url}/{index}/_search",
                headers=self._es_headers(),
                auth=self._auth(),  # type: ignore[arg-type]
                json={"query": query, "size": size},
            )
            resp.raise_for_status()
            hits = resp.json().get("hits", {}).get("hits", [])
            logger.info("elastic.dsl.complete", index=index, results=len(hits))
            return [h["_source"] for h in hits]

    async def create_or_update_detection_rule(
        self,
        rule_config: dict[str, Any],
    ) -> dict[str, Any]:
        """Create or update a detection rule in Kibana Security.

        rule_config must include at minimum: name, type, query (or other required fields per type).
        Upsert is done via rule_id if present.
        """
        rule_id = rule_config.get("rule_id")
        async with httpx.AsyncClient(timeout=30.0) as client:
            if rule_id:
                resp = await client.put(
                    f"{self._kibana_url}/api/detection_engine/rules",
                    headers=self._kibana_headers(),
                    auth=self._auth(),  # type: ignore[arg-type]
                    json=rule_config,
                )
            else:
                resp = await client.post(
                    f"{self._kibana_url}/api/detection_engine/rules",
                    headers=self._kibana_headers(),
                    auth=self._auth(),  # type: ignore[arg-type]
                    json=rule_config,
                )
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                "elastic.detection_rule.upserted",
                rule_name=rule_config.get("name"),
                rule_id=result.get("id"),
            )
            return {
                "success": True,
                "action": "upsert_detection_rule",
                "rule_id": result.get("id"),
                "rule_name": result.get("name"),
            }

    async def enable_detection_rule(self, rule_id: str) -> dict[str, Any]:
        """Enable a detection rule by ID."""
        return await self._toggle_rule(rule_id, enabled=True)

    async def disable_detection_rule(self, rule_id: str) -> dict[str, Any]:
        """Disable a detection rule by ID."""
        return await self._toggle_rule(rule_id, enabled=False)

    async def _toggle_rule(self, rule_id: str, enabled: bool) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.patch(
                f"{self._kibana_url}/api/detection_engine/rules",
                headers=self._kibana_headers(),
                auth=self._auth(),  # type: ignore[arg-type]
                json={"id": rule_id, "enabled": enabled},
            )
            resp.raise_for_status()
            logger.info("elastic.detection_rule.toggled", rule_id=rule_id, enabled=enabled)
            return {"success": True, "action": "toggle_detection_rule", "rule_id": rule_id, "enabled": enabled}

    async def update_watcher(self, watcher_id: str, watcher_body: dict[str, Any]) -> dict[str, Any]:
        """Create or update an Elasticsearch Watcher alert."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.put(
                f"{self._es_url}/_watcher/watch/{watcher_id}",
                headers=self._es_headers(),
                auth=self._auth(),  # type: ignore[arg-type]
                json=watcher_body,
            )
            resp.raise_for_status()
            logger.info("elastic.watcher.updated", watcher_id=watcher_id)
            return {"success": True, "action": "update_watcher", "watcher_id": watcher_id}

    async def activate_watcher(self, watcher_id: str) -> dict[str, Any]:
        """Activate an existing watcher."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.put(
                f"{self._es_url}/_watcher/watch/{watcher_id}/_activate",
                headers=self._es_headers(),
                auth=self._auth(),  # type: ignore[arg-type]
            )
            resp.raise_for_status()
            logger.info("elastic.watcher.activated", watcher_id=watcher_id)
            return {"success": True, "action": "activate_watcher", "watcher_id": watcher_id}

    async def deactivate_watcher(self, watcher_id: str) -> dict[str, Any]:
        """Deactivate an existing watcher."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.put(
                f"{self._es_url}/_watcher/watch/{watcher_id}/_deactivate",
                headers=self._es_headers(),
                auth=self._auth(),  # type: ignore[arg-type]
            )
            resp.raise_for_status()
            logger.info("elastic.watcher.deactivated", watcher_id=watcher_id)
            return {"success": True, "action": "deactivate_watcher", "watcher_id": watcher_id}

    # ──────────────────────────────────────────────────────────────
    # Phase 3.3 — alert lifecycle (ack + suppress)
    # ──────────────────────────────────────────────────────────────

    async def acknowledge_alert(self, signal_id: str) -> dict[str, Any]:
        """Mark an Elastic Security signal as in-progress.

        Elastic's "signal status" field on the ``.siem-signals-*``
        / ``.alerts-security.alerts-*`` indices uses
        ``open`` / ``acknowledged`` / ``closed``. We update the
        single signal by ID via the detection-engine status API
        (Kibana side) so the resulting state is visible in the
        Security app exactly as a manual UI ack would be.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._kibana_url}/api/detection_engine/signals/status",
                headers=self._kibana_headers(),
                auth=self._auth(),  # type: ignore[arg-type]
                json={"signal_ids": [signal_id], "status": "acknowledged"},
            )
            resp.raise_for_status()
            logger.info("elastic.alert.acknowledged", signal_id=signal_id)
            return {"success": True, "action": "acknowledge_alert", "signal_id": signal_id}

    async def close_alert(self, signal_id: str) -> dict[str, Any]:
        """Close (suppress) an Elastic Security signal.

        Sets status to ``closed`` so it drops out of the live
        triage queue. Like the Splunk suppress method, this is
        a one-way move from AiSOC's side; re-opening a closed
        alert must be done in the Kibana UI to avoid racing the
        analyst.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{self._kibana_url}/api/detection_engine/signals/status",
                headers=self._kibana_headers(),
                auth=self._auth(),  # type: ignore[arg-type]
                json={"signal_ids": [signal_id], "status": "closed"},
            )
            resp.raise_for_status()
            logger.info("elastic.alert.closed", signal_id=signal_id)
            return {"success": True, "action": "close_alert", "signal_id": signal_id}
