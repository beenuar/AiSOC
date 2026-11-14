"""
osctrl connector — open-source osquery fleet manager.

osctrl exposes a REST API under /api/v1 for node management, distributed
queries, and result retrieval. Auth is a long-lived API token issued from
the osctrl admin console (Manage Users -> generate token).

Why a dedicated connector (vs. routing through fleetdm) — osctrl is a
distinct project with a different data model (no "host status" bucketing,
flat node list, environment-scoped queries) and a different deployment
profile (often run by labs / smaller teams that explicitly chose
not-FleetDM). Treating them as separate first-class connectors keeps the
schema stable for both deployment patterns.

API references:
  https://osctrl.net/installation/      # admin token issuance
  https://osctrl.net/usage/             # /api/v1/queries, /api/v1/nodes
  https://osctrl.net/api/               # endpoint reference
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Severity mapping
#
# osctrl is a query/event platform — it does not emit "alerts" with vendor
# severity. We synthesise severity from the table queried so the rest of
# the AiSOC pipeline (which assumes events carry severity) has something
# to work with. Operators tune the mapping per environment via the
# detection layer; the defaults here just pick sensible "this is worth
# looking at by default" buckets.
#
# `medium` is the catch-all for "you asked for this query, here's a row" —
# we don't want to drown the SOC in `info` for routine inventory pulls,
# but we also don't want to escalate every row to `high` and burn alert
# budget. Detections in detections/endpoint/ promote interesting rows.
# ---------------------------------------------------------------------------

_OSCTRL_SEVERITY_BY_TABLE: dict[str, str] = {
    # Persistence + execution surfaces — high signal.
    "startup_items": "high",
    "scheduled_tasks": "high",
    "launchd": "high",
    "crontab": "high",
    "kernel_extensions": "high",
    "kernel_modules": "high",
    "browser_extensions": "high",
    # FIM — file_events is the canonical FIM table; severity bumps for
    # writes/deletes happen in detection rules, not here.
    "file_events": "medium",
    # Runtime telemetry — we treat these as `medium` so detections can
    # bubble specific rows up.
    "processes": "medium",
    "process_open_sockets": "medium",
    "listening_ports": "medium",
    "logged_in_users": "medium",
    # Pure inventory — low by default, detections promote.
    "system_info": "info",
    "os_version": "info",
    "uptime": "info",
}


def _osctrl_severity(table: str | None) -> str:
    if not table:
        return "medium"
    return _OSCTRL_SEVERITY_BY_TABLE.get(table.strip().lower(), "medium")


class OsctrlConnector(BaseConnector):
    """osctrl — open-source osquery fleet manager."""

    connector_id = "osctrl"
    connector_name = "osctrl"
    connector_category = "edr"

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # PR1 declares the read + query verbs. The ad-hoc live-query verb
        # (QUERY_PROCESSES) is the bridge into PR3 — the action client
        # uses the same auth + base URL to issue distributed queries.
        return (
            Capability.PULL_LOGS,
            Capability.QUERY_LOGS,
            Capability.QUERY_PROCESSES,
            Capability.PIVOT_HOST,
        )

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=("osctrl — open-source osquery fleet manager. Pulls query results and node telemetry from the osctrl admin API."),
            docs_url="/docs/connectors/osctrl",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "osctrl Admin URL",
                    placeholder="https://osctrl.example.com",
                    help_text=("Base URL of the osctrl admin server (no trailing slash). Use https in production."),
                ),
                Field(
                    "api_token",
                    "secret",
                    "API Token",
                    help_text=("Long-lived admin token issued from the osctrl UI under Manage Users -> generate token."),
                ),
                Field(
                    "environment",
                    "string",
                    "Environment Name",
                    required=False,
                    default="prod",
                    help_text=("osctrl environment to scope queries to (e.g. 'prod', 'corp'). Required for distributed queries."),
                ),
                Field(
                    "verify_tls",
                    "boolean",
                    "Verify TLS Certificate",
                    required=False,
                    default=True,
                ),
            ],
        )

    def __init__(
        self,
        base_url: str,
        api_token: str,
        environment: str = "prod",
        verify_tls: bool = True,
    ):
        # Strip trailing slash so URL composition is predictable. osctrl
        # paths begin with /api/v1; double-slash works but looks alarming
        # in audit logs.
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._environment = environment or "prod"
        self._verify_tls = bool(verify_tls)

    # ---- helpers ------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
            "User-Agent": "AiSOC/connectors-osctrl",
        }

    # ---- runtime ------------------------------------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify_tls) as client:
                resp = await client.get(
                    f"{self._base_url}/api/v1/nodes",
                    headers=self._headers(),
                )
            if resp.status_code == 200:
                return {"success": True, "connector": self.connector_id}
            if resp.status_code in (401, 403):
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": "authentication failed; check api_token",
                }
            return {
                "success": False,
                "connector": self.connector_id,
                "error": f"unexpected status {resp.status_code}",
            }
        except httpx.RequestError as exc:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": f"network error: {exc}",
            }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """Pull recent query results.

        osctrl persists distributed-query results under
        ``/api/v1/queries/<env>/results/<query_id>``. Listing all results
        across all queries in one shot is expensive; instead we ask for
        the most recent N completed queries in this environment and pull
        their result rows.

        ``since_seconds`` is honoured client-side because osctrl's list
        endpoint returns a `created_at` field but does not accept a
        server-side filter.
        """
        results: list[dict[str, Any]] = []
        cutoff_epoch = datetime.now(UTC).timestamp() - max(since_seconds, 0)

        try:
            async with httpx.AsyncClient(timeout=30.0, verify=self._verify_tls) as client:
                queries_resp = await client.get(
                    f"{self._base_url}/api/v1/queries/{self._environment}/list",
                    headers=self._headers(),
                )
                if queries_resp.status_code != 200:
                    logger.warning(
                        "osctrl.queries_list_failed",
                        status=queries_resp.status_code,
                        body=queries_resp.text[:300],
                    )
                    return []

                queries = queries_resp.json() or []
                if not isinstance(queries, list):
                    queries = (queries or {}).get("queries") or []

                for q in queries[:100]:
                    created_at = _parse_epoch(q.get("created_at"))
                    if created_at is not None and created_at < cutoff_epoch:
                        continue

                    qname = q.get("name") or q.get("query_name") or q.get("uuid")
                    if not qname:
                        continue

                    results_resp = await client.get(
                        f"{self._base_url}/api/v1/queries/{self._environment}/results/{qname}",
                        headers=self._headers(),
                    )
                    if results_resp.status_code != 200:
                        continue

                    payload = results_resp.json() or {}
                    rows = payload.get("results") if isinstance(payload, dict) else payload
                    if not isinstance(rows, list):
                        continue

                    for row in rows:
                        results.append(
                            self.normalize(
                                {
                                    "query": q,
                                    "row": row,
                                    "environment": self._environment,
                                }
                            )
                        )
        except httpx.RequestError as exc:
            logger.warning("osctrl.fetch_exception", error=str(exc))
            return []

        return results

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        query = raw.get("query") or {}
        row = raw.get("row") or {}
        table_name = query.get("query_table") or _infer_table(query.get("query"))

        hostname = row.get("hostname") or row.get("host_identifier") or row.get("computer_name")

        # Flatten osquery row columns to the top level so detection
        # rules can reference them directly in match_when clauses
        # (the matcher only reads top-level fields). We start with the
        # row dict and let the AiSOC-canonical fields below win on
        # collision so source/category/severity stay correct.
        event: dict[str, Any] = {}
        if isinstance(row, dict):
            event.update(row)
        event.update(
            {
                "source": self.connector_id,
                "category": "endpoint",
                "event_type": "osquery_query_row",
                "severity": _osctrl_severity(table_name),
                "title": (f"osctrl query: {query.get('name') or query.get('uuid') or 'distributed-query'}"),
                "description": (query.get("query") or "")[:400],
                "alert_id": (f"{query.get('name') or 'q'}::{row.get('uuid') or row.get('host_identifier') or ''}"),
                "hostname": hostname,
                "host": hostname,
                "external_id": query.get("uuid"),
                "osquery_table": table_name,
                "query_name": query.get("name") or query.get("query_name"),
                "raw_event": row,
                "raw": raw,
            }
        )
        return event


# ---------------------------------------------------------------------------
# Helpers — kept module-private so the connector class stays focused.
# ---------------------------------------------------------------------------


def _parse_epoch(value: Any) -> float | None:
    """Best-effort conversion of osctrl's `created_at` to epoch seconds."""
    if value is None:
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def _infer_table(query_sql: str | None) -> str | None:
    """Pull the FROM table out of an osquery SQL fragment.

    osctrl exposes the raw SQL of the query, not a parsed table name.
    We use a tiny heuristic — the first identifier after FROM — so we
    can populate ``osquery_table`` for downstream severity routing.
    """
    if not query_sql:
        return None
    lower = query_sql.lower()
    idx = lower.find(" from ")
    if idx < 0:
        return None
    rest = query_sql[idx + len(" from ") :].strip()
    token = rest.split()[0] if rest else ""
    return token.strip(",;()`'\"") or None
