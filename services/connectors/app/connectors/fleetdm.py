"""
FleetDM connector — commercial-grade osquery fleet manager.

FleetDM exposes a versioned REST API under ``/api/v1/fleet`` (alias
``/api/latest/fleet``) authenticated with a long-lived API token from a
service-account user.

The two telemetry surfaces we care about for v1 are:

  * ``GET /api/v1/fleet/hosts`` — host inventory + posture (online/offline,
    last_seen, gigs free, OS/version, MDM enrolment).
  * ``GET /api/v1/fleet/queries/<id>/report`` — saved-query result rows
    aggregated across hosts.

PR1 wires up read-only fetch + normalize. The action client in PR3 layers
the live-query verb (``POST /api/v1/fleet/queries/run``) on top of the
same auth surface, which is why ``QUERY_PROCESSES`` is declared here.

API references:
  https://fleetdm.com/docs/rest-api/rest-api
  https://fleetdm.com/docs/using-fleet/api-versioning
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


# ---------------------------------------------------------------------------
# FleetDM host status -> AiSOC severity
#
# FleetDM does not stream "alerts" in the traditional sense — its primary
# signal at the host level is the ``status`` field (online / offline /
# missing / new). We map host posture changes into the four-tier ladder
# so downstream detections can fire on transitions ("host went missing")
# without having to special-case the connector.
#
# Saved-query report rows reuse the same severity logic as osctrl
# (table-driven, defaults to medium) — see _table_severity.
# ---------------------------------------------------------------------------

_FLEET_HOST_STATUS_SEVERITY: dict[str, str] = {
    "online": "info",
    "new": "info",
    "offline": "low",
    "missing": "medium",
    "mia": "medium",
}

_FLEET_TABLE_SEVERITY: dict[str, str] = {
    # Persistence
    "startup_items": "high",
    "scheduled_tasks": "high",
    "launchd": "high",
    "crontab": "high",
    "kernel_extensions": "high",
    "kernel_modules": "high",
    "browser_extensions": "high",
    # FIM
    "file_events": "medium",
    # Runtime
    "processes": "medium",
    "process_open_sockets": "medium",
    "listening_ports": "medium",
    "logged_in_users": "medium",
    # Inventory
    "system_info": "info",
    "os_version": "info",
    "uptime": "info",
}


def _table_severity(table: str | None) -> str:
    if not table:
        return "medium"
    return _FLEET_TABLE_SEVERITY.get(table.strip().lower(), "medium")


def _host_status_severity(status: str | None) -> str:
    if not status:
        return "info"
    return _FLEET_HOST_STATUS_SEVERITY.get(status.strip().lower(), "info")


class FleetDMConnector(BaseConnector):
    """FleetDM — osquery fleet manager (commercial-friendly OSS)."""

    connector_id = "fleetdm"
    connector_name = "FleetDM"
    connector_category = "edr"

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
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
            description=("FleetDM — osquery fleet manager. Pulls host posture and saved-query results from the Fleet REST API."),
            docs_url="/docs/connectors/fleetdm",
            fields=[
                Field(
                    "base_url",
                    "string",
                    "Fleet Server URL",
                    placeholder="https://fleet.example.com",
                    help_text=("Base URL of the Fleet server (no trailing slash). The /api prefix is added automatically."),
                ),
                Field(
                    "api_token",
                    "secret",
                    "API Token",
                    help_text=("Long-lived token issued from the Fleet UI under Settings -> Users -> [user] -> Get API token."),
                ),
                Field(
                    "team_id",
                    "string",
                    "Team ID",
                    required=False,
                    help_text=("Optional Fleet Team ID to scope queries to. Leave empty to span all teams."),
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
        team_id: str | None = None,
        verify_tls: bool = True,
    ):
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._team_id = team_id or None
        self._verify_tls = bool(verify_tls)

    # ---- helpers ------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
            "User-Agent": "AiSOC/connectors-fleetdm",
        }

    # ---- runtime ------------------------------------------------------

    async def test_connection(self) -> dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15.0, verify=self._verify_tls) as client:
                resp = await client.get(
                    f"{self._base_url}/api/v1/fleet/me",
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
        """Pull host posture changes + recent saved-query report rows.

        We deliberately fetch *both* surfaces in a single poll so the SOC
        sees host-level signals (offline/missing) alongside query
        evidence rows. The two are clearly tagged via ``raw_event.kind``
        for downstream routing.
        """
        events: list[dict[str, Any]] = []
        cutoff = datetime.now(UTC).timestamp() - max(since_seconds, 0)
        params: dict[str, str] = {"per_page": "200"}
        if self._team_id:
            params["team_id"] = self._team_id

        try:
            async with httpx.AsyncClient(timeout=30.0, verify=self._verify_tls) as client:
                # ---- hosts -----------------------------------------
                hosts_resp = await client.get(
                    f"{self._base_url}/api/v1/fleet/hosts",
                    headers=self._headers(),
                    params=params,
                )
                if hosts_resp.status_code == 200:
                    body = hosts_resp.json() or {}
                    hosts = body.get("hosts") if isinstance(body, dict) else []
                    if isinstance(hosts, list):
                        for host in hosts:
                            seen = _parse_iso(host.get("seen_time"))
                            # Only emit hosts that changed within the
                            # window. We fall back to including the host
                            # when seen_time is missing rather than drop
                            # signal.
                            if seen is not None and seen < cutoff:
                                continue
                            events.append(self.normalize({"kind": "host", "host": host}))
                else:
                    logger.warning(
                        "fleetdm.hosts_fetch_failed",
                        status=hosts_resp.status_code,
                        body=hosts_resp.text[:300],
                    )

                # ---- saved-query reports ---------------------------
                queries_resp = await client.get(
                    f"{self._base_url}/api/v1/fleet/queries",
                    headers=self._headers(),
                    params={"per_page": "100", **({"team_id": self._team_id} if self._team_id else {})},
                )
                if queries_resp.status_code == 200:
                    qbody = queries_resp.json() or {}
                    queries = qbody.get("queries") if isinstance(qbody, dict) else []
                    if isinstance(queries, list):
                        for q in queries[:50]:
                            qid = q.get("id")
                            if qid is None:
                                continue
                            rep_resp = await client.get(
                                f"{self._base_url}/api/v1/fleet/queries/{qid}/report",
                                headers=self._headers(),
                            )
                            if rep_resp.status_code != 200:
                                continue
                            rbody = rep_resp.json() or {}
                            rows = rbody.get("results") if isinstance(rbody, dict) else []
                            if not isinstance(rows, list):
                                continue
                            for row in rows:
                                last_fetched = _parse_iso(row.get("last_fetched"))
                                if last_fetched is not None and last_fetched < cutoff:
                                    continue
                                events.append(
                                    self.normalize(
                                        {
                                            "kind": "query_row",
                                            "query": q,
                                            "row": row,
                                        }
                                    )
                                )
        except httpx.RequestError as exc:
            logger.warning("fleetdm.fetch_exception", error=str(exc))
            return []

        return events

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        kind = raw.get("kind")
        if kind == "host":
            host = raw.get("host") or {}
            status = host.get("status")
            return {
                "source": self.connector_id,
                "category": "endpoint",
                "severity": _host_status_severity(status),
                "title": f"FleetDM host status: {status or 'unknown'}",
                "description": (f"hostname={host.get('hostname')} platform={host.get('platform')} os={host.get('os_version')}"),
                "alert_id": f"fleetdm-host-{host.get('id')}-{status}",
                "hostname": host.get("hostname"),
                "host": host.get("hostname"),
                "external_id": str(host.get("id")) if host.get("id") is not None else None,
                "raw_event": host,
                "raw": raw,
            }

        # default: query report row
        query = raw.get("query") or {}
        row = raw.get("row") or {}
        table = _infer_table(query.get("query"))
        host_name = row.get("host_hostname") or row.get("hostname")

        # Flatten osquery row columns to the top level so detection
        # rules can match on them directly. AiSOC-canonical fields
        # (source/category/severity/...) win on collision.
        event: dict[str, Any] = {}
        if isinstance(row, dict):
            event.update(row)
        event.update(
            {
                "source": self.connector_id,
                "category": "endpoint",
                "event_type": "osquery_query_row",
                "severity": _table_severity(table),
                "title": f"FleetDM query: {query.get('name') or query.get('id')}",
                "description": (query.get("query") or "")[:400],
                "alert_id": (f"fleetdm-q{query.get('id')}-h{row.get('host_id') or row.get('host_hostname')}"),
                "hostname": host_name,
                "host": host_name,
                "external_id": str(query.get("id")) if query.get("id") is not None else None,
                "osquery_table": table,
                "query_name": query.get("name"),
                "raw_event": row,
                "raw": raw,
            }
        )
        return event


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_iso(value: Any) -> float | None:
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
    if not query_sql:
        return None
    lower = query_sql.lower()
    idx = lower.find(" from ")
    if idx < 0:
        return None
    rest = query_sql[idx + len(" from ") :].strip()
    token = rest.split()[0] if rest else ""
    return token.strip(",;()`'\"") or None
