"""
Splunk REST API client for SIEM response actions.

Supports: run search, create notable event, update lookup table, create/update correlation search.

Credentials expected in ActionRequest.parameters:
    splunk_host: str          e.g. "https://splunk.corp.example.com:8089"
    splunk_token: str         HEC or REST API token (bearer)
    splunk_username: str      (alternative to token — basic auth)
    splunk_password: str
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class SplunkClient:
    """Async client for Splunk REST API response actions."""

    def __init__(
        self,
        host: str,
        token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool = True,
    ) -> None:
        self._host = host.rstrip("/")
        self._token = token
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._session_key: str | None = None

    def _headers(self) -> dict[str, str]:
        if self._token:
            return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}
        if self._session_key:
            return {"Authorization": f"Splunk {self._session_key}", "Content-Type": "application/json"}
        return {"Content-Type": "application/json"}

    async def _authenticate(self, client: httpx.AsyncClient) -> None:
        """Authenticate with username/password to get a session key."""
        if self._token:
            return
        if not (self._username and self._password):
            raise ValueError("Either splunk_token or splunk_username+splunk_password required")
        resp = await client.post(
            f"{self._host}/services/auth/login",
            data={"username": self._username, "password": self._password, "output_mode": "json"},
            verify=self._verify_ssl,
        )
        resp.raise_for_status()
        self._session_key = resp.json()["sessionKey"]

    async def run_search(
        self,
        query: str,
        earliest_time: str = "-24h",
        latest_time: str = "now",
        max_count: int = 1000,
    ) -> list[dict[str, Any]]:
        """Execute a blocking SPL search and return results as list of dicts."""
        async with httpx.AsyncClient(timeout=60.0, verify=self._verify_ssl) as client:
            await self._authenticate(client)

            # Create search job
            create_resp = await client.post(
                f"{self._host}/services/search/jobs",
                headers=self._headers(),
                data={
                    "search": query if query.startswith("search ") else f"search {query}",
                    "earliest_time": earliest_time,
                    "latest_time": latest_time,
                    "output_mode": "json",
                    "exec_mode": "blocking",  # wait for completion
                    "max_count": str(max_count),
                },
            )
            create_resp.raise_for_status()
            sid = create_resp.json()["sid"]
            logger.info("splunk.search.created", sid=sid)

            # Retrieve results
            results_resp = await client.get(
                f"{self._host}/services/search/jobs/{sid}/results",
                headers=self._headers(),
                params={"output_mode": "json", "count": max_count},
                timeout=120.0,
            )
            results_resp.raise_for_status()
            data = results_resp.json()
            results = data.get("results", [])
            logger.info("splunk.search.complete", sid=sid, result_count=len(results))
            return results

    async def create_notable_event(
        self,
        rule_name: str,
        event_data: dict[str, Any],
        severity: str = "high",
        owner: str = "admin",
        status: str = "new",
    ) -> dict[str, Any]:
        """Create a notable event in Splunk ES using the REST API.

        Requires Splunk Enterprise Security with correlationsearches capability.
        """
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_ssl) as client:
            await self._authenticate(client)

            payload = {
                "rule_name": rule_name,
                "severity": severity,
                "owner": owner,
                "status": status,
                "output_mode": "json",
                **event_data,
            }
            resp = await client.post(
                f"{self._host}/services/notable_events",
                headers=self._headers(),
                data=payload,
            )
            resp.raise_for_status()
            logger.info("splunk.notable_event.created", rule_name=rule_name, severity=severity)
            return {
                "success": True,
                "action": "create_notable_event",
                "rule_name": rule_name,
                "response": resp.json() if resp.content else {},
            }

    async def update_lookup(
        self,
        lookup_name: str,
        entries: list[dict[str, str]],
        app: str = "search",
    ) -> dict[str, Any]:
        """Append or overwrite a lookup table in Splunk via the REST API.

        entries: list of dicts, each dict is one row of the lookup.
        """
        if not entries:
            return {"success": True, "action": "update_lookup", "rows_added": 0}

        # Build CSV content
        headers = list(entries[0].keys())
        rows = [",".join(headers)]
        for entry in entries:
            rows.append(",".join(str(entry.get(h, "")) for h in headers))
        csv_content = "\n".join(rows)

        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_ssl) as client:
            await self._authenticate(client)
            resp = await client.post(
                f"{self._host}/servicesNS/nobody/{app}/data/lookup-table-files/{lookup_name}",
                headers={k: v for k, v in self._headers().items() if k != "Content-Type"},
                files={"eai:data": (lookup_name, csv_content.encode(), "text/csv")},
            )
            resp.raise_for_status()
            logger.info("splunk.lookup.updated", lookup_name=lookup_name, rows=len(entries))
            return {
                "success": True,
                "action": "update_lookup",
                "lookup_name": lookup_name,
                "rows_added": len(entries),
            }

    async def create_or_update_correlation_search(
        self,
        name: str,
        search: str,
        schedule: str = "*/5 * * * *",
        severity: str = "high",
        app: str = "SplunkEnterpriseSecuritySuite",
    ) -> dict[str, Any]:
        """Create or update a correlation search in Splunk ES."""
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_ssl) as client:
            await self._authenticate(client)

            # Try to update, fall back to create
            url = f"{self._host}/servicesNS/nobody/{app}/saved/searches/{name}"
            payload = {
                "search": search,
                "cron_schedule": schedule,
                "is_scheduled": "1",
                "alert.severity": severity,
                "output_mode": "json",
            }
            resp = await client.post(url, headers=self._headers(), data=payload)
            if resp.status_code == 404:
                create_url = f"{self._host}/servicesNS/nobody/{app}/saved/searches"
                resp = await client.post(create_url, headers=self._headers(), data={"name": name, **payload})
            resp.raise_for_status()
            logger.info("splunk.correlation_search.upserted", name=name)
            return {"success": True, "action": "upsert_correlation_search", "name": name}

    async def acknowledge_notable_event(
        self,
        event_id: str,
        owner: str = "aisoc",
        comment: str = "Acknowledged by AiSOC",
        urgency: str | None = None,
    ) -> dict[str, Any]:
        """Acknowledge (mark as in-progress) a Splunk ES notable event.

        Splunk ES exposes notable-event lifecycle changes via the
        ``notable_event_actions/edit_event`` endpoint. We set the
        status to "in progress" (status code 1) by default; callers
        can override ``urgency`` to retag the alert at the same time.

        Phase 3.3 — replaces playbooks that were previously closing
        Splunk alerts out-of-band via a tribal shell script.
        """
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_ssl) as client:
            await self._authenticate(client)
            payload = {
                "ruleUIDs": event_id,
                "status": 1,  # 1 = "in progress" in ES; 5 = closed.
                "newOwner": owner,
                "comment": comment,
                "output_mode": "json",
            }
            if urgency:
                payload["urgency"] = urgency
            resp = await client.post(
                f"{self._host}/services/notable_update",
                headers=self._headers(),
                data=payload,
            )
            resp.raise_for_status()
            logger.info("splunk.notable_event.acknowledged", event_id=event_id, owner=owner)
            return {
                "success": True,
                "action": "acknowledge_notable_event",
                "event_id": event_id,
                "owner": owner,
                "response": resp.json() if resp.content else {},
            }

    async def suppress_notable_event(
        self,
        event_id: str,
        comment: str = "Suppressed by AiSOC",
    ) -> dict[str, Any]:
        """Close (suppress) a Splunk ES notable event.

        Sets ES status to 5 ("closed"). This is a one-way move
        from the AiSOC side; re-opening must be done from the
        Splunk console (no production playbook should be racing
        the SOC analyst by re-opening tickets behind their back).
        """
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_ssl) as client:
            await self._authenticate(client)
            payload = {
                "ruleUIDs": event_id,
                "status": 5,  # 5 = "closed" in ES.
                "comment": comment,
                "output_mode": "json",
            }
            resp = await client.post(
                f"{self._host}/services/notable_update",
                headers=self._headers(),
                data=payload,
            )
            resp.raise_for_status()
            logger.info("splunk.notable_event.suppressed", event_id=event_id)
            return {
                "success": True,
                "action": "suppress_notable_event",
                "event_id": event_id,
                "response": resp.json() if resp.content else {},
            }
