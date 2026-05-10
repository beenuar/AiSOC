"""Async client for the AiSOC built-in osquery TLS endpoint.

Communicates with ``services/osquery-tls`` to enqueue distributed queries
and poll for their results.  This is used by the ``osquery_live_query``
playbook step when ``backend: aisoc_direct`` is configured.

Authentication uses a bearer token passed in the ``Authorization`` header.
The token is typically an internal service-account secret managed the same
way as any other AiSOC credential.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.clients.osquery_allowlist import render_query

logger = logging.getLogger(__name__)


class AiSOCDirectError(RuntimeError):
    """Raised when an aisoc-direct API call fails."""


class AiSOCDirectClient:
    """Async client for the AiSOC built-in osquery TLS service.

    Parameters
    ----------
    base_url:
        Root URL of the ``services/osquery-tls`` FastAPI service, e.g.
        ``http://osquery-tls:8080``.
    api_token:
        Bearer token presented as ``Authorization: Bearer <token>``.
    verify_tls:
        Whether to verify TLS when the service is behind HTTPS.
    poll_interval:
        Polling cadence in seconds between /distributed/status checks.
    """

    def __init__(
        self,
        base_url: str,
        api_token: str,
        verify_tls: bool = True,
        poll_interval: float = 3.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._verify_tls = verify_tls
        self._poll_interval = poll_interval

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._api_token}"}

    async def live_query(
        self,
        target_hosts: list[str],
        template: str,
        template_params: dict[str, Any] | None = None,
        timeout_seconds: int = 60,
    ) -> dict[str, Any]:
        """Run a distributed osquery query against a set of hosts.

        Enqueues the query via ``POST /api/v1/osquery/distributed/enqueue``
        and polls ``GET /api/v1/osquery/distributed/{query_id}`` until all
        target hosts respond or the timeout expires.

        Parameters
        ----------
        target_hosts:
            List of ``host_identifier`` values to target.
        template:
            Allowlist template ID (see ``osquery_allowlist``).
        template_params:
            Parameters forwarded to the template renderer.
        timeout_seconds:
            Maximum time to wait for results.

        Returns
        -------
        dict
            ``{"results": {host_id: [rows]}, "error": str | None}``

        Raises
        ------
        AiSOCDirectError
            If the HTTP request to the TLS service fails.
        AllowlistError
            If *template* is not in the approved allowlist.
        """
        params = template_params or {}
        sql = render_query(template, **params)

        async with httpx.AsyncClient(verify=self._verify_tls, timeout=30.0) as client:
            query_ids = await self._enqueue_for_hosts(client, target_hosts, sql)
            results = await self._poll_results(client, query_ids, timeout_seconds)

        errors = [r for r in results.values() if "error" in r]
        return {
            "results": {host: results[qid].get("rows", []) for host, qid in zip(target_hosts, query_ids, strict=False) if qid in results},
            "error": errors[0]["error"] if errors else None,
        }

    async def _enqueue_for_hosts(
        self,
        client: httpx.AsyncClient,
        target_hosts: list[str],
        sql: str,
    ) -> list[str]:
        """Enqueue one distributed query per target host and return query IDs."""
        url = f"{self._base_url}/api/v1/osquery/distributed/enqueue"
        query_ids: list[str] = []
        for host in target_hosts:
            try:
                resp = await client.post(
                    url,
                    json={"host_identifier": host, "query_text": sql},
                    headers=self._headers(),
                )
                resp.raise_for_status()
                data = resp.json()
                query_ids.append(data["query_id"])
            except httpx.HTTPError as exc:
                raise AiSOCDirectError(f"Failed to enqueue query for host {host}: {exc}") from exc
        return query_ids

    async def _poll_results(
        self,
        client: httpx.AsyncClient,
        query_ids: list[str],
        timeout_seconds: int,
    ) -> dict[str, Any]:
        """Poll until all queries complete or timeout is reached."""
        remaining = set(query_ids)
        results: dict[str, Any] = {}
        elapsed = 0.0

        while remaining and elapsed < timeout_seconds:
            await asyncio.sleep(self._poll_interval)
            elapsed += self._poll_interval
            done = set()
            for qid in list(remaining):
                url = f"{self._base_url}/api/v1/osquery/distributed/{qid}"
                try:
                    resp = await client.get(url, headers=self._headers())
                    resp.raise_for_status()
                    data = resp.json()
                    if data.get("status") in ("completed", "error"):
                        results[qid] = data
                        done.add(qid)
                except httpx.HTTPError as exc:
                    logger.warning("Poll error for query %s: %s", qid, exc)
            remaining -= done

        for qid in remaining:
            results[qid] = {"status": "timeout", "rows": [], "error": "timeout"}

        return results
