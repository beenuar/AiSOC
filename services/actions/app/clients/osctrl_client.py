"""Async client for the osctrl REST API — live distributed queries.

osctrl is an open-source TLS server for osquery fleets.
API reference: https://github.com/jmpsec/osctrl

Supported operations
---------------------
- ``live_query``: Submit a distributed osquery SQL template to one or more
  hosts in a named environment and poll for results until all hosts respond or
  the timeout elapses.

All SQL must come from :mod:`app.clients.osquery_allowlist`; callers pass a
``template`` ID and optional ``template_params`` rather than raw SQL.

Authentication
--------------
osctrl uses a static Bearer token (``Authorization: Bearer <api_token>``).

Endpoints used
--------------
POST /api/v1/queries/{environment}
GET  /api/v1/queries/{environment}/{query_id}/results
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.clients.osquery_allowlist import AllowlistError, render_query

logger = logging.getLogger(__name__)

_DEFAULT_POLL_INTERVAL = 3.0  # seconds between result-polling retries
_DEFAULT_TIMEOUT = 60  # seconds before we stop polling


class OsctrlError(RuntimeError):
    """Raised when an osctrl API call fails."""


class OsctrlClient:
    """Thin async wrapper over the osctrl REST API for live distributed queries.

    Parameters
    ----------
    base_url:
        Root URL of the osctrl admin server, e.g. ``https://osctrl.example.com``.
    environment:
        The osctrl environment name that owns the target fleet.
    api_token:
        Static Bearer token issued by osctrl.
    verify_tls:
        Whether to verify the server's TLS certificate.  Set to ``False`` only
        for local development with self-signed certs.
    poll_interval:
        Seconds to wait between result-polling attempts.
    """

    def __init__(
        self,
        base_url: str,
        environment: str,
        api_token: str,
        verify_tls: bool = True,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._environment = environment
        self._api_token = api_token
        self._verify_tls = verify_tls
        self._poll_interval = poll_interval

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def live_query(
        self,
        target_hosts: list[str],
        template: str,
        template_params: dict[str, Any] | None = None,
        timeout_seconds: int = _DEFAULT_TIMEOUT,
    ) -> dict[str, Any]:
        """Submit a distributed query and return results keyed by hostname.

        Parameters
        ----------
        target_hosts:
            List of osctrl node UUIDs or hostnames to target.
        template:
            Template ID from :mod:`app.clients.osquery_allowlist`.
        template_params:
            Optional keyword arguments forwarded to :func:`render_query`.
        timeout_seconds:
            How long (in wall-clock seconds) to wait for all hosts to respond.

        Returns
        -------
        dict
            ``{"results": {hostname: [row, ...]}, "partial": bool}``

            ``partial`` is ``True`` when the timeout elapsed before all hosts
            responded.

        Raises
        ------
        AllowlistError
            If *template* is not in the approved allowlist.
        OsctrlError
            If the osctrl API returns an unexpected HTTP status.
        asyncio.TimeoutError
            If *timeout_seconds* elapses before any results arrive.
        """
        params = template_params or {}
        try:
            sql = render_query(template, **params)
        except AllowlistError:
            logger.warning("osctrl live_query rejected: template=%s params=%s", template, params)
            raise

        async with self._client() as http:
            query_id = await self._submit_query(http, sql, target_hosts)
            logger.info(
                "osctrl distributed query submitted",
                extra={"query_id": query_id, "env": self._environment, "hosts": target_hosts},
            )

            return await self._poll_results(http, query_id, expected_hosts=set(target_hosts), timeout=timeout_seconds)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers={"Authorization": f"Bearer {self._api_token}"},
            verify=self._verify_tls,
            follow_redirects=True,
            timeout=httpx.Timeout(30.0),
        )

    async def _submit_query(
        self,
        http: httpx.AsyncClient,
        sql: str,
        target_hosts: list[str],
    ) -> str:
        """POST to /api/v1/queries/{env} and return the query UUID."""
        url = f"{self._base_url}/api/v1/queries/{self._environment}"
        payload: dict[str, Any] = {
            "query": sql,
            "targets": [{"type": "nodes", "list": target_hosts}],
        }

        resp = await http.post(url, json=payload)
        if resp.status_code not in (200, 201):
            raise OsctrlError(f"osctrl query submission failed: HTTP {resp.status_code} — {resp.text[:300]}")

        data = resp.json()
        query_id: str | None = data.get("id") or data.get("query_id") or data.get("uuid")
        if not query_id:
            raise OsctrlError(f"osctrl returned no query ID in response: {data}")
        return str(query_id)

    async def _poll_results(
        self,
        http: httpx.AsyncClient,
        query_id: str,
        expected_hosts: set[str],
        timeout: int,
    ) -> dict[str, Any]:
        """Poll GET /api/v1/queries/{env}/{query_id}/results until complete."""
        url = f"{self._base_url}/api/v1/queries/{self._environment}/{query_id}/results"
        deadline = asyncio.get_event_loop().time() + timeout
        results: dict[str, list[dict[str, Any]]] = {}
        responded: set[str] = set()

        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                logger.warning(
                    "osctrl poll timeout: query_id=%s responded=%s/%s",
                    query_id,
                    len(responded),
                    len(expected_hosts),
                )
                return {"results": results, "partial": True}

            resp = await http.get(url)
            if resp.status_code == 404:
                # Query not yet available on the server — wait and retry.
                await asyncio.sleep(min(self._poll_interval, remaining))
                continue
            if resp.status_code != 200:
                raise OsctrlError(f"osctrl result poll failed: HTTP {resp.status_code} — {resp.text[:300]}")

            data = resp.json()
            # osctrl returns a list of result objects, each with "node" and "rows".
            for item in data if isinstance(data, list) else data.get("results", []):
                node = item.get("node") or item.get("hostname") or item.get("uuid", "unknown")
                rows = item.get("rows") or item.get("data") or []
                if node not in results:
                    results[node] = []
                results[node].extend(rows)
                responded.add(node)

            if expected_hosts and responded >= expected_hosts:
                logger.info("osctrl query %s: all hosts responded", query_id)
                return {"results": results, "partial": False}

            await asyncio.sleep(min(self._poll_interval, remaining))
