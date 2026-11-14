"""Async client for the FleetDM REST API — live distributed queries.

FleetDM is a popular open-source device management platform built on osquery.
API reference: https://fleetdm.com/docs/rest-api/rest-api

Supported operations
---------------------
- ``live_query``: Create a live-query campaign, poll for results, then cancel.

All SQL must come from :mod:`app.clients.osquery_allowlist`; callers pass a
``template`` ID and optional ``template_params`` rather than raw SQL.

Authentication
--------------
FleetDM uses a session token obtained by POSTing credentials to
``/api/v1/fleet/login`` and then passing the token in the
``Authorization: Bearer <token>`` header.  This client accepts either:

* ``api_token`` — a pre-issued API token (preferred; no login needed).
* ``username`` + ``password`` — session-based auth (fallback).

Endpoints used
--------------
POST /api/v1/fleet/queries/run              → start campaign, get campaign_id
GET  /api/v1/fleet/queries/run/{campaign_id} → stream results
DELETE /api/v1/fleet/queries/run/{campaign_id} → cancel when done
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from app.clients.osquery_allowlist import AllowlistError, render_query

logger = logging.getLogger(__name__)

_DEFAULT_POLL_INTERVAL = 3.0
_DEFAULT_TIMEOUT = 60


class FleetDMError(RuntimeError):
    """Raised when a FleetDM API call fails."""


class FleetDMClient:
    """Thin async wrapper over the FleetDM REST API for live distributed queries.

    Parameters
    ----------
    base_url:
        Root URL of the FleetDM server, e.g. ``https://fleet.example.com``.
    api_token:
        Pre-issued FleetDM API token.  If omitted, supply *username* and
        *password* for session-based authentication.
    username:
        FleetDM username (used only when *api_token* is ``None``).
    password:
        FleetDM password (used only when *api_token* is ``None``).
    verify_tls:
        Whether to verify the server's TLS certificate.
    poll_interval:
        Seconds between result-polling attempts.
    """

    def __init__(
        self,
        base_url: str,
        api_token: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_tls: bool = True,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> None:
        if not api_token and not (username and password):
            raise ValueError("FleetDMClient requires either api_token or (username, password).")
        self._base_url = base_url.rstrip("/")
        self._api_token = api_token
        self._username = username
        self._password = password
        self._verify_tls = verify_tls
        self._poll_interval = poll_interval
        self._session_token: str | None = None

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
        """Submit a live-query campaign and return results keyed by hostname.

        Parameters
        ----------
        target_hosts:
            List of FleetDM host identifiers (UUIDs or hostnames).
        template:
            Template ID from :mod:`app.clients.osquery_allowlist`.
        template_params:
            Optional keyword arguments forwarded to :func:`render_query`.
        timeout_seconds:
            How long to wait for all hosts to respond.

        Returns
        -------
        dict
            ``{"results": {hostname: [row, ...]}, "partial": bool}``

        Raises
        ------
        AllowlistError
            If *template* is not in the approved allowlist.
        FleetDMError
            If the FleetDM API returns an unexpected HTTP status.
        """
        params = template_params or {}
        try:
            sql = render_query(template, **params)
        except AllowlistError:
            logger.warning("fleetdm live_query rejected: template=%s params=%s", template, params)
            raise

        async with self._client() as http:
            await self._ensure_auth(http)
            campaign_id = await self._create_campaign(http, sql, target_hosts)
            logger.info(
                "FleetDM campaign created",
                extra={"campaign_id": campaign_id, "hosts": target_hosts},
            )

            try:
                return await self._poll_campaign(
                    http,
                    campaign_id,
                    expected_hosts=set(target_hosts),
                    timeout=timeout_seconds,
                )
            finally:
                await self._cancel_campaign(http, campaign_id)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=self._verify_tls,
            follow_redirects=True,
            timeout=httpx.Timeout(30.0),
        )

    def _auth_headers(self) -> dict[str, str]:
        token = self._api_token or self._session_token
        if not token:
            return {}
        return {"Authorization": f"Bearer {token}"}

    async def _ensure_auth(self, http: httpx.AsyncClient) -> None:
        """Obtain a session token if we don't already have one."""
        if self._api_token or self._session_token:
            return

        url = f"{self._base_url}/api/v1/fleet/login"
        resp = await http.post(
            url,
            json={"email": self._username, "password": self._password},
        )
        if resp.status_code != 200:
            raise FleetDMError(f"FleetDM login failed: HTTP {resp.status_code} — {resp.text[:300]}")
        data = resp.json()
        token = data.get("token") or (data.get("user") or {}).get("token")
        if not token:
            raise FleetDMError(f"FleetDM login returned no token: {data}")
        self._session_token = token

    async def _create_campaign(
        self,
        http: httpx.AsyncClient,
        sql: str,
        target_hosts: list[str],
    ) -> str:
        """POST /api/v1/fleet/queries/run and return campaign ID."""
        url = f"{self._base_url}/api/v1/fleet/queries/run"
        payload: dict[str, Any] = {
            "query": sql,
            "selected": {"hosts": target_hosts},
        }
        resp = await http.post(url, json=payload, headers=self._auth_headers())
        if resp.status_code not in (200, 201):
            raise FleetDMError(f"FleetDM campaign creation failed: HTTP {resp.status_code} — {resp.text[:300]}")
        data = resp.json()
        campaign = data.get("campaign") or data
        campaign_id = str(campaign.get("id") or campaign.get("campaign_id") or campaign.get("uuid") or "")
        if not campaign_id:
            raise FleetDMError(f"FleetDM returned no campaign ID: {data}")
        return campaign_id

    async def _poll_campaign(
        self,
        http: httpx.AsyncClient,
        campaign_id: str,
        expected_hosts: set[str],
        timeout: int,
    ) -> dict[str, Any]:
        """Poll GET /api/v1/fleet/queries/run/{campaign_id} until done."""
        url = f"{self._base_url}/api/v1/fleet/queries/run/{campaign_id}"
        deadline = asyncio.get_event_loop().time() + timeout
        results: dict[str, list[dict[str, Any]]] = {}
        responded: set[str] = set()

        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                logger.warning(
                    "FleetDM poll timeout: campaign_id=%s responded=%s/%s",
                    campaign_id,
                    len(responded),
                    len(expected_hosts),
                )
                return {"results": results, "partial": True}

            resp = await http.get(url, headers=self._auth_headers())
            if resp.status_code == 404:
                await asyncio.sleep(min(self._poll_interval, remaining))
                continue
            if resp.status_code != 200:
                raise FleetDMError(f"FleetDM campaign poll failed: HTTP {resp.status_code} — {resp.text[:300]}")

            data = resp.json()
            # FleetDM returns {results: [{host: {...}, rows: [...]}, ...]}
            for item in data.get("results") or (data if isinstance(data, list) else []):
                host_info = item.get("host") or {}
                node = host_info.get("hostname") or host_info.get("uuid") or item.get("hostname") or "unknown"
                rows = item.get("rows") or []
                if node not in results:
                    results[node] = []
                results[node].extend(rows)
                responded.add(node)

            if expected_hosts and responded >= expected_hosts:
                logger.info("FleetDM campaign %s: all hosts responded", campaign_id)
                return {"results": results, "partial": False}

            # Check campaign status to avoid polling a finished campaign.
            status = (data.get("campaign") or data).get("status") or ""
            if status in ("finished", "complete", "error"):
                return {"results": results, "partial": responded < expected_hosts}

            await asyncio.sleep(min(self._poll_interval, remaining))

    async def _cancel_campaign(
        self,
        http: httpx.AsyncClient,
        campaign_id: str,
    ) -> None:
        """DELETE /api/v1/fleet/queries/run/{campaign_id} — best-effort cleanup."""
        url = f"{self._base_url}/api/v1/fleet/queries/run/{campaign_id}"
        try:
            await http.delete(url, headers=self._auth_headers())
        except Exception as exc:  # noqa: BLE001
            logger.debug("FleetDM campaign cancel failed (ignored): %s", exc)
