"""Async HTTP client for interacting with the AiSOC REST API.

Plugins can use ``AiSOCClient`` to:
- Push enrichment data back to an indicator record
- Attach evidence or notes to a case
- Trigger follow-up actions within a playbook run
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from .plugin import PluginContext

logger = logging.getLogger(__name__)


class AiSOCClientError(Exception):
    """Raised when the AiSOC API returns an unexpected response."""

    def __init__(self, status_code: int, body: str) -> None:
        self.status_code = status_code
        self.body = body
        super().__init__(f"AiSOC API error {status_code}: {body}")


class AiSOCClient:
    """Thin async HTTP client scoped to a single plugin invocation.

    Usage::

        async with AiSOCClient(ctx) as client:
            await client.add_case_note(case_id="abc123", note="Found IOC")
    """

    def __init__(self, ctx: PluginContext, timeout: float = 30.0) -> None:
        self._ctx = ctx
        self._timeout = timeout
        self._http: httpx.AsyncClient | None = None

    # ── Context-manager helpers ───────────────────────────────────────────────

    async def __aenter__(self) -> "AiSOCClient":
        self._http = httpx.AsyncClient(
            base_url=self._ctx.api_base_url,
            headers={
                "Authorization": f"Bearer {self._ctx.api_token}",
                "Content-Type": "application/json",
            },
            timeout=self._timeout,
        )
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None

    # ── Internal ─────────────────────────────────────────────────────────────

    @property
    def _client_instance(self) -> httpx.AsyncClient:
        if self._http is None:
            raise RuntimeError("AiSOCClient must be used as an async context manager.")
        return self._http

    async def _get(self, path: str, **params: Any) -> Any:
        resp = await self._client_instance.get(path, params=params)
        self._raise_for_status(resp)
        return resp.json()

    async def _post(self, path: str, payload: dict[str, Any]) -> Any:
        resp = await self._client_instance.post(path, json=payload)
        self._raise_for_status(resp)
        return resp.json()

    async def _patch(self, path: str, payload: dict[str, Any]) -> Any:
        resp = await self._client_instance.patch(path, json=payload)
        self._raise_for_status(resp)
        return resp.json()

    @staticmethod
    def _raise_for_status(resp: httpx.Response) -> None:
        if resp.is_error:
            raise AiSOCClientError(resp.status_code, resp.text)

    # ── Cases API ─────────────────────────────────────────────────────────────

    async def get_case(self, case_id: str) -> dict[str, Any]:
        """Fetch a case by ID."""
        return await self._get(f"/api/v1/cases/{case_id}")

    async def add_case_note(self, case_id: str, note: str) -> dict[str, Any]:
        """Append a plain-text note to a case timeline."""
        return await self._post(
            f"/api/v1/cases/{case_id}/notes",
            {"content": note},
        )

    async def update_case_severity(
        self, case_id: str, severity: str
    ) -> dict[str, Any]:
        """Set case severity. ``severity`` must be one of: low, medium, high, critical."""
        return await self._patch(
            f"/api/v1/cases/{case_id}",
            {"severity": severity},
        )

    # ── Indicators API ────────────────────────────────────────────────────────

    async def get_indicator(self, indicator_id: str) -> dict[str, Any]:
        """Fetch a raw indicator record."""
        return await self._get(f"/api/v1/indicators/{indicator_id}")

    async def patch_indicator(
        self, indicator_id: str, enrichments: dict[str, Any]
    ) -> dict[str, Any]:
        """Merge enrichment data into an existing indicator record."""
        return await self._patch(
            f"/api/v1/indicators/{indicator_id}",
            {"enrichments": enrichments},
        )

    # ── Playbook runs API ─────────────────────────────────────────────────────

    async def get_playbook_run(self, run_id: str) -> dict[str, Any]:
        """Fetch playbook run status."""
        return await self._get(f"/api/v1/playbook-runs/{run_id}")

    async def complete_playbook_step(
        self,
        run_id: str,
        step_id: str,
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """Signal that a manual or async step is complete."""
        return await self._post(
            f"/api/v1/playbook-runs/{run_id}/steps/{step_id}/complete",
            result,
        )
