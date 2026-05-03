"""Thin async client for the Caldera REST API."""
from __future__ import annotations

import logging
from typing import Any

import httpx

LOG = logging.getLogger(__name__)

_HEADERS = {"KEY": "", "Content-Type": "application/json"}


class CalderaClient:
    def __init__(self, base_url: str, api_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = {"KEY": api_key, "Content-Type": "application/json"}

    async def health(self) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(f"{self.base_url}/api/v2/health", headers=self._headers)
                return r.status_code == 200
        except Exception:
            return False

    async def list_abilities(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{self.base_url}/api/v2/abilities", headers=self._headers)
            r.raise_for_status()
            return r.json()

    async def get_ability(self, ability_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                f"{self.base_url}/api/v2/abilities/{ability_id}", headers=self._headers
            )
            r.raise_for_status()
            return r.json()

    async def list_operations(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{self.base_url}/api/v2/operations", headers=self._headers)
            r.raise_for_status()
            return r.json()

    async def get_operation(self, operation_id: str) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                f"{self.base_url}/api/v2/operations/{operation_id}", headers=self._headers
            )
            r.raise_for_status()
            return r.json()

    async def start_operation(
        self,
        name: str,
        adversary_id: str,
        group: str = "red",
        auto_close: bool = True,
    ) -> dict[str, Any]:
        payload = {
            "name": name,
            "adversary": {"adversary_id": adversary_id},
            "group": group,
            "auto_close": auto_close,
            "state": "running",
        }
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.post(
                f"{self.base_url}/api/v2/operations", json=payload, headers=self._headers
            )
            r.raise_for_status()
            return r.json()

    async def list_adversaries(self) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{self.base_url}/api/v2/adversaries", headers=self._headers)
            r.raise_for_status()
            return r.json()

    async def get_operation_links(self, operation_id: str) -> list[dict[str, Any]]:
        """Return all links (executed commands) for an operation."""
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                f"{self.base_url}/api/v2/operations/{operation_id}/links",
                headers=self._headers,
            )
            r.raise_for_status()
            return r.json()
