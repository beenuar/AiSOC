"""
CrowdStrike Falcon Real-Time-Response (RTR) client.

Wraps the RTR API for host containment, process termination, and file quarantine.
Credentials are expected in ActionRequest.parameters:
    cs_client_id: str
    cs_client_secret: str
    cs_base_url: str  (optional, default api.crowdstrike.com)
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()

_DEFAULT_BASE = "https://api.crowdstrike.com"
_TOKEN_PATH = "/oauth2/token"


class CrowdStrikeRTRClient:
    """Thin async wrapper over the CrowdStrike Falcon RTR REST API."""

    def __init__(self, client_id: str, client_secret: str, base_url: str = _DEFAULT_BASE) -> None:
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = base_url.rstrip("/")
        self._token: str | None = None

    async def _authenticate(self, client: httpx.AsyncClient) -> str:
        resp = await client.post(
            f"{self._base_url}{_TOKEN_PATH}",
            data={"client_id": self._client_id, "client_secret": self._client_secret},
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        return self._token

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"}

    async def _ensure_token(self, client: httpx.AsyncClient) -> None:
        if not self._token:
            await self._authenticate(client)

    async def get_device_id(self, hostname: str) -> str | None:
        """Resolve a hostname to a CrowdStrike device_id."""
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{self._base_url}/devices/queries/devices/v1",
                headers=self._auth_headers(),
                params={"filter": f"hostname:'{hostname}'", "limit": 1},
            )
            if resp.status_code == 401:
                await self._authenticate(client)
                resp = await client.get(
                    f"{self._base_url}/devices/queries/devices/v1",
                    headers=self._auth_headers(),
                    params={"filter": f"hostname:'{hostname}'", "limit": 1},
                )
            resp.raise_for_status()
            resources = resp.json().get("resources", [])
            return resources[0] if resources else None

    async def contain_host(self, device_id: str) -> dict[str, Any]:
        """Put a host into network containment via RTR."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{self._base_url}/devices/entities/devices-actions/v2",
                headers=self._auth_headers(),
                params={"action_name": "contain"},
                json={"ids": [device_id]},
            )
            resp.raise_for_status()
            return {"device_id": device_id, "action": "contain", "response": resp.json()}

    async def lift_containment(self, device_id: str) -> dict[str, Any]:
        """Remove a host from network containment."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            resp = await client.post(
                f"{self._base_url}/devices/entities/devices-actions/v2",
                headers=self._auth_headers(),
                params={"action_name": "lift_containment"},
                json={"ids": [device_id]},
            )
            resp.raise_for_status()
            return {"device_id": device_id, "action": "lift_containment", "response": resp.json()}

    async def _init_rtr_session(self, client: httpx.AsyncClient, device_id: str) -> str:
        """Open an RTR batch session with a single host, return session_id."""
        resp = await client.post(
            f"{self._base_url}/real-time-response/combined/batch-init-session/v1",
            headers=self._auth_headers(),
            json={"host_ids": [device_id], "queue_offline": False},
        )
        resp.raise_for_status()
        return resp.json()["batch_id"]

    async def kill_process(self, device_id: str, pid: int) -> dict[str, Any]:
        """Kill a process by PID via RTR kill command."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            await self._ensure_token(client)
            batch_id = await self._init_rtr_session(client, device_id)

            resp = await client.post(
                f"{self._base_url}/real-time-response/combined/batch-active-responder-command/v1",
                headers=self._auth_headers(),
                json={
                    "base_command": "kill",
                    "batch_id": batch_id,
                    "command_string": f"kill {pid}",
                    "optional_hosts": [device_id],
                },
            )
            resp.raise_for_status()
            return {"device_id": device_id, "pid": pid, "action": "kill_process", "response": resp.json()}

    async def quarantine_file(self, device_id: str, file_path: str) -> dict[str, Any]:
        """Remove (quarantine) a file from the host via RTR rm command."""
        async with httpx.AsyncClient(timeout=60.0) as client:
            await self._ensure_token(client)
            batch_id = await self._init_rtr_session(client, device_id)

            resp = await client.post(
                f"{self._base_url}/real-time-response/combined/batch-active-responder-command/v1",
                headers=self._auth_headers(),
                json={
                    "base_command": "rm",
                    "batch_id": batch_id,
                    "command_string": f"rm '{file_path}'",
                    "optional_hosts": [device_id],
                },
            )
            resp.raise_for_status()
            return {"device_id": device_id, "file_path": file_path, "action": "quarantine_file", "response": resp.json()}

    async def run_script(self, device_id: str, script_content: str) -> dict[str, Any]:
        """Run a PowerShell script on the host via RTR."""
        async with httpx.AsyncClient(timeout=120.0) as client:
            await self._ensure_token(client)
            batch_id = await self._init_rtr_session(client, device_id)

            resp = await client.post(
                f"{self._base_url}/real-time-response/combined/batch-admin-command/v1",
                headers=self._auth_headers(),
                json={
                    "base_command": "runscript",
                    "batch_id": batch_id,
                    "command_string": f"runscript -Raw=```{script_content}```",
                    "optional_hosts": [device_id],
                },
            )
            resp.raise_for_status()
            return {"device_id": device_id, "action": "run_script", "response": resp.json()}
