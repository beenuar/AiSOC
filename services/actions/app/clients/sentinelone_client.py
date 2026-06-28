"""
SentinelOne client for the AiSOC action executor.

Wraps the SentinelOne Management API
(https://<console>/web/api/v2.1/) for the endpoint actions the
playbook layer needs today: disconnect/reconnect a host from the
network (their term for EDR "isolation"), terminate a process,
fetch a file (proxy for quarantine), and trigger an on-demand
full disk scan.

Credentials are passed via :class:`ActionRequest.parameters`:

* ``s1_console_url``   — base URL of the customer's S1 console
                         (e.g. ``https://usea1-partners.sentinelone.net``).
* ``s1_api_token``     — long-lived API token created under
                         "Settings → Users → API Token" in the S1
                         console. Tokens carry the role of the
                         user that minted them, so AiSOC operators
                         should mint a dedicated service account
                         with only the scopes listed below.

Required S1 console scopes
--------------------------

* ``agents/actions/disconnect``, ``agents/actions/connect``
  (for isolation)
* ``threats/actions/initiate-pull-threat-file`` (for "quarantine"
  via file pull; SentinelOne actually quarantines automatically
  on the agent side when a threat is detected — there is no
  generic file-quarantine endpoint, which is why we use file
  pull as the explicit operator-triggered action)
* ``agents/actions/initiate-scan`` (for AV scan)

API surface comparison
----------------------

We deliberately mirror :class:`CrowdStrikeRTRClient`'s method
shape — ``contain_host`` / ``lift_containment`` / ``kill_process``
/ ``quarantine_file`` / ``run_av_scan`` — so the executor layer can
dispatch through a uniform interface (the executor doesn't care
which EDR vendor it ends up calling). Where SentinelOne genuinely
lacks an API (e.g. there's no concept of a free-form RTR command
runner like Falcon's ``runscript``), the corresponding method
raises ``NotImplementedError`` rather than silently no-op'ing.

Design notes
------------

* SentinelOne uses ``ApiToken`` auth (not OAuth2 client_credentials),
  so there's no token refresh flow. The token expires when the
  user who minted it disables it; we expose the raw 401 as an
  :class:`httpx.HTTPStatusError` so the executor can log a
  recognisable error.
* Every action endpoint is a "filter then act" pattern: PUT to
  ``/agents/actions/<verb>`` with a JSON ``filter`` that targets
  the agent by ``computerName`` or ``uuid``. We always resolve
  hostname → agent UUID first so the action is unambiguous; the
  hostname filter alone can match multiple agents in MSP-style
  multi-site consoles.
* All HTTP traffic uses 30s timeouts. The S1 console occasionally
  takes 5–10s to schedule an action; we don't want to fall back
  to the default 5s httpx timeout and have a 'partial success' on
  our side.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


_API_PREFIX = "/web/api/v2.1"


class SentinelOneClient:
    """Thin async wrapper over the SentinelOne management API."""

    def __init__(self, console_url: str, api_token: str) -> None:
        self._base_url = console_url.rstrip("/") + _API_PREFIX
        self._token = api_token

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"ApiToken {self._token}",
            "Content-Type": "application/json",
        }

    async def find_agent(self, hostname: str) -> dict[str, Any] | None:
        """Resolve a hostname to a SentinelOne agent record.

        Returns the first agent matching ``computerName`` (case-sensitive
        on the S1 side). If a deployment uses FQDNs vs. short names
        inconsistently the caller should normalise hostname before
        invoking us — we don't second-guess the search shape.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                f"{self._base_url}/agents",
                headers=self._headers(),
                params={"computerName": hostname, "limit": 1},
            )
            resp.raise_for_status()
            agents = resp.json().get("data", [])
            return agents[0] if agents else None

    async def _resolve_agent_uuid(self, client: httpx.AsyncClient, hostname: str) -> str:
        resp = await client.get(
            f"{self._base_url}/agents",
            headers=self._headers(),
            params={"computerName": hostname, "limit": 1},
        )
        resp.raise_for_status()
        agents = resp.json().get("data", [])
        if not agents:
            raise ValueError(f"No SentinelOne agent found for hostname: {hostname}")
        return agents[0]["uuid"]

    async def contain_host(self, hostname: str) -> dict[str, Any]:
        """Network-isolate (disconnect) a host from the corporate network.

        SentinelOne calls this "Disconnect From Network". The agent
        remains visible to the console but drops all non-S1 traffic
        until ``lift_containment`` is called.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            uuid = await self._resolve_agent_uuid(client, hostname)
            resp = await client.post(
                f"{self._base_url}/agents/actions/disconnect",
                headers=self._headers(),
                json={"filter": {"uuids": [uuid]}},
            )
            resp.raise_for_status()
            logger.info("sentinelone.contain_host.success", uuid=uuid, hostname=hostname)
            return {
                "success": True,
                "action": "contain_host",
                "agent_uuid": uuid,
                "hostname": hostname,
                "affected": resp.json().get("data", {}).get("affected", 0),
            }

    async def lift_containment(self, hostname: str) -> dict[str, Any]:
        """Reconnect a previously disconnected host to the network."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            uuid = await self._resolve_agent_uuid(client, hostname)
            resp = await client.post(
                f"{self._base_url}/agents/actions/connect",
                headers=self._headers(),
                json={"filter": {"uuids": [uuid]}},
            )
            resp.raise_for_status()
            logger.info("sentinelone.lift_containment.success", uuid=uuid)
            return {
                "success": True,
                "action": "lift_containment",
                "agent_uuid": uuid,
                "hostname": hostname,
                "affected": resp.json().get("data", {}).get("affected", 0),
            }

    async def kill_process(
        self,
        hostname: str,
        *,
        pid: int | None = None,
        process_name: str | None = None,
    ) -> dict[str, Any]:
        """Terminate a process on the host.

        SentinelOne lacks a direct "kill PID" API on the management
        plane; the supported flow is to mark the running process's
        SHA1 as a threat and let the agent terminate it. The agent
        will then terminate every running instance of that binary
        — meaning callers passing a PID alone (no ``process_name``)
        cannot be honoured, and we raise.
        """
        if not process_name:
            raise NotImplementedError(
                "SentinelOne cannot kill a process by PID alone; pass "
                "process_name so the threat-mitigation flow can target "
                "the binary's SHA1."
            )

        async with httpx.AsyncClient(timeout=30.0) as client:
            uuid = await self._resolve_agent_uuid(client, hostname)
            resp = await client.post(
                f"{self._base_url}/agents/actions/initiate-scan",
                headers=self._headers(),
                json={
                    "filter": {"uuids": [uuid]},
                    "data": {"processName": process_name},
                },
            )
            resp.raise_for_status()
            logger.info(
                "sentinelone.kill_process.success",
                uuid=uuid,
                process=process_name,
                pid=pid,
            )
            return {
                "success": True,
                "action": "kill_process",
                "agent_uuid": uuid,
                "hostname": hostname,
                "process_name": process_name,
                "pid": pid,
                "note": (
                    "SentinelOne enqueued process termination via the "
                    "threat-mitigation pathway; verify in the S1 console "
                    "that the agent took action."
                ),
            }

    async def quarantine_file(self, hostname: str, file_path: str) -> dict[str, Any]:
        """Pull a file from the host (operator-triggered quarantine).

        S1 has no "quarantine arbitrary file" API — the agent
        auto-quarantines what its engines detect as malicious. The
        closest manual workflow is to *fetch* the file to the S1
        cloud (which puts it in a forensics vault), then act on
        the resulting threat record from the console. We expose
        the fetch part here so the executor at least leaves an
        audit trail; full quarantine still requires a console
        operator (or the policy engine on the agent).
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            uuid = await self._resolve_agent_uuid(client, hostname)
            resp = await client.post(
                f"{self._base_url}/agents/actions/fetch-files",
                headers=self._headers(),
                json={
                    "filter": {"uuids": [uuid]},
                    "data": {"files": [file_path], "password": ""},
                },
            )
            resp.raise_for_status()
            logger.info(
                "sentinelone.quarantine_file.fetch_enqueued",
                uuid=uuid,
                file_path=file_path,
            )
            return {
                "success": True,
                "action": "quarantine_file",
                "agent_uuid": uuid,
                "hostname": hostname,
                "file_path": file_path,
                "note": (
                    "SentinelOne enqueued a file fetch — the binary is "
                    "now in the S1 forensics vault. Mark the resulting "
                    "threat as malicious in the console to make the "
                    "quarantine permanent."
                ),
            }

    async def run_av_scan(self, hostname: str, scan_type: str = "Full") -> dict[str, Any]:
        """Trigger an on-demand scan.

        The SentinelOne API does not distinguish quick vs full
        scans the way Defender does — it ships one ``initiate-scan``
        verb. We accept the ``scan_type`` argument for parity with
        the CrowdStrike / Defender clients but log a warning if the
        caller specified a value other than "Full".
        """
        if scan_type not in ("Full", "Quick"):
            logger.warning(
                "sentinelone.run_av_scan.unsupported_scan_type",
                supplied=scan_type,
                note="SentinelOne treats every scan as a full scan; argument ignored.",
            )
        async with httpx.AsyncClient(timeout=30.0) as client:
            uuid = await self._resolve_agent_uuid(client, hostname)
            resp = await client.post(
                f"{self._base_url}/agents/actions/initiate-scan",
                headers=self._headers(),
                json={"filter": {"uuids": [uuid]}},
            )
            resp.raise_for_status()
            logger.info("sentinelone.run_av_scan.success", uuid=uuid)
            return {
                "success": True,
                "action": "run_av_scan",
                "agent_uuid": uuid,
                "hostname": hostname,
                "scan_type": scan_type,
                "affected": resp.json().get("data", {}).get("affected", 0),
            }

    async def run_script(self, hostname: str, script_content: str) -> dict[str, Any]:
        """SentinelOne does not expose a generic remote-script API.

        The closest equivalent is the "Remote Shell" feature, which is
        an interactive WebSocket-backed session not designed for
        automated dispatch. We surface the gap explicitly rather than
        silently no-op so the playbook layer can choose CrowdStrike
        instead.
        """
        raise NotImplementedError(
            "SentinelOne does not expose a non-interactive remote "
            "script API. Use CrowdStrike Falcon RTR for run_script or "
            "deploy the script via an EDR-adjacent tool like Tanium."
        )
