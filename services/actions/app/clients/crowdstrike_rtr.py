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

    async def get_containment_status(self, device_id: str) -> str | None:
        """Read a device's actual containment state.

        Returns CrowdStrike's ``status`` string — ``"contained"``,
        ``"containment_pending"``, ``"lift_containment_pending"`` or
        ``"normal"`` — or ``None`` when the device cannot be read.

        This exists so post-action verification can prove containment took
        effect. Resolving a hostname to a device id (``get_device_id``) only
        proves the host exists, so a verifier built on it would certify an
        uncontained host as verified.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await client.get(
                f"{self._base_url}/devices/entities/devices/v2",
                headers=self._auth_headers(),
                params={"ids": device_id},
            )
            if resp.status_code == 401:
                await self._authenticate(client)
                resp = await client.get(
                    f"{self._base_url}/devices/entities/devices/v2",
                    headers=self._auth_headers(),
                    params={"ids": device_id},
                )
            resp.raise_for_status()
            resources = resp.json().get("resources", [])
            if not resources:
                return None
            status = resources[0].get("status")
            return str(status) if status is not None else None

    async def get_device(self, device_id: str) -> dict[str, Any] | None:
        """The full device record, for investigation rather than verification.

        ``get_containment_status`` returns one field because that is all a
        verifier should look at. An investigation needs more — OS, last
        seen, agent version, local IP — and asking a responder to infer
        those from a containment string is how an agent ends up guessing.

        Returns ``None`` when the device cannot be read. Never a partial
        record with invented fields.
        """
        async with httpx.AsyncClient(timeout=20.0) as client:
            await self._ensure_token(client)
            resp = await self._get_with_retry(client, "/devices/entities/devices/v2", {"ids": device_id})
            if resp is None:
                return None
            resources = resp.json().get("resources", [])
            if not resources:
                return None
            device = resources[0]
            # An explicit projection rather than the raw record: the vendor
            # payload carries ~90 fields, most of them noise in a prompt,
            # and an unbounded dict is an unbounded token cost.
            return {
                "device_id": device.get("device_id"),
                "hostname": device.get("hostname"),
                "platform": device.get("platform_name"),
                "os_version": device.get("os_version"),
                "agent_version": device.get("agent_version"),
                "local_ip": device.get("local_ip"),
                "external_ip": device.get("external_ip"),
                "last_seen": device.get("last_seen"),
                "first_seen": device.get("first_seen"),
                "containment_status": device.get("status"),
                "tags": device.get("tags") or [],
            }

    async def get_detections(self, device_id: str, *, limit: int = 20) -> list[dict[str, Any]]:
        """Recent detections for one device, newest first.

        Returns an empty list both when the device has no detections and
        when the read fails; the caller cannot distinguish those, which is
        why failures are logged rather than swallowed silently. A read error
        surfacing as "no detections" would be an investigation concluding a
        host is clean because the API was down.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            found = await self._get_with_retry(
                client,
                "/detects/queries/detects/v1",
                {
                    "filter": f"device.device_id:'{device_id}'",
                    "limit": max(1, min(limit, 100)),
                    "sort": "last_behavior|desc",
                },
            )
            if found is None:
                logger.warning("crowdstrike.get_detections.query_failed", device_id=device_id)
                return []
            ids = found.json().get("resources", [])
            if not ids:
                return []

            resp = await client.post(
                f"{self._base_url}/detects/entities/summaries/GET/v1",
                headers=self._auth_headers(),
                json={"ids": ids},
            )
            if resp.status_code != 200:
                logger.warning(
                    "crowdstrike.get_detections.summary_failed",
                    device_id=device_id,
                    status=resp.status_code,
                )
                return []

            return [
                {
                    "detection_id": d.get("detection_id"),
                    "severity": d.get("max_severity_displayname"),
                    "tactic": d.get("behaviors", [{}])[0].get("tactic"),
                    "technique": d.get("behaviors", [{}])[0].get("technique"),
                    "filename": d.get("behaviors", [{}])[0].get("filename"),
                    "sha256": d.get("behaviors", [{}])[0].get("sha256"),
                    "last_behavior": d.get("last_behavior"),
                    "status": d.get("status"),
                }
                for d in resp.json().get("resources", [])
            ]

    async def _get_with_retry(self, client: httpx.AsyncClient, path: str, params: dict[str, Any]) -> httpx.Response | None:
        """GET with one re-auth retry. Returns None on a non-200.

        The re-auth-on-401 dance was duplicated at every call site, and a
        copy that forgets it fails intermittently once the token ages past
        thirty minutes — which is the hardest kind of bug to reproduce.
        """
        resp = await client.get(f"{self._base_url}{path}", headers=self._auth_headers(), params=params)
        if resp.status_code == 401:
            await self._authenticate(client)
            resp = await client.get(f"{self._base_url}{path}", headers=self._auth_headers(), params=params)
        return resp if resp.status_code == 200 else None

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

    async def _read_only_command(self, device_id: str, base_command: str, command_string: str) -> str | None:
        """Run an RTR *read* command and return this host's stdout.

        ``/real-time-response/combined/batch-command/v1`` is the read-only
        tier of the same batch API the containment commands above use —
        ``ls``, ``ps``, ``cat``, ``netstat``. It is a separate endpoint from
        ``batch-active-responder-command`` (``kill``, ``rm``) and
        ``batch-admin-command`` (``runscript``) precisely because it cannot
        change anything, so a verification path can hold read scope only.

        Returns ``None`` — never ``""`` — for every way this can fail to
        produce an answer: no session, a non-200, a host missing from the
        batch response, or a command the agent reported incomplete. The
        callers treat ``None`` as indeterminate, and an empty string is a
        real result (``ls`` on a path that is gone), so collapsing the two
        would turn "could not ask" into evidence.
        """
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                await self._ensure_token(client)
                batch_id = await self._init_rtr_session(client, device_id)
                resp = await client.post(
                    f"{self._base_url}/real-time-response/combined/batch-command/v1",
                    headers=self._auth_headers(),
                    json={
                        "base_command": base_command,
                        "batch_id": batch_id,
                        "command_string": command_string,
                        "optional_hosts": [device_id],
                    },
                )
                if resp.status_code != 200:
                    logger.warning(
                        "crowdstrike.read_only_command.http_error",
                        device_id=device_id,
                        base_command=base_command,
                        status=resp.status_code,
                    )
                    return None
                host = (resp.json().get("combined", {}).get("resources", {}) or {}).get(device_id)
                if not isinstance(host, dict):
                    return None
                if host.get("complete") is False:
                    # The agent is offline or still working. Not an answer.
                    return None
                stdout = host.get("stdout")
                return stdout if isinstance(stdout, str) else None
        except Exception as exc:  # noqa: BLE001 - indeterminate, never a false confirmation
            logger.warning(
                "crowdstrike.read_only_command.failed",
                device_id=device_id,
                base_command=base_command,
                error=str(exc),
            )
            return None

    async def is_process_running(self, device_id: str, pid: int) -> bool | None:
        """Whether ``pid`` still appears in the host's process table.

        The read-back for ``kill_process``, whose own response says only that
        RTR accepted a ``kill``. ``None`` means the question could not be
        answered.

        Absence is only trusted when the output looks like a process table —
        at least one line whose first column is a number. If RTR returns
        something this cannot parse, no PID is found, and reporting that as
        "the process is gone" would confirm a kill from output we did not
        understand. Only the first column is matched, so a surviving child
        listing the dead PID as its parent does not read as the process
        itself.
        """
        stdout = await self._read_only_command(device_id, "ps", "ps")
        if stdout is None:
            return None

        first_columns = [line.split()[0] for line in stdout.splitlines() if line.split()]
        numeric = [column for column in first_columns if column.isdigit()]
        if not numeric:
            logger.warning("crowdstrike.is_process_running.unparsed", device_id=device_id)
            return None
        return str(pid) in numeric

    async def path_exists(self, device_id: str, path: str) -> bool | None:
        """Whether ``path`` still resolves on the host.

        The read-back for ``quarantine_file``, which is implemented as an RTR
        ``rm``: the effect to confirm is the file's absence.

        ``ls`` on a path that is gone returns an error and no stdout, so an
        empty listing is the confirmation. That makes the empty string
        load-bearing, which is why ``_read_only_command`` distinguishes it
        from ``None``.
        """
        stdout = await self._read_only_command(device_id, "ls", f"ls '{path}'")
        if stdout is None:
            return None
        return bool(stdout.strip())
