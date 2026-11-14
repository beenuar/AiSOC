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

#: The Alerts API. `/detects/queries/detects/v1` and
#: `/detects/entities/summaries/GET/v1` were decommissioned on 2025-09-30 and
#: answer 404 (issue #1695); `PostCombinedAlertsV1` is the documented
#: replacement and carries the alert in one round trip.
_ALERTS_PATH = "/alerts/combined/alerts/v1"


class CrowdStrikeAlertsError(RuntimeError):
    """An alerts read could not be completed.

    Raised rather than returned as an empty list. "No alerts on this host"
    and "I could not ask" are different answers, and only one of them
    exonerates the host.
    """


def quote_fql_literal(value: str, *, field: str) -> str:
    """Render ``value`` as one single-quoted Falcon Query Language literal.

    ``device_id`` reaches here from the request parameters, so it is caller
    controlled, and FQL filters are assembled as text. Refused rather than
    escaped: an escaped value that reaches Falcon and matches nothing returns
    a clean result from a query that never asked the intended question, which
    on an investigation read is worse than an error. The refused set is only
    what can leave a single-quoted literal, so no real device id is rejected.
    """
    if not isinstance(value, str) or not value:
        raise CrowdStrikeAlertsError(f"{field} must be a non-empty string")
    bad = sorted({c for c in "'\\\n\r\x00" if c in value})
    if bad:
        printable = ", ".join(repr(c) for c in bad)
        raise CrowdStrikeAlertsError(f"{field} contains characters that cannot appear in an FQL literal: {printable}")
    return f"'{value}'"


def _alert_row(alert: dict[str, Any]) -> dict[str, Any]:
    """Project one Alerts-API alert onto the fields an investigation reads.

    An explicit projection rather than the raw record, for the same reason
    ``get_device`` uses one: the payload carries well over a hundred fields
    and an unbounded dict is an unbounded token cost.

    ``tactic``, ``technique``, ``filename`` and ``sha256`` sit on the alert
    itself here. The decommissioned Detects payload carried them under
    ``behaviors[0]``, so reading only from there returns None against every
    real Alerts response — the behaviours are still consulted as a fallback
    because an alert may carry them in both places.
    """
    behaviors = [b for b in (alert.get("behaviors") or []) if isinstance(b, dict)]

    def pick(key: str) -> Any:
        value = alert.get(key)
        if value:
            return value
        for behavior in behaviors:
            candidate = behavior.get(key)
            if candidate:
                return candidate
        return None

    return {
        "detection_id": alert.get("composite_id") or alert.get("id") or alert.get("detection_id"),
        "severity": alert.get("severity_name") or alert.get("max_severity_displayname") or alert.get("severity"),
        "tactic": pick("tactic"),
        "technique": pick("technique"),
        "filename": pick("filename"),
        "sha256": pick("sha256"),
        "occurred_at": alert.get("timestamp") or alert.get("created_timestamp"),
        "status": alert.get("status"),
        # Alerts are not EPP-only. A reader deciding what a finding means
        # needs to know whether it came from the endpoint sensor or from
        # identity protection, and the old Detects payload could not say.
        "product": alert.get("product"),
    }


#: Characters that can leave a single-quoted RTR argument. Deliberately small.
#:
#: Every interpolation below sits *inside* single quotes, where `&`, `|`, `;`,
#: `$`, `(`, `)` and `\` are literal — they were in the published payloads only
#: because the payload closed the quote with `'` first. Refusing them too would
#: reject `C:\Program Files (x86)\vendor\agent.exe`, an ordinary path on the
#: platform this verb is most used against, and a containment action that
#: refuses real Windows paths is not a usable control.
#:
#: So the set is the characters that actually break out:
#:   '   closes the quoted argument — the mechanism in all three reports
#:   `   delimits the -Raw=``` ``` block the runscript path wraps a body in
#:   \n \r  end the command line
#:   \x00   truncates it
_RTR_FORBIDDEN = frozenset("'`\n\r\x00")


class RtrArgumentError(ValueError):
    """An argument cannot be rendered as a single RTR argument.

    Raised rather than sanitised. These values name a file to delete or a
    script to run on a customer endpoint at the agent's privilege, so a
    silently-altered path is a wrong action taken on a real host, which is
    worse than a refusal an operator can read.
    """


def quote_rtr_argument(value: str, *, field: str) -> str:
    """Render ``value`` as one single-quoted RTR argument, or refuse it.

    RTR command strings are assembled as text and parsed by the agent, so an
    unescaped value is command injection executing as SYSTEM/root on the
    endpoint. Legitimate inputs here are filesystem paths, script names and
    argument strings; none of them need a quote or a shell operator, so the
    safe set is large enough to be practical and small enough to be provable.
    """
    if not isinstance(value, str):
        raise RtrArgumentError(f"{field} must be a string, got {type(value).__name__}")
    bad = sorted(_RTR_FORBIDDEN.intersection(value))
    if bad:
        printable = ", ".join(repr(c) for c in bad)
        raise RtrArgumentError(f"{field} contains characters that cannot appear in an RTR argument: {printable}")
    return f"'{value}'"


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
        """Recent alerts for one device, newest first.

        Raises ``CrowdStrikeAlertsError`` when the read fails. It used to
        return ``[]`` for both "no detections" and "could not read", and the
        caller cannot tell those apart: ``CrowdStrikeGetDetections`` reports
        SUCCEEDED with ``count: 0``, and an investigation reads that as the
        EDR having nothing on the host — the strongest exonerating evidence
        there is, from a call that never completed. Since the Detects API was
        decommissioned that was not an outage-only hazard but the answer on
        every deployment.
        """
        async with httpx.AsyncClient(timeout=30.0) as client:
            await self._ensure_token(client)
            body = {
                "filter": f"device.device_id:{quote_fql_literal(device_id, field='device_id')}",
                "limit": max(1, min(limit, 1000)),
                # `last_behavior` is a Detects field. An Alert is sortable on
                # created_timestamp, which is also what "newest first" means
                # for an alert rather than for its underlying behaviour.
                "sort": "created_timestamp|desc",
            }
            url = f"{self._base_url}{_ALERTS_PATH}"
            resp = await client.post(url, headers=self._auth_headers(), json=body)
            if resp.status_code == 401:
                await self._authenticate(client)
                resp = await client.post(url, headers=self._auth_headers(), json=body)
            if resp.status_code == 403:
                raise CrowdStrikeAlertsError(
                    "CrowdStrike refused the alerts read (403). This API client needs the "
                    "Alerts: Read scope, which is separate from the RTR scopes the response "
                    "actions use. Falcon console -> Support and resources -> API clients and "
                    "keys -> edit this client -> Alerts -> Read."
                )
            if resp.status_code != 200:
                logger.warning(
                    "crowdstrike.get_detections.failed",
                    device_id=device_id,
                    status=resp.status_code,
                )
                raise CrowdStrikeAlertsError(f"CrowdStrike alerts read returned HTTP {resp.status_code}")

            resources = resp.json().get("resources") or []
            return [_alert_row(alert) for alert in resources if isinstance(alert, dict)]

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
        # Before the session is opened, so a refused path costs no RTR session
        # and the caller sees the reason rather than a half-performed action.
        quoted_path = quote_rtr_argument(file_path, field="file_path")
        async with httpx.AsyncClient(timeout=60.0) as client:
            await self._ensure_token(client)
            batch_id = await self._init_rtr_session(client, device_id)

            resp = await client.post(
                f"{self._base_url}/real-time-response/combined/batch-active-responder-command/v1",
                headers=self._auth_headers(),
                json={
                    "base_command": "rm",
                    "batch_id": batch_id,
                    "command_string": f"rm {quoted_path}",
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
        # This probe runs automatically after a quarantine and solicits no
        # approval of its own, so an unescaped path here executes on the
        # endpoint with nobody having agreed to it.
        quoted_path = quote_rtr_argument(path, field="path")
        stdout = await self._read_only_command(device_id, "ls", f"ls {quoted_path}")
        if stdout is None:
            return None
        return bool(stdout.strip())
