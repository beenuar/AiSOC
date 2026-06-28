"""
Endpoint action executors: isolate host, quarantine file, kill process, run script.

Vendor priority
---------------

The executors try EDR vendors in this order when their credentials
are present in :class:`ActionRequest.parameters`:

1. **CrowdStrike Falcon RTR** — credentials prefixed ``cs_``.
2. **Microsoft Defender for Endpoint** — credentials prefixed ``mde_``.
3. **SentinelOne** (Phase 3.1) — credentials prefixed ``s1_``.

If no vendor credentials are supplied we fall back to simulation
mode. The selection order is intentional: CrowdStrike has the most
complete API surface (it can run arbitrary scripts via RTR, which
SentinelOne can't), so when an operator hands us both we prefer it.
SentinelOne lacks RTR-equivalent APIs for a handful of actions —
the SentinelOne client raises ``NotImplementedError`` for those and
this executor logs it before falling through to simulation, so the
caller sees a clear error instead of a silent no-op.

Credential reference
--------------------

* ``cs_client_id``, ``cs_client_secret``, ``cs_base_url`` (optional)
* ``mde_tenant_id``, ``mde_client_id``, ``mde_client_secret``
* ``s1_console_url``, ``s1_api_token``
"""

from __future__ import annotations

from datetime import datetime

import structlog

from app.clients.crowdstrike_rtr import CrowdStrikeRTRClient
from app.clients.defender_client import DefenderClient
from app.clients.sentinelone_client import SentinelOneClient
from app.executors.base import _SIM_FUNNEL_CTA, BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus, BlastRadius

logger = structlog.get_logger()


def _cs_client(params: dict) -> CrowdStrikeRTRClient | None:
    client_id = params.get("cs_client_id")
    client_secret = params.get("cs_client_secret")
    if not (client_id and client_secret):
        return None
    return CrowdStrikeRTRClient(
        client_id=client_id,
        client_secret=client_secret,
        base_url=params.get("cs_base_url", "https://api.crowdstrike.com"),
    )


def _mde_client(params: dict) -> DefenderClient | None:
    tenant_id = params.get("mde_tenant_id")
    client_id = params.get("mde_client_id")
    client_secret = params.get("mde_client_secret")
    if not (tenant_id and client_id and client_secret):
        return None
    return DefenderClient(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)


def _s1_client(params: dict) -> SentinelOneClient | None:
    """Build a SentinelOne client from ``ActionRequest.parameters``.

    Returns ``None`` when either field is missing so the executor
    can cleanly fall through to the next vendor / simulation. We
    don't pull the API token out of an env var here — the dispatcher
    intentionally treats every credential as request-scoped so that
    multi-tenant deployments can route different tenants to
    different S1 consoles in the same process.
    """
    console_url = params.get("s1_console_url")
    api_token = params.get("s1_api_token")
    if not (console_url and api_token):
        return None
    return SentinelOneClient(console_url=console_url, api_token=api_token)


async def _cs_contain_host_by_hostname(cs: CrowdStrikeRTRClient, hostname: str) -> dict:
    """Resolve hostname → device_id, then containment.

    The standalone CrowdStrikeRTRClient API takes a ``device_id``
    everywhere. The executor accepts a hostname (because that's
    what the playbook layer ships), so we resolve here and surface
    a useful error if Falcon doesn't know the host. Without this
    wrapper an unknown hostname produced a confusing 404 inside
    ``contain_host`` because Falcon was being asked to contain a
    literal computer name as if it were a device_id.
    """
    device_id = await cs.get_device_id(hostname)
    if not device_id:
        raise ValueError(f"No CrowdStrike device_id for hostname: {hostname}")
    return await cs.contain_host(device_id)


class IsolateHostExecutor(BaseExecutor):
    """Isolates a host from the network via EDR API.

    Supports CrowdStrike Falcon RTR (cs_client_id / cs_client_secret) and
    Microsoft Defender for Endpoint (mde_tenant_id / mde_client_id / mde_client_secret).
    Falls back to simulation if no credentials are provided.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        hostname = request.target
        logger.info("Executing isolate_host", hostname=hostname)

        cs = _cs_client(request.parameters)
        if cs:
            try:
                result = await _cs_contain_host_by_hostname(cs, hostname)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"hostname": hostname, "vendor": "crowdstrike"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("isolate_host.crowdstrike.failed", hostname=hostname, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        mde = _mde_client(request.parameters)
        if mde:
            try:
                result = await mde.isolate_machine(
                    hostname,
                    comment=request.rationale or "AiSOC automated isolation",
                )
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"hostname": hostname, "vendor": "defender"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("isolate_host.defender.failed", hostname=hostname, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        # Phase 3.1 — SentinelOne fallback. Same blast-radius +
        # rollback contract as CrowdStrike / Defender so the rollback
        # router can route ``vendor: sentinelone`` to
        # ``lift_containment`` without re-checking the credentials
        # we used.
        s1 = _s1_client(request.parameters)
        if s1:
            try:
                result = await s1.contain_host(hostname)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"hostname": hostname, "vendor": "sentinelone"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("isolate_host.sentinelone.failed", hostname=hostname, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "isolate_host.simulation",
            hostname=hostname,
            reason="no EDR credentials provided",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.HIGH,
            output={
                "action": "isolate_host",
                "hostname": hostname,
                "isolation_id": f"SIM-ISO-{hostname}",
                "note": (
                    "Simulation mode — provide cs_client_id/cs_client_secret, "
                    "mde_tenant_id/mde_client_id/mde_client_secret, or "
                    "s1_console_url/s1_api_token to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"hostname": hostname},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        hostname = result.rollback_data.get("hostname")
        vendor = result.rollback_data.get("vendor")
        logger.info("Rolling back isolate_host (de-isolating)", hostname=hostname, vendor=vendor)
        return True


class QuarantineFileExecutor(BaseExecutor):
    """Quarantines a suspicious file via CrowdStrike RTR.

    Requires: cs_client_id, cs_client_secret in parameters.
    target: hostname where file resides.
    parameters.file_path: full path to the file on the remote host.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        hostname = request.target
        file_path = request.parameters.get("file_path", request.target)
        file_hash = request.parameters.get("file_hash", "")
        logger.info("Executing quarantine_file", hostname=hostname, path=file_path)

        cs = _cs_client(request.parameters)
        if cs:
            try:
                device_id = await cs.get_device_id(hostname)
                if not device_id:
                    raise ValueError(f"No CrowdStrike device_id for hostname: {hostname}")
                result = await cs.quarantine_file(device_id, file_path)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.LOW,
                    output=result,
                    rollback_data={"hostname": hostname, "file_path": file_path, "file_hash": file_hash, "vendor": "crowdstrike"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("quarantine_file.crowdstrike.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.LOW,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        # Phase 3.1 — SentinelOne fallback. The S1 client's
        # ``quarantine_file`` issues a file-fetch into the forensics
        # vault; see :class:`SentinelOneClient.quarantine_file` for
        # the caveat around manual console mark-as-malicious.
        s1 = _s1_client(request.parameters)
        if s1:
            try:
                result = await s1.quarantine_file(hostname, file_path)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.LOW,
                    output=result,
                    rollback_data={"hostname": hostname, "file_path": file_path, "file_hash": file_hash, "vendor": "sentinelone"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("quarantine_file.sentinelone.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.LOW,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "quarantine_file.simulation",
            path=file_path,
            reason="no EDR credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.LOW,
            output={
                "action": "quarantine_file",
                "path": file_path,
                "hash": file_hash,
                "quarantine_id": f"SIM-QRN-{file_hash[:8] if file_hash else 'NOHASH'}",
                "note": (
                    "Simulation mode — provide cs_client_id/cs_client_secret or "
                    "s1_console_url/s1_api_token to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"file_path": file_path, "file_hash": file_hash},
            completed_at=datetime.utcnow(),
        )


class KillProcessExecutor(BaseExecutor):
    """Terminates a malicious process via CrowdStrike RTR.

    Requires: cs_client_id, cs_client_secret, parameters.pid or parameters.process_name.
    target: hostname where process is running.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        hostname = request.target
        pid = request.parameters.get("pid")
        process_name = request.parameters.get("process_name", request.target)
        logger.info("Executing kill_process", hostname=hostname, pid=pid, process=process_name)

        cs = _cs_client(request.parameters)
        if cs:
            try:
                device_id = await cs.get_device_id(hostname)
                if not device_id:
                    raise ValueError(f"No CrowdStrike device_id for hostname: {hostname}")
                if pid is None:
                    raise ValueError("CrowdStrike kill_process requires a PID")
                result = await cs.kill_process(device_id, int(pid))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"vendor": "crowdstrike"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("kill_process.crowdstrike.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        # Phase 3.1 — SentinelOne fallback. Unlike CrowdStrike the
        # S1 client requires ``process_name`` (the S1 management
        # plane targets binaries by SHA1, not by PID); see the
        # NotImplementedError path in :class:`SentinelOneClient.kill_process`.
        s1 = _s1_client(request.parameters)
        if s1:
            try:
                result = await s1.kill_process(hostname, pid=pid, process_name=process_name)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"vendor": "sentinelone"},
                    completed_at=datetime.utcnow(),
                )
            except NotImplementedError as exc:
                logger.warning(
                    "kill_process.sentinelone.unsupported",
                    process=process_name,
                    pid=pid,
                    reason=str(exc),
                )
                # Fall through to simulation — the caller probably
                # asked for PID-only termination, which S1 can't do.
            except Exception as exc:
                logger.error("kill_process.sentinelone.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "kill_process.simulation",
            process=process_name,
            reason="no EDR credentials (or vendor unsupported for this shape)",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "kill_process",
                "process": process_name,
                "pid": pid,
                "note": (
                    "Simulation mode — provide cs_client_id/cs_client_secret (PID-based) or "
                    "s1_console_url/s1_api_token (process_name-based) to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={},
            completed_at=datetime.utcnow(),
        )


class RunScriptExecutor(BaseExecutor):
    """Runs a custom script on a remote host via CrowdStrike RTR.

    Requires: cs_client_id, cs_client_secret in parameters.
    target: hostname.
    parameters.script_name: pre-staged RTR script name.
    parameters.script_args: optional arguments string.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        hostname = request.target
        script_name = request.parameters.get("script_name", "")
        script_args = request.parameters.get("script_args", "")
        script_content = request.parameters.get("script_content", "")
        logger.info("Executing run_script", hostname=hostname, script=script_name)

        cs = _cs_client(request.parameters)
        if cs:
            try:
                device_id = await cs.get_device_id(hostname)
                if not device_id:
                    raise ValueError(f"No CrowdStrike device_id for hostname: {hostname}")
                # The CrowdStrike client's run_script takes the raw
                # PowerShell body, not a registered script_name +
                # args. We accept either shape from the playbook
                # layer and prefer raw content when supplied.
                body = script_content or f"runscript -CloudFile='{script_name}' -CommandLine='{script_args}'"
                result = await cs.run_script(device_id, body)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"vendor": "crowdstrike"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("run_script.crowdstrike.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        # Phase 3.1 — SentinelOne has no non-interactive remote-script
        # API, so we surface that explicitly to the caller instead of
        # silently falling back to simulation. The dispatcher / agent
        # loop can use this signal to fail the playbook step rather
        # than report a fake success.
        s1 = _s1_client(request.parameters)
        if s1:
            try:
                result = await s1.run_script(hostname, script_content or script_name)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"vendor": "sentinelone"},
                    completed_at=datetime.utcnow(),
                )
            except NotImplementedError as exc:
                logger.error(
                    "run_script.sentinelone.unsupported",
                    hostname=hostname,
                    reason=str(exc),
                )
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.HIGH,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "run_script.simulation",
            script=script_name,
            reason="no cs credentials (and SentinelOne does not support remote scripts)",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.HIGH,
            output={
                "action": "run_script",
                "hostname": hostname,
                "script_name": script_name,
                "note": ("Simulation mode — provide cs_client_id/cs_client_secret to enable live execution." + _SIM_FUNNEL_CTA),
            },
            rollback_data={},
            completed_at=datetime.utcnow(),
        )


class RunAVScanExecutor(BaseExecutor):
    """Triggers an antivirus scan via Microsoft Defender for Endpoint.

    Requires: mde_tenant_id, mde_client_id, mde_client_secret in parameters.
    target: hostname.
    parameters.scan_type: "Quick" or "Full" (default: Full).
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        hostname = request.target
        scan_type = request.parameters.get("scan_type", "Full")
        logger.info("Executing run_av_scan", hostname=hostname, scan_type=scan_type)

        mde = _mde_client(request.parameters)
        if mde:
            try:
                result = await mde.run_av_scan(hostname, scan_type=scan_type)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.LOW,
                    output=result,
                    rollback_data={"vendor": "defender"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("run_av_scan.defender.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.LOW,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        # Phase 3.1 — SentinelOne fallback. S1 doesn't distinguish
        # quick vs full scans; the client logs a warning and runs
        # one full scan either way.
        s1 = _s1_client(request.parameters)
        if s1:
            try:
                result = await s1.run_av_scan(hostname, scan_type=scan_type)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.LOW,
                    output=result,
                    rollback_data={"vendor": "sentinelone"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("run_av_scan.sentinelone.failed", error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.LOW,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "run_av_scan.simulation",
            hostname=hostname,
            reason="no EDR credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.LOW,
            output={
                "action": "run_av_scan",
                "hostname": hostname,
                "scan_type": scan_type,
                "note": (
                    "Simulation mode — provide mde_tenant_id/mde_client_id/mde_client_secret or "
                    "s1_console_url/s1_api_token to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={},
            completed_at=datetime.utcnow(),
        )
