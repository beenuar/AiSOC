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

# Re-exported from app.clients.factories, which is where these now live so
# app.services.rollback can import them without creating a cycle back into
# this module. Imported here because rollback and verification import them
# from this path, and tests monkeypatch them here.
from app.clients.factories import (  # noqa: F401
    _cortex_client,
    _cs_client,
    _mde_client,
    _s1_client,
)
from app.executors.base import _SIM_FUNNEL_CTA, BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus, ActionType, BlastRadius
from app.services.rollback import reverse_via_rollback_service

logger = structlog.get_logger()


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

        # Cortex XDR fallback — same blast-radius + rollback contract so the
        # rollback router can route ``vendor: cortex_xdr`` to ``lift_containment``.
        cortex = _cortex_client(request.parameters)
        if cortex:
            try:
                result = await cortex.contain_host(hostname)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={"hostname": hostname, "vendor": "cortex_xdr"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("isolate_host.cortex_xdr.failed", hostname=hostname, error=str(exc))
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
                    "mde_tenant_id/mde_client_id/mde_client_secret, "
                    "s1_console_url/s1_api_token, or "
                    "cortex_api_key_id/cortex_api_key/cortex_fqdn to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"hostname": hostname},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        """De-isolate the host by actually calling the EDR.

        This used to log "Rolling back isolate_host (de-isolating)" and return
        True without contacting any vendor, so an operator who clicked rollback
        was told the host was released while it stayed contained.
        `reverse_action` holds the real lift-containment calls for CrowdStrike,
        Defender and SentinelOne; it reports `simulated` when credentials are
        absent rather than claiming success.
        """
        hostname = result.rollback_data.get("hostname")
        return await reverse_via_rollback_service(
            ActionType.ISOLATE_HOST,
            hostname,
            result.rollback_data,
            logger,
        )


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


#: The MDE machine-action type a forensic acquisition produces. Named once so
#: the executor and the verification probe cannot look for different things.
INVESTIGATION_PACKAGE_ACTION = "CollectInvestigationPackage"

#: The MDE machine-action type an antivirus sweep produces, for the same
#: reason. ``DefenderClient.run_av_scan`` posts to ``/runAntiVirusScan`` and
#: returns the queued action's id; this is what that action is called when
#: the verification probe has to find it by type instead.
AV_SCAN_ACTION = "RunAntiVirusScan"


class CaptureForensicsExecutor(BaseExecutor):
    """Acquire a forensic evidence package from a host.

    ``capture_forensics`` was an ``ActionType`` with no executor behind it,
    and ``services/agents`` proposes it by name whenever an investigation maps
    to the C2 or exfiltration stage. So on the one class of incident where
    preserving evidence matters most, the product recommended an acquisition
    it could not perform and an analyst who approved it got "No executor found
    for action type" — which reads as a broken deployment rather than a verb
    nobody built.

    Defender only, deliberately
    ---------------------------
    Microsoft Defender's investigation package is the one broad acquisition in
    this service's vendor set: the agent bundles processes, network
    connections, registry, prefetch, scheduled tasks and event logs, and MDE
    exposes both the collection's completion state and a download URI, so the
    claim "evidence exists" is checkable rather than inferred from a 202.

    CrowdStrike RTR's ``get`` retrieves one *named file*, which is a different
    verb with a different blast radius. Wiring it here would make
    ``capture_forensics`` mean "collect the host's forensic package" on one
    vendor and "fetch this path" on another — the per-vendor drift the
    capability contract exists to prevent. A tenant without MDE credentials
    gets an honest simulation naming what to configure, not a fabricated
    acquisition.

    Reports ``RUNNING``, not ``COMPLETED``
    --------------------------------------
    Collection is asynchronous: MDE queues a machine action and the package
    appears minutes later. Reporting the queued request as completed is the
    same gap as reporting an accepted isolate call as a contained host — an
    analyst reads "done" and stops looking for the evidence. ``RUNNING`` says
    what is true: the acquisition started and the package is not there yet.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        hostname = request.target
        logger.info("Executing capture_forensics", hostname=hostname)

        mde = _mde_client(request.parameters)
        if mde:
            try:
                result = await mde.collect_investigation_package(
                    hostname,
                    comment=request.rationale or "AiSOC forensic acquisition",
                )
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.RUNNING,
                    blast_radius=BlastRadius.LOW,
                    output={
                        **result,
                        # `executed` is the single field meaning a vendor was
                        # actually touched. The acquisition being unfinished is
                        # carried by `package_ready`, not by pretending nothing
                        # ran.
                        "executed": True,
                        "package_ready": False,
                        "vendor": "defender",
                    },
                    rollback_data={"hostname": hostname, "vendor": "defender"},
                )
            except Exception as exc:
                logger.error("capture_forensics.defender.failed", hostname=hostname, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.LOW,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "capture_forensics.simulation",
            hostname=hostname,
            reason="no Defender credentials provided",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.LOW,
            output={
                "action": "capture_forensics",
                "hostname": hostname,
                "executed": False,
                "package_ready": False,
                "note": (
                    "Simulation mode — provide mde_tenant_id/mde_client_id/mde_client_secret "
                    "to collect a Defender investigation package." + _SIM_FUNNEL_CTA
                ),
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
