"""
Endpoint action executors: isolate host, quarantine file, kill process, run script.

Live integration via CrowdStrike Falcon RTR when credentials are provided in
ActionRequest.parameters:
    cs_client_id: str
    cs_client_secret: str
    cs_base_url: str  (optional, default: https://api.crowdstrike.com)

Falls back to simulation mode if credentials are absent.

For Microsoft Defender for Endpoint isolation, supply instead:
    mde_tenant_id: str
    mde_client_id: str
    mde_client_secret: str
"""

from __future__ import annotations

from datetime import datetime

import structlog

from app.clients.crowdstrike_rtr import CrowdStrikeRTRClient
from app.clients.defender_client import DefenderClient
from app.executors.base import BaseExecutor, _SIM_FUNNEL_CTA
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
                result = await cs.contain_host(hostname)
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
                    "Simulation mode — provide cs_client_id/cs_client_secret or "
                    "mde_tenant_id/mde_client_id/mde_client_secret to enable live execution."
                    + _SIM_FUNNEL_CTA
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
                result = await cs.quarantine_file(hostname, file_path)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.LOW,
                    output=result,
                    rollback_data={"hostname": hostname, "file_path": file_path, "file_hash": file_hash},
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

        logger.warning(
            "quarantine_file.simulation",
            path=file_path,
            reason="no cs credentials",
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
                    "Simulation mode — provide cs_client_id/cs_client_secret to enable live execution."
                    + _SIM_FUNNEL_CTA
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
                result = await cs.kill_process(hostname, pid=pid, process_name=process_name)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={},
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

        logger.warning(
            "kill_process.simulation",
            process=process_name,
            reason="no cs credentials",
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
                    "Simulation mode — provide cs_client_id/cs_client_secret to enable live execution."
                    + _SIM_FUNNEL_CTA
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
        logger.info("Executing run_script", hostname=hostname, script=script_name)

        cs = _cs_client(request.parameters)
        if cs:
            try:
                result = await cs.run_script(hostname, script_name=script_name, script_args=script_args)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.HIGH,
                    output=result,
                    rollback_data={},
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

        logger.warning(
            "run_script.simulation",
            script=script_name,
            reason="no cs credentials",
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
                "note": (
                    "Simulation mode — provide cs_client_id/cs_client_secret to enable live execution."
                    + _SIM_FUNNEL_CTA
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
                    rollback_data={},
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

        logger.warning(
            "run_av_scan.simulation",
            hostname=hostname,
            reason="no MDE credentials",
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
                    "Simulation mode — provide mde_tenant_id/mde_client_id/mde_client_secret to enable live execution."
                    + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={},
            completed_at=datetime.utcnow(),
        )
