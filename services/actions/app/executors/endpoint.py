"""
Endpoint action executors: isolate host, quarantine file, kill process.
"""
from __future__ import annotations

from datetime import datetime

import structlog

from app.executors.base import BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus

logger = structlog.get_logger()


class IsolateHostExecutor(BaseExecutor):
    """Isolates a host from the network via EDR API."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        hostname = request.target
        logger.info("Executing isolate_host", hostname=hostname)

        # TODO: integrate with CrowdStrike, SentinelOne, Defender, etc.
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius="high",
            output={
                "action": "isolate_host",
                "hostname": hostname,
                "isolation_id": f"SIM-ISO-{hostname}",
                "note": "Simulation mode — integrate with EDR API",
            },
            rollback_data={"hostname": hostname},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        hostname = result.rollback_data.get("hostname")
        logger.info("Rolling back isolate_host (de-isolating)", hostname=hostname)
        # TODO: call EDR API to lift isolation
        return True


class QuarantineFileExecutor(BaseExecutor):
    """Quarantines a suspicious file via EDR."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        file_path = request.target
        file_hash = request.parameters.get("file_hash", "")
        logger.info("Executing quarantine_file", path=file_path, hash=file_hash)

        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius="low",
            output={
                "action": "quarantine_file",
                "path": file_path,
                "hash": file_hash,
                "quarantine_id": f"SIM-QRN-{file_hash[:8]}",
                "note": "Simulation mode — integrate with EDR API",
            },
            rollback_data={"file_path": file_path, "file_hash": file_hash},
            completed_at=datetime.utcnow(),
        )


class KillProcessExecutor(BaseExecutor):
    """Terminates a malicious process."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        process = request.target
        pid = request.parameters.get("pid")
        logger.info("Executing kill_process", process=process, pid=pid)

        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius="medium",
            output={
                "action": "kill_process",
                "process": process,
                "pid": pid,
                "note": "Simulation mode — integrate with EDR API",
            },
            rollback_data={},
            completed_at=datetime.utcnow(),
        )
