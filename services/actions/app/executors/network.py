"""
Network action executors: block IP, block domain.
These are simulation stubs — integrate with your firewall/EDR/SIEM APIs.
"""
from __future__ import annotations

from datetime import datetime

import structlog

from app.executors.base import BaseExecutor
from app.models.action import ActionRequest, ActionResult, ActionStatus

logger = structlog.get_logger()


class BlockIPExecutor(BaseExecutor):
    """Blocks an IP address at the network perimeter."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        ip = request.target
        logger.info("Executing block_ip", ip=ip, incident_id=str(request.incident_id))

        # TODO: integrate with firewall API (Palo Alto, FortiGate, AWS Security Groups, etc.)
        # Simulation: always succeed
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=request.parameters.get("blast_radius", "medium"),
            output={
                "action": "block_ip",
                "ip": ip,
                "firewall_rule_id": f"SIM-BLOCK-{ip.replace('.', '-')}",
                "note": "Simulation mode — integrate with firewall API",
            },
            rollback_data={"ip": ip, "rule_type": "block_ip"},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        ip = result.rollback_data.get("ip")
        logger.info("Rolling back block_ip", ip=ip)
        # TODO: remove firewall rule
        return True


class BlockDomainExecutor(BaseExecutor):
    """Blocks a domain via DNS sinkholing or firewall rule."""

    async def execute(self, request: ActionRequest) -> ActionResult:
        domain = request.target
        logger.info("Executing block_domain", domain=domain)

        # TODO: integrate with DNS firewall or proxy API
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=request.parameters.get("blast_radius", "medium"),
            output={
                "action": "block_domain",
                "domain": domain,
                "dns_block_id": f"SIM-DNS-{domain.replace('.', '-')}",
                "note": "Simulation mode — integrate with DNS firewall",
            },
            rollback_data={"domain": domain},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        domain = result.rollback_data.get("domain")
        logger.info("Rolling back block_domain", domain=domain)
        return True
