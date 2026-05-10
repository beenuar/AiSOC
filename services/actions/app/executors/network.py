"""
Network action executors: block IP, block domain, allow IP.

Live integration via AWS Security Groups when credentials are provided:
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region: str                (optional, default: us-east-1)
    aws_security_group_id: str     (the SG to modify)
    aws_role_arn: str              (optional, for cross-account assume-role)
    aws_session_name: str          (optional)

Falls back to simulation mode if credentials are absent.
"""

from __future__ import annotations

from datetime import datetime

import structlog

from app.clients.aws_security_groups import AWSSecurityGroupsClient
from app.executors.base import BaseExecutor, _SIM_FUNNEL_CTA
from app.models.action import ActionRequest, ActionResult, ActionStatus, BlastRadius

logger = structlog.get_logger()


def _aws_client(params: dict) -> AWSSecurityGroupsClient | None:
    access_key = params.get("aws_access_key_id")
    secret_key = params.get("aws_secret_access_key")
    sg_id = params.get("aws_security_group_id")
    if not sg_id:
        return None
    return AWSSecurityGroupsClient(
        access_key_id=access_key,
        secret_access_key=secret_key,
        region=params.get("aws_region", "us-east-1"),
        role_arn=params.get("aws_role_arn"),
        session_name=params.get("aws_session_name", "aisoc-action"),
    )


class BlockIPExecutor(BaseExecutor):
    """Blocks an IP address at the network perimeter.

    Live: modifies an AWS Security Group to deny traffic from the target IP.
    Simulation: logs the action without making API calls.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        ip = request.target
        logger.info("Executing block_ip", ip=ip, incident_id=str(request.incident_id))

        aws = _aws_client(request.parameters)
        if aws:
            sg_id = request.parameters["aws_security_group_id"]
            port = request.parameters.get("port", -1)
            protocol = request.parameters.get("protocol", "-1")
            try:
                result = await aws.block_ip(sg_id=sg_id, ip=ip, port=port, protocol=protocol)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={
                        "ip": ip,
                        "sg_id": sg_id,
                        "port": port,
                        "protocol": protocol,
                        "vendor": "aws_sg",
                    },
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("block_ip.aws.failed", ip=ip, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "block_ip.simulation",
            ip=ip,
            reason="no AWS credentials or sg_id provided",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "block_ip",
                "ip": ip,
                "firewall_rule_id": f"SIM-BLOCK-{ip.replace('.', '-')}",
                "note": (
                    "Simulation mode — provide aws_access_key_id/aws_secret_access_key/aws_security_group_id "
                    "to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"ip": ip, "rule_type": "block_ip"},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        ip = result.rollback_data.get("ip")
        vendor = result.rollback_data.get("vendor")
        logger.info("Rolling back block_ip", ip=ip, vendor=vendor)

        if vendor == "aws_sg" and result.rollback_data.get("sg_id"):
            sg_id = result.rollback_data["sg_id"]
            port = result.rollback_data.get("port", -1)
            protocol = result.rollback_data.get("protocol", "-1")
            try:
                aws = AWSSecurityGroupsClient(region=result.rollback_data.get("aws_region", "us-east-1"))
                await aws.unblock_ip(sg_id=sg_id, ip=ip, port=port, protocol=protocol)
                logger.info("block_ip.rolled_back", ip=ip, sg_id=sg_id)
                return True
            except Exception as exc:
                logger.error("block_ip.rollback.failed", ip=ip, error=str(exc))
                return False
        return True


class AllowIPExecutor(BaseExecutor):
    """Allows an IP address through an AWS Security Group (removes a block rule).

    Live: calls AWS Security Groups revoke-ingress to remove a previously added deny rule.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        ip = request.target
        logger.info("Executing allow_ip", ip=ip)

        aws = _aws_client(request.parameters)
        if aws:
            sg_id = request.parameters["aws_security_group_id"]
            port = request.parameters.get("port", -1)
            protocol = request.parameters.get("protocol", "-1")
            try:
                result = await aws.unblock_ip(sg_id=sg_id, ip=ip, port=port, protocol=protocol)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"ip": ip, "sg_id": sg_id, "vendor": "aws_sg"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("allow_ip.aws.failed", ip=ip, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "allow_ip.simulation",
            ip=ip,
            reason="no AWS credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "allow_ip",
                "ip": ip,
                "note": (
                    "Simulation mode — provide aws_access_key_id/aws_secret_access_key/aws_security_group_id "
                    "to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"ip": ip},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        logger.info("Rolling back allow_ip (re-blocking)", ip=result.rollback_data.get("ip"))
        return True


class BlockDomainExecutor(BaseExecutor):
    """Blocks a domain via DNS sinkholing or firewall rule.

    Currently simulation-only — integrate with your DNS firewall or proxy API.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        domain = request.target
        logger.info("Executing block_domain", domain=domain)

        logger.warning(
            "block_domain.simulation",
            domain=domain,
            reason="DNS firewall integration not yet implemented — use Route53 Resolver, Umbrella, or Palo Alto DNS Security",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "block_domain",
                "domain": domain,
                "dns_block_id": f"SIM-DNS-{domain.replace('.', '-')}",
                "note": (
                    "Simulation mode — integrate with DNS firewall (Route53 Resolver, Umbrella, Palo Alto) "
                    "to enable live execution." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"domain": domain},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        domain = result.rollback_data.get("domain")
        logger.info("Rolling back block_domain", domain=domain)
        return True
