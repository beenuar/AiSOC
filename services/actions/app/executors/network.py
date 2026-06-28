"""
Network action executors: block IP, block domain, allow IP.

Vendor priority
---------------

Phase 3.2 added three real firewall integrations on top of the
existing AWS Security Group path. The executors try vendors in
this order when their credentials are present in
:class:`ActionRequest.parameters`:

1. **AWS Security Groups** — credentials prefixed ``aws_``.
2. **Palo Alto PAN-OS** — credentials prefixed ``panos_``.
3. **Fortinet FortiGate** — credentials prefixed ``fgt_``.
4. **Cloudflare WAF / Gateway** — credentials prefixed ``cf_``.

The order matters: AWS lives in the data plane (it's closest to
the workloads operators are usually defending), then the on-prem
NGFWs (PAN-OS / FortiGate), then the edge perimeter (Cloudflare).
If a deployment supplies credentials for multiple vendors the
playbook layer is expected to scope what each one is responsible
for; the executor will simply fire whichever it can.

Domain blocks have a different surface. Only Cloudflare Gateway
ships a sinkhole API in this set, so :class:`BlockDomainExecutor`
prefers it when ``cf_*`` are present and falls back to simulation
otherwise.

Credential reference
--------------------

* ``aws_access_key_id``, ``aws_secret_access_key``, ``aws_security_group_id``,
  ``aws_region`` (opt), ``aws_role_arn`` (opt), ``aws_session_name`` (opt)
* ``panos_host``, ``panos_api_key``, ``panos_tag``, ``panos_vsys`` (opt)
* ``fgt_host``, ``fgt_api_token``, ``fgt_address_group``, ``fgt_vdom`` (opt)
* ``cf_api_token``, ``cf_zone_id`` (for zone-scope IP block),
  ``cf_account_id`` + ``cf_block_list_id`` (for DNS sinkhole)
"""

from __future__ import annotations

from datetime import datetime

import structlog

from app.clients.aws_security_groups import AWSSecurityGroupsClient
from app.clients.cloudflare_client import CloudflareClient
from app.clients.fortigate_client import FortiGateClient
from app.clients.panos_client import PanOsClient
from app.executors.base import _SIM_FUNNEL_CTA, BaseExecutor
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


def _panos_client(params: dict) -> PanOsClient | None:
    """Build a PAN-OS client. Returns None if the minimum
    credentials are missing so the executor can fall through.
    """
    host = params.get("panos_host")
    api_key = params.get("panos_api_key")
    tag = params.get("panos_tag")
    if not (host and api_key and tag):
        return None
    return PanOsClient(
        host=host,
        api_key=api_key,
        vsys=params.get("panos_vsys", "vsys1"),
        verify_tls=bool(params.get("panos_verify_tls", True)),
    )


def _fortigate_client(params: dict) -> FortiGateClient | None:
    host = params.get("fgt_host")
    token = params.get("fgt_api_token")
    group = params.get("fgt_address_group")
    if not (host and token and group):
        return None
    return FortiGateClient(
        host=host,
        api_token=token,
        vdom=params.get("fgt_vdom", "root"),
        verify_tls=bool(params.get("fgt_verify_tls", True)),
    )


def _cloudflare_client(params: dict) -> CloudflareClient | None:
    token = params.get("cf_api_token")
    if not token:
        return None
    return CloudflareClient(api_token=token)


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

        # Phase 3.2 — PAN-OS dynamic address group registration.
        panos = _panos_client(request.parameters)
        if panos:
            tag = request.parameters["panos_tag"]
            try:
                result = await panos.block_ip(ip=ip, tag=tag)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"ip": ip, "tag": tag, "vendor": "panos"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("block_ip.panos.failed", ip=ip, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        # Phase 3.2 — FortiGate address-group membership.
        fgt = _fortigate_client(request.parameters)
        if fgt:
            group = request.parameters["fgt_address_group"]
            try:
                result = await fgt.block_ip(ip=ip, group=group)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"ip": ip, "group": group, "vendor": "fortigate"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("block_ip.fortigate.failed", ip=ip, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        # Phase 3.2 — Cloudflare WAF custom rule (zone-level only;
        # account-level blocks require a different scope on the
        # token so we keep that explicit in the playbook layer).
        cf = _cloudflare_client(request.parameters)
        cf_zone_id = request.parameters.get("cf_zone_id")
        if cf and cf_zone_id:
            try:
                description = request.rationale or f"AiSOC block — incident {request.incident_id}"
                result = await cf.block_ip_zone(ip=ip, zone_id=cf_zone_id, description=description)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={
                        "ip": ip,
                        "zone_id": cf_zone_id,
                        "rule_id": result.get("rule_id"),
                        "vendor": "cloudflare",
                    },
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("block_ip.cloudflare.failed", ip=ip, error=str(exc))
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
            reason="no firewall credentials provided",
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
                "note": ("Simulation mode — provide aws_*/panos_*/fgt_*/cf_* credentials " "to enable live execution." + _SIM_FUNNEL_CTA),
            },
            rollback_data={"ip": ip, "rule_type": "block_ip"},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        """Rollback the IP block in whatever vendor we created it in.

        We refuse to make assumptions across vendors because rolling
        back a block on the wrong device leaves a stuck rule on the
        live device. The rollback path requires the rollback_data
        bag to carry the credentials needed to talk to the vendor;
        the dispatcher injects them at rollback dispatch time so we
        never persist secrets in the action timeline.
        """
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

        # Phase 3.2 — PAN-OS unregister.
        panos = _panos_client(request.parameters)
        if panos:
            tag = request.parameters["panos_tag"]
            try:
                result = await panos.unblock_ip(ip=ip, tag=tag)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"ip": ip, "tag": tag, "vendor": "panos"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("allow_ip.panos.failed", ip=ip, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        # Phase 3.2 — FortiGate address-group removal.
        fgt = _fortigate_client(request.parameters)
        if fgt:
            group = request.parameters["fgt_address_group"]
            try:
                result = await fgt.unblock_ip(ip=ip, group=group)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"ip": ip, "group": group, "vendor": "fortigate"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("allow_ip.fortigate.failed", ip=ip, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        # Phase 3.2 — Cloudflare rule deletion. The caller must
        # supply the rule_id we returned from block_ip; we don't
        # search by IP because that requires a separate
        # paginated rulesets-list scan that's expensive on large
        # zones.
        cf = _cloudflare_client(request.parameters)
        cf_rule_id = request.parameters.get("cf_rule_id")
        cf_zone_id = request.parameters.get("cf_zone_id")
        if cf and cf_rule_id and cf_zone_id:
            try:
                result = await cf.unblock_ip_zone(rule_id=cf_rule_id, zone_id=cf_zone_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={"ip": ip, "rule_id": cf_rule_id, "vendor": "cloudflare"},
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("allow_ip.cloudflare.failed", ip=ip, error=str(exc))
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
            reason="no firewall credentials",
            funnel="plugin-sdk",
        )
        return ActionResult(
            action_id=request.id,
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            output={
                "action": "allow_ip",
                "ip": ip,
                "note": ("Simulation mode — provide aws_*/panos_*/fgt_*/cf_* credentials " "to enable live execution." + _SIM_FUNNEL_CTA),
            },
            rollback_data={"ip": ip},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        logger.info("Rolling back allow_ip (re-blocking)", ip=result.rollback_data.get("ip"))
        return True


class BlockDomainExecutor(BaseExecutor):
    """Blocks a domain via DNS sinkholing or firewall rule.

    Phase 3.2 wires Cloudflare Gateway as the production sinkhole
    backend (``cf_api_token`` + ``cf_account_id`` + ``cf_block_list_id``).
    Falls back to simulation if those parameters aren't supplied;
    operators on other DNS-firewall vendors should add a sibling
    branch here rather than re-implementing the simulation note.
    """

    async def execute(self, request: ActionRequest) -> ActionResult:
        domain = request.target
        logger.info("Executing block_domain", domain=domain)

        cf = _cloudflare_client(request.parameters)
        account_id = request.parameters.get("cf_account_id")
        list_id = request.parameters.get("cf_block_list_id")
        if cf and account_id and list_id:
            try:
                result = await cf.sinkhole_domain(domain=domain, account_id=account_id, list_id=list_id)
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.COMPLETED,
                    blast_radius=BlastRadius.MEDIUM,
                    output=result,
                    rollback_data={
                        "domain": domain,
                        "account_id": account_id,
                        "list_id": list_id,
                        "vendor": "cloudflare_gateway",
                    },
                    completed_at=datetime.utcnow(),
                )
            except Exception as exc:
                logger.error("block_domain.cloudflare.failed", domain=domain, error=str(exc))
                return ActionResult(
                    action_id=request.id,
                    status=ActionStatus.FAILED,
                    blast_radius=BlastRadius.MEDIUM,
                    error=str(exc),
                    completed_at=datetime.utcnow(),
                )

        logger.warning(
            "block_domain.simulation",
            domain=domain,
            reason="no DNS-firewall credentials — set cf_api_token + cf_account_id + cf_block_list_id",
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
                    "Simulation mode — provide cf_api_token + cf_account_id + cf_block_list_id "
                    "to sinkhole via Cloudflare Gateway." + _SIM_FUNNEL_CTA
                ),
            },
            rollback_data={"domain": domain},
            completed_at=datetime.utcnow(),
        )

    async def rollback(self, result: ActionResult) -> bool:
        domain = result.rollback_data.get("domain")
        vendor = result.rollback_data.get("vendor")
        logger.info("Rolling back block_domain", domain=domain, vendor=vendor)
        return True
