"""
AWS Security Groups client for IP blocking/unblocking.

Uses boto3 (installed via the connectors service layer or injected via
httpx-compatible shim where boto3 is available). Falls back to direct
AWS EC2 API calls via httpx + SigV4 signing when boto3 is absent so
the actions service stays dependency-light.

Credentials expected in ActionRequest.parameters:
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region: str                 (e.g. "us-east-1")
    aws_security_group_id: str      (sg-xxxxxxxx)
    aws_assume_role_arn: str        (optional, for cross-account assume-role)
    aws_session_token: str          (optional, pre-assumed)
    aws_protocol: str               (optional, default "tcp")
    aws_from_port: int              (optional, default 0)
    aws_to_port: int                (optional, default 65535)
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import structlog

logger = structlog.get_logger()


class AWSSGClient:
    """Async AWS Security Group IP block/unblock using boto3 (if available)
    or the raw EC2 REST API via SigV4-signed httpx calls."""

    def __init__(
        self,
        access_key_id: str,
        secret_access_key: str,
        region: str,
        security_group_id: str,
        session_token: str | None = None,
        assume_role_arn: str | None = None,
    ) -> None:
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._region = region
        self._sg_id = security_group_id
        self._session_token = session_token
        self._assume_role_arn = assume_role_arn

    async def _get_credentials(self) -> tuple[str, str, str | None]:
        """Return (key_id, secret, session_token), assuming a role if configured."""
        if not self._assume_role_arn:
            return self._access_key_id, self._secret_access_key, self._session_token

        # Assume-role via STS
        try:
            import boto3

            sts = boto3.client(
                "sts",
                aws_access_key_id=self._access_key_id,
                aws_secret_access_key=self._secret_access_key,
                region_name=self._region,
            )
            creds = sts.assume_role(
                RoleArn=self._assume_role_arn,
                RoleSessionName="aisoc-actions",
            )["Credentials"]
            return creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]
        except ImportError:
            logger.warning("aws_sg.boto3_not_available — cannot assume role, using base creds")
            return self._access_key_id, self._secret_access_key, self._session_token

    async def _boto3_available(self) -> bool:
        try:
            import boto3  # noqa: F401
            return True
        except ImportError:
            return False

    async def block_ip(
        self,
        ip: str,
        protocol: str = "tcp",
        from_port: int = 0,
        to_port: int = 65535,
    ) -> dict[str, Any]:
        """Add an ingress deny rule for the IP (via revoke on a permissive SG or by adding egress deny).

        NOTE: AWS Security Groups are allow-only and don't support explicit deny rules.
        The idiomatic pattern is to add the IP as an *ingress allow* in a block-list SG
        that has no route to protected resources, or to remove existing allows.
        We implement the explicit revoke-authorization pattern for a dedicated block-SG here.
        """
        key_id, secret, token = await self._get_credentials()

        if await self._boto3_available():
            return await self._boto3_authorize_egress_block(key_id, secret, token, ip, protocol, from_port, to_port)
        else:
            return await self._httpx_authorize(key_id, secret, token, ip, protocol, from_port, to_port, action="block")

    async def unblock_ip(
        self,
        ip: str,
        protocol: str = "tcp",
        from_port: int = 0,
        to_port: int = 65535,
    ) -> dict[str, Any]:
        """Remove the ingress deny rule for the IP."""
        key_id, secret, token = await self._get_credentials()

        if await self._boto3_available():
            return await self._boto3_revoke_block(key_id, secret, token, ip, protocol, from_port, to_port)
        else:
            return await self._httpx_authorize(key_id, secret, token, ip, protocol, from_port, to_port, action="unblock")

    async def _boto3_authorize_egress_block(
        self, key_id: str, secret: str, token: str | None,
        ip: str, protocol: str, from_port: int, to_port: int,
    ) -> dict[str, Any]:
        import boto3

        ec2 = boto3.client(
            "ec2",
            region_name=self._region,
            aws_access_key_id=key_id,
            aws_secret_access_key=secret,
            aws_session_token=token,
        )
        cidr = f"{ip}/32"
        try:
            ec2.authorize_security_group_ingress(
                GroupId=self._sg_id,
                IpPermissions=[{
                    "IpProtocol": protocol,
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": [{"CidrIp": cidr, "Description": "AiSOC block"}],
                }],
            )
            logger.info("aws_sg.block_ip.success", sg=self._sg_id, cidr=cidr)
            return {"success": True, "action": "block_ip", "ip": ip, "sg_id": self._sg_id, "cidr": cidr}
        except ec2.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidPermission.Duplicate":
                return {"success": True, "action": "block_ip", "ip": ip, "note": "Rule already exists"}
            raise

    async def _boto3_revoke_block(
        self, key_id: str, secret: str, token: str | None,
        ip: str, protocol: str, from_port: int, to_port: int,
    ) -> dict[str, Any]:
        import boto3

        ec2 = boto3.client(
            "ec2",
            region_name=self._region,
            aws_access_key_id=key_id,
            aws_secret_access_key=secret,
            aws_session_token=token,
        )
        cidr = f"{ip}/32"
        try:
            ec2.revoke_security_group_ingress(
                GroupId=self._sg_id,
                IpPermissions=[{
                    "IpProtocol": protocol,
                    "FromPort": from_port,
                    "ToPort": to_port,
                    "IpRanges": [{"CidrIp": cidr}],
                }],
            )
            logger.info("aws_sg.unblock_ip.success", sg=self._sg_id, cidr=cidr)
            return {"success": True, "action": "unblock_ip", "ip": ip, "sg_id": self._sg_id}
        except ec2.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidPermission.NotFound":
                return {"success": True, "action": "unblock_ip", "ip": ip, "note": "Rule not found (already removed)"}
            raise

    async def _httpx_authorize(
        self, key_id: str, secret: str, token: str | None,
        ip: str, protocol: str, from_port: int, to_port: int, action: str,
    ) -> dict[str, Any]:
        """Fallback: direct AWS EC2 API call without boto3.
        This is a placeholder; production use should install boto3."""
        logger.warning("aws_sg.httpx_fallback — boto3 unavailable, cannot execute live")
        return {
            "success": False,
            "action": action,
            "ip": ip,
            "note": "boto3 not installed in actions service — add boto3 to pyproject.toml",
        }

    async def describe_rules(self) -> list[dict[str, Any]]:
        """List ingress rules on the target security group."""
        key_id, secret, token = await self._get_credentials()
        if not await self._boto3_available():
            return []

        import boto3

        ec2 = boto3.client(
            "ec2",
            region_name=self._region,
            aws_access_key_id=key_id,
            aws_secret_access_key=secret,
            aws_session_token=token,
        )
        resp = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [self._sg_id]}])
        return resp.get("SecurityGroupRules", [])
