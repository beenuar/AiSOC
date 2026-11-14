"""
AWS Security Groups client for IP block / unblock actions.

Used by ``app.executors.network`` to enforce containment via a dedicated AWS
Security Group. boto3 is the supported transport; when boto3 is unavailable the
client returns a structured stub so the actions service still boots and the
executor can fall back to simulation mode.

Credential resolution (all optional — when omitted, boto3 falls back to its
default chain: env vars, ``~/.aws/credentials``, IAM instance profile, IRSA):
    region (str)                  — AWS region, default ``us-east-1``
    access_key_id (str | None)
    secret_access_key (str | None)
    session_token (str | None)
    security_group_id (str | None) — may be supplied per-call instead
    role_arn (str | None)          — optional cross-account assume-role
    session_name (str)             — STS session name when assuming a role

Both ``AWSSecurityGroupsClient`` and the legacy ``AWSSGClient`` alias are
exported, so existing callers using either name keep working.
"""

from __future__ import annotations

from typing import Any

import structlog

logger = structlog.get_logger()


class AWSSecurityGroupsClient:
    """Async wrapper around EC2 ``authorize`` / ``revoke`` security-group ingress.

    The class is intentionally tolerant of how callers supply parameters:

    * ``security_group_id`` may be provided at construction *or* passed per-call
      as ``sg_id=`` (the latter is what ``app.executors.network`` does).
    * Credentials are optional. If absent, boto3's default credential chain is
      used (env vars / shared config / IAM role / IRSA), which is the right
      behaviour for in-cluster deployments.
    * ``port`` follows AWS conventions: ``-1`` (or ``None``) means "all ports"
      and is paired with ``IpProtocol="-1"`` for "all protocols".
    """

    def __init__(
        self,
        *,
        region: str = "us-east-1",
        access_key_id: str | None = None,
        secret_access_key: str | None = None,
        session_token: str | None = None,
        security_group_id: str | None = None,
        role_arn: str | None = None,
        session_name: str = "aisoc-actions",
        # Legacy aliases retained for backward compatibility.
        assume_role_arn: str | None = None,
        sg_id: str | None = None,
    ) -> None:
        self._region = region
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._session_token = session_token
        self._sg_id = security_group_id or sg_id
        self._role_arn = role_arn or assume_role_arn
        self._session_name = session_name

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _port_range(port: int | None) -> tuple[int, int]:
        """Translate executor port semantics into AWS ``(FromPort, ToPort)``.

        ``-1`` and ``None`` mean "all ports", anything else is treated as a
        single port (FromPort == ToPort == port).
        """
        if port is None or port == -1:
            return -1, -1
        return port, port

    def _resolve_sg_id(self, sg_id: str | None) -> str:
        resolved = sg_id or self._sg_id
        if not resolved:
            raise ValueError("security_group_id is required (set at construct time or pass sg_id=)")
        return resolved

    @staticmethod
    def _boto3_available() -> bool:
        try:
            import boto3  # noqa: F401

            return True
        except ImportError:
            return False

    async def _get_credentials(self) -> tuple[str | None, str | None, str | None]:
        """Return ``(key_id, secret, token)``, assuming a role if configured.

        Falls through to the configured static credentials (or ``None`` to let
        boto3 use its default chain) when assume-role is not requested or when
        boto3 is unavailable.
        """
        if not self._role_arn or not self._boto3_available():
            return self._access_key_id, self._secret_access_key, self._session_token

        import boto3

        sts = boto3.client(
            "sts",
            aws_access_key_id=self._access_key_id,
            aws_secret_access_key=self._secret_access_key,
            region_name=self._region,
        )
        creds = sts.assume_role(
            RoleArn=self._role_arn,
            RoleSessionName=self._session_name,
        )["Credentials"]
        return creds["AccessKeyId"], creds["SecretAccessKey"], creds["SessionToken"]

    def _ec2(
        self,
        key_id: str | None,
        secret: str | None,
        token: str | None,
    ):
        import boto3

        return boto3.client(
            "ec2",
            region_name=self._region,
            aws_access_key_id=key_id,
            aws_secret_access_key=secret,
            aws_session_token=token,
        )

    @staticmethod
    def _unavailable(action: str, ip: str) -> dict[str, Any]:
        logger.warning("aws_sg.boto3_unavailable", action=action, ip=ip)
        return {
            "success": False,
            "action": action,
            "ip": ip,
            "note": ("boto3 not installed in actions service — install boto3 to enable live AWS Security Group execution."),
        }

    # ------------------------------------------------------------------
    # Public API used by app.executors.network
    # ------------------------------------------------------------------

    async def block_ip(
        self,
        ip: str,
        *,
        sg_id: str | None = None,
        protocol: str = "-1",
        port: int | None = None,
        from_port: int | None = None,
        to_port: int | None = None,
    ) -> dict[str, Any]:
        """Authorize an ingress rule for ``ip`` on the dedicated block-list SG."""
        sg = self._resolve_sg_id(sg_id)
        if from_port is None or to_port is None:
            from_port, to_port = self._port_range(port)

        if not self._boto3_available():
            return self._unavailable("block_ip", ip)

        key_id, secret, token = await self._get_credentials()
        ec2 = self._ec2(key_id, secret, token)
        cidr = f"{ip}/32"

        try:
            ec2.authorize_security_group_ingress(
                GroupId=sg,
                IpPermissions=[
                    {
                        "IpProtocol": protocol,
                        "FromPort": from_port,
                        "ToPort": to_port,
                        "IpRanges": [{"CidrIp": cidr, "Description": "AiSOC block"}],
                    }
                ],
            )
            logger.info("aws_sg.block_ip.success", sg=sg, cidr=cidr)
            return {
                "success": True,
                "action": "block_ip",
                "ip": ip,
                "sg_id": sg,
                "cidr": cidr,
            }
        except ec2.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidPermission.Duplicate":
                return {
                    "success": True,
                    "action": "block_ip",
                    "ip": ip,
                    "sg_id": sg,
                    "note": "Rule already exists",
                }
            raise

    async def unblock_ip(
        self,
        ip: str,
        *,
        sg_id: str | None = None,
        protocol: str = "-1",
        port: int | None = None,
        from_port: int | None = None,
        to_port: int | None = None,
    ) -> dict[str, Any]:
        """Revoke a previously authorized ingress rule for ``ip``."""
        sg = self._resolve_sg_id(sg_id)
        if from_port is None or to_port is None:
            from_port, to_port = self._port_range(port)

        if not self._boto3_available():
            return self._unavailable("unblock_ip", ip)

        key_id, secret, token = await self._get_credentials()
        ec2 = self._ec2(key_id, secret, token)
        cidr = f"{ip}/32"

        try:
            ec2.revoke_security_group_ingress(
                GroupId=sg,
                IpPermissions=[
                    {
                        "IpProtocol": protocol,
                        "FromPort": from_port,
                        "ToPort": to_port,
                        "IpRanges": [{"CidrIp": cidr}],
                    }
                ],
            )
            logger.info("aws_sg.unblock_ip.success", sg=sg, cidr=cidr)
            return {
                "success": True,
                "action": "unblock_ip",
                "ip": ip,
                "sg_id": sg,
            }
        except ec2.exceptions.ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidPermission.NotFound":
                return {
                    "success": True,
                    "action": "unblock_ip",
                    "ip": ip,
                    "sg_id": sg,
                    "note": "Rule not found (already removed)",
                }
            raise

    async def describe_rules(self, sg_id: str | None = None) -> list[dict[str, Any]]:
        """List ingress rules on the target security group (empty when boto3 missing)."""
        sg = self._resolve_sg_id(sg_id)
        if not self._boto3_available():
            return []

        key_id, secret, token = await self._get_credentials()
        ec2 = self._ec2(key_id, secret, token)
        resp = ec2.describe_security_group_rules(Filters=[{"Name": "group-id", "Values": [sg]}])
        return resp.get("SecurityGroupRules", [])


# Legacy alias: older code (and external plugins) may import the short name.
AWSSGClient = AWSSecurityGroupsClient


__all__ = ["AWSSecurityGroupsClient", "AWSSGClient"]
