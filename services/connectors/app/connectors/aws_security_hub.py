"""
AWS Security Hub connector.
Fetches findings from AWS Security Hub via boto3.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


class AWSSecurityHubConnector(BaseConnector):
    connector_id = "aws_security_hub"
    connector_name = "AWS Security Hub"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description="AWS Security Hub findings (GuardDuty, Inspector, Macie, third-party).",
            docs_url="/docs/connectors/aws-security-hub",
            fields=[
                Field("region", "string", "AWS Region", default="us-east-1"),
                Field(
                    "access_key",
                    "string",
                    "Access Key ID",
                    required=False,
                    help_text="Leave blank to use the runtime IAM role / instance profile.",
                ),
                Field(
                    "secret_key",
                    "secret",
                    "Secret Access Key",
                    required=False,
                    help_text="Required only when supplying a static access key above.",
                ),
            ],
        )

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        # Security Hub aggregates findings from GuardDuty/Inspector/Macie/3p partners,
        # which we surface to the agent layer as alerts.
        # WS-E2: Live AWS Security Groups network blocking actions now wired
        # via services/actions/app/clients/aws_security_groups.py
        return (
            Capability.PULL_ALERTS,
            Capability.BLOCK_IP,
            Capability.ALLOW_IP,
        )

    def __init__(self, region: str = "us-east-1", access_key: str = "", secret_key: str = ""):
        self._region = region
        self._access_key = access_key
        self._secret_key = secret_key

    def _get_client(self):
        try:
            import boto3

            kwargs: dict[str, Any] = {"region_name": self._region}
            if self._access_key and self._secret_key:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            return boto3.client("securityhub", **kwargs)
        except ImportError as exc:
            raise RuntimeError("boto3 is required for AWS Security Hub connector. Install it with: pip install boto3") from exc

    async def test_connection(self) -> dict[str, Any]:
        try:
            client = self._get_client()
            client.describe_hub()
            return {"success": True, "connector": self.connector_id, "region": self._region}
        except Exception as exc:
            return {"success": False, "connector": self.connector_id, "error": str(exc)}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        client = self._get_client()
        since = (datetime.now(UTC) - timedelta(seconds=since_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")

        findings = []
        paginator = client.get_paginator("get_findings")
        pages = paginator.paginate(
            Filters={
                "UpdatedAt": [{"Start": since, "End": "9999-12-31T23:59:59Z"}],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            },
            PaginationConfig={"MaxItems": 200, "PageSize": 100},
        )
        for page in pages:
            findings.extend(page.get("Findings", []))

        return [self.normalize(f) for f in findings]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        severity_label = raw.get("Severity", {}).get("Label", "MEDIUM").lower()
        severity_map = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}

        return {
            "source": self.connector_id,
            "external_id": raw.get("Id", ""),
            "title": raw.get("Title", "AWS Security Hub Finding"),
            "description": raw.get("Description", ""),
            "severity": severity_map.get(severity_label, "medium"),
            "src_ip": raw.get("NetworkDestinationIpV4") or raw.get("NetworkSourceIpV4"),
            "aws_account_id": raw.get("AwsAccountId"),
            "aws_region": raw.get("Region"),
            "compliance_status": raw.get("Compliance", {}).get("Status"),
            "raw_event": raw,
            "created_at": raw.get("CreatedAt"),
        }
