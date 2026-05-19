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

    # T1.2 — config snapshots
    #
    # AWS Config is the canonical "what did this resource look like at
    # ts?" surface for AWS resources, so ``get_resource_config`` walks
    # it (via ``BatchGetResourceConfig`` / ``GetResourceConfigHistory``)
    # rather than the per-service ``describe_*`` APIs.
    #
    # Two specific stretches of ARN we handle natively:
    #
    #   - ``arn:aws:cloudtrail:...`` — return the CloudTrail trail
    #     config (from ``cloudtrail.describe_trails`` + recent event
    #     selectors). This is the "trail tampering" forensic story.
    #
    #   - ``arn:aws:iam::*:policy/*`` — return the IAM policy version
    #     effective at ts (we resolve via ``list_policy_versions`` and
    #     pick the latest version <= ts).
    #
    # All other ARNs fall through to ``config:get_resource_config_history``.
    # If AWS Config isn't recording the resource, we surface
    # ``{"error": "not recorded"}`` rather than raising — the ingest
    # snapshotter then records "no config" rather than failing the path.

    async def get_resource_config(self, resource_id: str, ts: str) -> dict[str, Any]:
        if not resource_id:
            return {}
        # boto3 is synchronous; the connector path is async, so we run
        # the lookup in a worker thread to avoid blocking the event loop.
        # We accept the small thread-pool overhead here because the
        # ingest snapshotter caches results aggressively (TTL bucket).
        import asyncio

        return await asyncio.to_thread(self._get_resource_config_sync, resource_id, ts)

    def _get_resource_config_sync(self, resource_id: str, ts: str) -> dict[str, Any]:
        # Lazy-import boto3 so unit tests that don't exercise this path
        # don't need it installed. Same pattern as ``_get_client``.
        try:
            import boto3  # noqa: F401
        except ImportError:
            return {"error": "boto3 not installed"}

        # Route by ARN service.
        if "arn:aws:cloudtrail:" in resource_id:
            return self._cloudtrail_config(resource_id)
        if ":iam::" in resource_id and ":policy/" in resource_id:
            return self._iam_policy_config(resource_id, ts)
        return self._aws_config_history(resource_id, ts)

    def _cloudtrail_config(self, trail_arn: str) -> dict[str, Any]:
        try:
            import boto3

            kwargs: dict[str, Any] = {"region_name": self._region}
            if self._access_key and self._secret_key:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            ct = boto3.client("cloudtrail", **kwargs)
            trails = ct.describe_trails(trailNameList=[trail_arn]).get("trailList", [])
            if not trails:
                return {"error": "trail not found"}
            trail = trails[0]
            try:
                selectors = ct.get_event_selectors(TrailName=trail_arn).get("EventSelectors", [])
            except Exception:  # noqa: BLE001
                selectors = []
            return {
                "resource_type": "AWS::CloudTrail::Trail",
                "name": trail.get("Name"),
                "is_multi_region_trail": trail.get("IsMultiRegionTrail"),
                "include_global_service_events": trail.get("IncludeGlobalServiceEvents"),
                "log_file_validation_enabled": trail.get("LogFileValidationEnabled"),
                "kms_key_id": trail.get("KmsKeyId"),
                "s3_bucket_name": trail.get("S3BucketName"),
                "event_selectors": selectors,
            }
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)}

    def _iam_policy_config(self, policy_arn: str, ts: str) -> dict[str, Any]:
        try:
            import boto3

            kwargs: dict[str, Any] = {"region_name": self._region}
            if self._access_key and self._secret_key:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            iam = boto3.client("iam", **kwargs)
            versions = iam.list_policy_versions(PolicyArn=policy_arn).get("Versions", [])
            from datetime import datetime as _dt

            def _parse(s: str | None) -> _dt | None:
                if not s:
                    return None
                try:
                    return _dt.fromisoformat(s.replace("Z", "+00:00"))
                except ValueError:
                    return None

            target = _parse(ts)
            chosen: dict[str, Any] | None = None
            for v in sorted(
                versions,
                key=lambda v: v.get("CreateDate") or _dt.min,
            ):
                created = v.get("CreateDate")
                if target and created and created > target:
                    break
                chosen = v
            if not chosen:
                # No version <= ts. Fall back to the marked default.
                for v in versions:
                    if v.get("IsDefaultVersion"):
                        chosen = v
                        break
            if not chosen:
                return {"error": "no policy versions"}
            doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=chosen["VersionId"]).get("PolicyVersion", {}).get("Document", {})
            return {
                "resource_type": "AWS::IAM::ManagedPolicy",
                "policy_arn": policy_arn,
                "version_id": chosen["VersionId"],
                "is_default_version": bool(chosen.get("IsDefaultVersion")),
                "policy_document": doc,
            }
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)}

    def _aws_config_history(self, resource_id: str, ts: str) -> dict[str, Any]:
        # AWS Config keys recorded resources by (ResourceType, ResourceId)
        # not ARN, so we hand the ARN tail to ``get_resource_config_history``
        # and let it parse. If Config isn't recording the resource we get
        # an empty configurationItems list and surface that cleanly.
        try:
            from datetime import datetime as _dt

            import boto3

            kwargs: dict[str, Any] = {"region_name": self._region}
            if self._access_key and self._secret_key:
                kwargs["aws_access_key_id"] = self._access_key
                kwargs["aws_secret_access_key"] = self._secret_key
            cfgc = boto3.client("config", **kwargs)
            # ARN tail-after-last-`/` is the resourceId for most types.
            short_id = resource_id.rsplit("/", 1)[-1] or resource_id
            target = None
            try:
                target = _dt.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                target = None
            params: dict[str, Any] = {
                "resourceId": short_id,
                "limit": 5,
            }
            # AWS::*::* type guess from the ARN service segment.
            arn_parts = resource_id.split(":")
            if len(arn_parts) >= 3:
                params["resourceType"] = "AWS::" + arn_parts[2].capitalize() + "::Resource"
            if target:
                params["laterTime"] = target
            items = cfgc.get_resource_config_history(**params).get("configurationItems", [])
            if not items:
                return {"error": "not recorded"}
            return {
                "resource_type": items[0].get("resourceType"),
                "resource_id": short_id,
                "configuration": items[0].get("configuration"),
                "configuration_status": items[0].get("configurationItemStatus"),
                "recorded_at": items[0].get("configurationItemCaptureTime"),
            }
        except Exception as exc:  # noqa: BLE001
            return {"error": str(exc)}
