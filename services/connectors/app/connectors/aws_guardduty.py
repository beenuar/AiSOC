"""
AWS GuardDuty connector.

Pulls findings from one or more AWS GuardDuty detectors in a single region
via boto3. GuardDuty's data model is:

    detector --> finding (per detector)

so each poll lists all detectors in the configured region, then fetches
findings under each detector. Cross-region coverage is handled by adding
one connector instance per region.

Auth model:
    Same dual-mode pattern as AWS Security Hub. Either:
      - Leave ``access_key`` / ``secret_key`` blank to use the runtime
        IAM role / instance profile (recommended for production).
      - Or supply a static IAM access-key pair scoped to read-only
        GuardDuty permissions.

Severity collapse:
    GuardDuty returns severity as a float in [1.0, 8.9]. AiSOC's
    canonical ladder is ``info | low | medium | high``. We bucket using
    AWS's published thresholds:

        1.0–3.9  --> low
        4.0–6.9  --> medium
        7.0–8.9  --> high

    Anything < 1.0 (rare but possible for sample/test findings) collapses
    to ``info``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import structlog

from app.connectors.base import BaseConnector, Capability, ConnectorSchema, Field

logger = structlog.get_logger()


def _severity_label(score: float | int | None) -> str:
    """Collapse GuardDuty's float severity into AiSOC's 4-tier ladder.

    GuardDuty publishes severity as a float roughly in [0.1, 10.0]. AWS's
    own console buckets that into Low (1.0-3.9), Medium (4.0-6.9),
    High (7.0-8.9), and Critical (9.0-10.0). AiSOC's canonical ladder
    has no ``critical`` tier, so anything 7.0+ collapses into ``high``
    and the original float is preserved on ``raw_event.Severity`` for
    callers that need exact comparisons.
    """
    if score is None:
        return "medium"
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "medium"
    if s < 1.0:
        return "info"
    if s < 4.0:
        return "low"
    if s < 7.0:
        return "medium"
    return "high"


class AWSGuardDutyConnector(BaseConnector):
    connector_id = "aws_guardduty"
    connector_name = "AWS GuardDuty"
    connector_category = "cloud"

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "AWS GuardDuty findings. Pulls native GuardDuty alerts "
                "(threat detection across VPC flow logs, DNS logs, "
                "CloudTrail, EKS, S3, RDS, Lambda) directly without "
                "requiring Security Hub aggregation."
            ),
            docs_url="/docs/connectors/aws-guardduty",
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
        return (Capability.PULL_ALERTS,)

    def __init__(
        self,
        region: str = "us-east-1",
        access_key: str = "",
        secret_key: str = "",
    ):
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
            return boto3.client("guardduty", **kwargs)
        except ImportError as exc:
            raise RuntimeError("boto3 is required for AWS GuardDuty connector. Install it with: pip install boto3") from exc

    async def test_connection(self) -> dict[str, Any]:
        try:
            client = self._get_client()
            # ``list_detectors`` is the cheapest auth-only call. We treat
            # a successful 200 with zero detectors as a soft failure
            # because the polling loop would be a no-op forever — the
            # operator almost certainly pointed at the wrong region.
            resp = client.list_detectors()
            detector_ids = resp.get("DetectorIds", [])
            if not detector_ids:
                return {
                    "success": False,
                    "connector": self.connector_id,
                    "error": (
                        f"GuardDuty has no detector in region {self._region}. "
                        "Enable GuardDuty in this region or point the "
                        "connector at the correct region."
                    ),
                }
            return {
                "success": True,
                "connector": self.connector_id,
                "region": self._region,
                "detector_count": len(detector_ids),
            }
        except Exception as exc:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": str(exc),
            }

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        try:
            client = self._get_client()
        except RuntimeError as exc:
            logger.warning("guardduty.client_init_failed", error=str(exc))
            return []

        # GuardDuty stores ``updatedAt`` as epoch milliseconds. Filter on
        # the cursor window so we only re-fetch changed findings.
        cursor_ms = int((datetime.now(UTC) - timedelta(seconds=since_seconds)).timestamp() * 1000)

        all_findings: list[dict[str, Any]] = []

        try:
            detector_ids = client.list_detectors().get("DetectorIds", [])
        except Exception as exc:
            logger.warning("guardduty.list_detectors_failed", error=str(exc))
            return []

        for detector_id in detector_ids:
            try:
                # Page list_findings to keep memory bounded. We cap each
                # detector at 500 findings per poll — same order of
                # magnitude as the Security Hub connector.
                finding_ids: list[str] = []
                paginator = client.get_paginator("list_findings")
                pages = paginator.paginate(
                    DetectorId=detector_id,
                    FindingCriteria={
                        "Criterion": {
                            "updatedAt": {"GreaterThanOrEqual": cursor_ms},
                            "service.archived": {"Equals": ["false"]},
                        }
                    },
                    PaginationConfig={"MaxItems": 500, "PageSize": 50},
                )
                for page in pages:
                    finding_ids.extend(page.get("FindingIds", []))

                if not finding_ids:
                    continue

                # ``get_findings`` accepts max 50 IDs per call.
                for i in range(0, len(finding_ids), 50):
                    batch = finding_ids[i : i + 50]
                    resp = client.get_findings(DetectorId=detector_id, FindingIds=batch)
                    all_findings.extend(resp.get("Findings", []))
            except Exception as exc:
                logger.warning(
                    "guardduty.detector_fetch_failed",
                    detector_id=detector_id,
                    error=str(exc),
                )
                continue

        return [self.normalize(f) for f in all_findings]

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        service = raw.get("Service") or {}
        resource = raw.get("Resource") or {}
        severity = _severity_label(raw.get("Severity"))

        # Best-effort attacker-IP extraction. GuardDuty surfaces remote IPs
        # on a few different paths depending on the finding type
        # (PortProbe, Recon:EC2/Portscan, UnauthorizedAccess:*, etc).
        action = service.get("Action") or {}
        remote_ip = (
            action.get("NetworkConnectionAction", {}).get("RemoteIpDetails", {}).get("IpAddressV4")
            or action.get("AwsApiCallAction", {}).get("RemoteIpDetails", {}).get("IpAddressV4")
            or action.get("PortProbeAction", {}).get("PortProbeDetails", [{}])[0].get("RemoteIpDetails", {}).get("IpAddressV4")
        )

        return {
            "source": self.connector_id,
            "category": "cloud",
            "external_id": raw.get("Id"),
            "title": raw.get("Title") or raw.get("Type") or "GuardDuty finding",
            "description": raw.get("Description") or "",
            "severity": severity,
            "src_ip": remote_ip,
            "aws_account_id": raw.get("AccountId"),
            "aws_region": raw.get("Region"),
            "cloud_platform": "aws",
            "cloud_resource": (resource.get("InstanceDetails") or {}).get("InstanceId")
            or (resource.get("AccessKeyDetails") or {}).get("AccessKeyId"),
            "rule_name": raw.get("Type"),
            "raw_event": raw,
            "created_at": raw.get("CreatedAt"),
        }
