"""Agentless Cloud Security Posture Management scanner (Wave 6, W6.2).

Evaluates a normalised snapshot of cloud resources (collected read-only via
provider APIs — no agent on the workload) against a set of misconfiguration
checks, emitting findings mapped to compliance controls (CIS / SOC 2). Pure
functions over plain dicts so the checks are trivially unit-tested and the
collector (which does the API calls) stays a thin, swappable layer.

A resource is ``{"type": "s3_bucket"|"security_group"|"iam_user"|
"rds_instance"|"ebs_volume", "id": "...", ...provider fields...}``.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

# Ports we consider sensitive when exposed to the world.
_SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017, 9200, 1433}


@dataclass(frozen=True)
class CspmFinding:
    check_id: str
    resource_type: str
    resource_id: str
    severity: str  # info | low | medium | high | critical
    title: str
    remediation: str
    control_refs: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _check_s3(r: dict[str, Any]) -> list[CspmFinding]:
    out: list[CspmFinding] = []
    rid = str(r.get("id", "unknown"))
    if r.get("public_acl") or r.get("policy_public"):
        out.append(
            CspmFinding(
                "cspm.s3.public",
                "s3_bucket",
                rid,
                "critical",
                "S3 bucket is publicly accessible",
                "Remove public ACLs/policy grants and enable S3 Block Public Access.",
                ["CIS-AWS-2.1.5", "SOC2-CC6.1"],
            )
        )
    if r.get("encrypted") is False:
        out.append(
            CspmFinding(
                "cspm.s3.unencrypted",
                "s3_bucket",
                rid,
                "medium",
                "S3 bucket has no default encryption",
                "Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                ["CIS-AWS-2.1.1", "SOC2-CC6.7"],
            )
        )
    return out


def _check_security_group(r: dict[str, Any]) -> list[CspmFinding]:
    out: list[CspmFinding] = []
    rid = str(r.get("id", "unknown"))
    for rule in r.get("ingress", []) or []:
        cidr = rule.get("cidr")
        if cidr not in ("0.0.0.0/0", "::/0"):
            continue
        from_port = rule.get("from_port")
        to_port = rule.get("to_port", from_port)
        opens_all = from_port in (None, 0) and to_port in (None, 0, 65535)
        hits_sensitive = any(from_port is not None and to_port is not None and from_port <= p <= to_port for p in _SENSITIVE_PORTS)
        if opens_all or hits_sensitive:
            out.append(
                CspmFinding(
                    "cspm.sg.world_open",
                    "security_group",
                    rid,
                    "high",
                    f"Security group open to the world ({cidr}) on sensitive port(s)",
                    "Restrict the ingress rule to known CIDRs / a bastion; never expose admin ports to 0.0.0.0/0.",
                    ["CIS-AWS-5.2", "SOC2-CC6.6"],
                )
            )
    return out


def _check_iam_user(r: dict[str, Any]) -> list[CspmFinding]:
    out: list[CspmFinding] = []
    rid = str(r.get("id", "unknown"))
    if r.get("console_enabled") and not r.get("mfa_enabled", False):
        out.append(
            CspmFinding(
                "cspm.iam.no_mfa",
                "iam_user",
                rid,
                "high",
                "IAM user with console access has no MFA",
                "Enforce MFA for all console users (IAM policy / SCP).",
                ["CIS-AWS-1.10", "SOC2-CC6.1"],
            )
        )
    if int(r.get("access_key_age_days", 0)) > 90:
        out.append(
            CspmFinding(
                "cspm.iam.stale_key",
                "iam_user",
                rid,
                "medium",
                "IAM access key older than 90 days",
                "Rotate access keys at least every 90 days; prefer short-lived role credentials.",
                ["CIS-AWS-1.14", "SOC2-CC6.1"],
            )
        )
    return out


def _check_rds(r: dict[str, Any]) -> list[CspmFinding]:
    out: list[CspmFinding] = []
    rid = str(r.get("id", "unknown"))
    if r.get("publicly_accessible"):
        out.append(
            CspmFinding(
                "cspm.rds.public",
                "rds_instance",
                rid,
                "high",
                "RDS instance is publicly accessible",
                "Set PubliclyAccessible=false and place the instance in private subnets.",
                ["CIS-AWS-2.3.3", "SOC2-CC6.6"],
            )
        )
    if r.get("storage_encrypted") is False:
        out.append(
            CspmFinding(
                "cspm.rds.unencrypted",
                "rds_instance",
                rid,
                "medium",
                "RDS storage is not encrypted",
                "Enable storage encryption (encrypt a snapshot and restore).",
                ["CIS-AWS-2.3.1", "SOC2-CC6.7"],
            )
        )
    return out


def _check_ebs(r: dict[str, Any]) -> list[CspmFinding]:
    rid = str(r.get("id", "unknown"))
    if r.get("encrypted") is False:
        return [
            CspmFinding(
                "cspm.ebs.unencrypted",
                "ebs_volume",
                rid,
                "medium",
                "EBS volume is not encrypted",
                "Enable EBS encryption by default and re-create the volume from an encrypted snapshot.",
                ["CIS-AWS-2.2.1", "SOC2-CC6.7"],
            )
        ]
    return []


_CHECKS: dict[str, Callable[[dict[str, Any]], list[CspmFinding]]] = {
    "s3_bucket": _check_s3,
    "security_group": _check_security_group,
    "iam_user": _check_iam_user,
    "rds_instance": _check_rds,
    "ebs_volume": _check_ebs,
}


def scan_resources(resources: list[dict[str, Any]]) -> list[CspmFinding]:
    """Run every applicable check over a resource snapshot."""
    findings: list[CspmFinding] = []
    for resource in resources:
        check = _CHECKS.get(str(resource.get("type", "")))
        if check is not None:
            findings.extend(check(resource))
    return findings


def summarize(findings: list[CspmFinding]) -> dict[str, int]:
    """Count findings by severity for a posture score / dashboard tile."""
    counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
