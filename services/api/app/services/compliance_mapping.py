"""Detection/finding → compliance-control mapping with auto-evidence (Wave 6, W6.1).

Ties security signals to the controls they demonstrate: a CSPM finding or a
fired detection is mapped to CIS / SOC 2 controls, and an evidence record is
minted automatically so an auditor can see *this control is being monitored /
enforced, here is the proof, at this time*. Pure functions over dicts.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

# Minimal control catalogue (framework, human title). Extend as needed.
CONTROL_CATALOG: dict[str, dict[str, str]] = {
    "SOC2-CC6.1": {"framework": "SOC 2", "title": "Logical access controls restrict access"},
    "SOC2-CC6.6": {"framework": "SOC 2", "title": "Boundary protection / restrict external access"},
    "SOC2-CC6.7": {"framework": "SOC 2", "title": "Encryption of data at rest / in transit"},
    "SOC2-CC7.2": {"framework": "SOC 2", "title": "Detection + monitoring of anomalies"},
    "CIS-AWS-1.10": {"framework": "CIS AWS", "title": "MFA enabled for console users"},
    "CIS-AWS-1.14": {"framework": "CIS AWS", "title": "Access keys rotated <= 90 days"},
    "CIS-AWS-2.1.1": {"framework": "CIS AWS", "title": "S3 default encryption"},
    "CIS-AWS-2.1.5": {"framework": "CIS AWS", "title": "S3 Block Public Access"},
    "CIS-AWS-2.2.1": {"framework": "CIS AWS", "title": "EBS encryption by default"},
    "CIS-AWS-2.3.1": {"framework": "CIS AWS", "title": "RDS encryption at rest"},
    "CIS-AWS-2.3.3": {"framework": "CIS AWS", "title": "RDS not publicly accessible"},
    "CIS-AWS-5.2": {"framework": "CIS AWS", "title": "No ingress from 0.0.0.0/0 to admin ports"},
}

# MITRE ATT&CK technique → controls whose monitoring the detection evidences.
_MITRE_TO_CONTROLS: dict[str, list[str]] = {
    "T1078": ["SOC2-CC6.1", "CIS-AWS-1.10"],  # valid accounts
    "T1110": ["SOC2-CC6.1"],  # brute force
    "T1621": ["SOC2-CC6.1"],  # MFA request generation
    "T1530": ["SOC2-CC6.6", "CIS-AWS-2.1.5"],  # data from cloud storage
    "T1567": ["SOC2-CC6.6"],  # exfiltration over web service
    "T1046": ["SOC2-CC7.2", "CIS-AWS-5.2"],  # network service scanning
}


@dataclass(frozen=True)
class EvidenceRecord:
    control_id: str
    framework: str
    control_title: str
    source_type: str  # "detection" | "cspm" | "alert"
    source_id: str
    detail: str
    collected_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def map_mitre_to_controls(mitre_techniques: list[str]) -> list[str]:
    """Resolve controls from MITRE techniques (base technique, ignoring sub-IDs)."""
    controls: list[str] = []
    for technique in mitre_techniques:
        base = str(technique).split(".")[0].upper()
        for control in _MITRE_TO_CONTROLS.get(base, []):
            if control not in controls:
                controls.append(control)
    return controls


def _evidence(control_id: str, source_type: str, source_id: str, detail: str) -> EvidenceRecord | None:
    meta = CONTROL_CATALOG.get(control_id)
    if meta is None:
        return None
    return EvidenceRecord(
        control_id=control_id,
        framework=meta["framework"],
        control_title=meta["title"],
        source_type=source_type,
        source_id=source_id,
        detail=detail,
    )


def build_evidence(control_ids: list[str], *, source_type: str, source_id: str, detail: str) -> list[EvidenceRecord]:
    """Mint an evidence record per known control."""
    records = [_evidence(cid, source_type, source_id, detail) for cid in control_ids]
    return [r for r in records if r is not None]


def evidence_for_detection(detection_id: str, mitre_techniques: list[str], detail: str) -> list[EvidenceRecord]:
    """Auto-evidence for a fired detection (W6.1)."""
    return build_evidence(map_mitre_to_controls(mitre_techniques), source_type="detection", source_id=detection_id, detail=detail)


def evidence_for_cspm_finding(finding: dict[str, Any]) -> list[EvidenceRecord]:
    """Auto-evidence for a CSPM finding (its ``control_refs`` become records)."""
    return build_evidence(
        list(finding.get("control_refs", [])),
        source_type="cspm",
        source_id=str(finding.get("check_id", "unknown")) + ":" + str(finding.get("resource_id", "")),
        detail=str(finding.get("title", "")),
    )
