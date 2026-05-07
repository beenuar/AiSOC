"""
Alert and Incident models for the Fusion service.
These are Pydantic models used for message processing (not ORM).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"
    FUSED = "fused"  # Merged into an incident


class FusionDecision(str, Enum):
    NEW_ALERT = "new_alert"
    DUPLICATE = "duplicate"
    CORRELATED = "correlated"  # Added to existing incident
    NEW_INCIDENT = "new_incident"


class RawAlert(BaseModel):
    """Incoming alert from the Kafka raw alerts topic."""

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    source: str
    title: str
    description: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    status: AlertStatus = AlertStatus.NEW

    # IOC / entity data
    src_ip: str | None = None
    dst_ip: str | None = None
    hostname: str | None = None
    username: str | None = None
    file_hash: str | None = None
    domain: str | None = None
    url: str | None = None

    # MITRE ATT&CK
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Raw event
    raw_event: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    risk_score: float = 0.0

    created_at: datetime = Field(default_factory=datetime.utcnow)
    event_time: datetime | None = None

    def fingerprint(self) -> str:
        """Generate a stable deduplication fingerprint."""
        fields = {
            "tenant_id": str(self.tenant_id),
            "source": self.source,
            "title": self.title,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "hostname": self.hostname,
            "username": self.username,
            "file_hash": self.file_hash,
            "mitre_techniques": sorted(self.mitre_techniques),
        }
        canonical = json.dumps(fields, sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def correlation_key(self) -> str:
        """Generate a key for alert correlation (grouping related alerts)."""
        # Correlate by primary entity and tactic
        entity = self.src_ip or self.hostname or self.username or self.domain or "unknown"
        tactic = self.mitre_tactics[0] if self.mitre_tactics else "unknown"
        return f"{self.tenant_id}:{entity}:{tactic}"


class ConfidenceLabel(str, Enum):
    """High/medium/low confidence label surfaced on every alert.

    Wave 1 of the AiSOC v6 capability roadmap — every alert ships with a
    transparent confidence label and a chain of contributing factors so the
    analyst can decide whether to action it without re-deriving the score.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ConfidenceFactor(BaseModel):
    """One row of the explainability chain attached to a fused alert.

    The frontend renders these as a stack of evidence pills in the alert
    detail drawer. ``contribution`` is signed in [-1.0, +1.0] — positive
    increases confidence, negative decreases it. ``weight`` is the relative
    importance of the factor inside the model (sums to ~1.0 across factors).
    """

    factor: str  # short machine-friendly name, e.g. "ml_anomaly"
    label: str  # human-readable label, e.g. "ML anomaly score"
    value: str  # observed value, e.g. "0.82" or "3 techniques"
    contribution: float = Field(ge=-1.0, le=1.0)  # signed effect on confidence
    weight: float = Field(ge=0.0, le=1.0)  # relative importance


class FusedAlert(BaseModel):
    """Alert after fusion processing, ready for downstream consumption."""

    id: UUID
    tenant_id: UUID
    incident_id: UUID | None = None
    fusion_decision: FusionDecision
    duplicate_of: UUID | None = None
    alert: RawAlert

    # Enrichment data (populated by enrichment service)
    enrichments: dict[str, Any] = Field(default_factory=dict)

    # ML scores — populated by MLScorer
    anomaly_score: float = 0.0  # 0.0 = normal, 1.0 = highly anomalous (Isolation Forest)
    priority_score: float = 0.0  # 0.0–1.0 priority rank (LightGBM ranker)

    # Exploit-in-wild boost (Tier 3.5) — set when alert entity matches an asset vulnerability with is_exploited=True
    exploit_in_wild: bool = False

    # Detection confidence + explainability — Wave 1 of v6 roadmap.
    # ``confidence_score`` is the raw [0.0, 1.0] number used to derive the
    # human-readable ``confidence_label``. ``confidence_rationale`` is the
    # ordered evidence chain rendered in the alert detail drawer.
    confidence_label: ConfidenceLabel = ConfidenceLabel.MEDIUM
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence_rationale: list[ConfidenceFactor] = Field(default_factory=list)

    fused_at: datetime = Field(default_factory=datetime.utcnow)


class AnalystFeedback(BaseModel):
    """Analyst feedback on a fused alert, used to re-train the ML ranker."""

    alert_id: UUID
    tenant_id: UUID
    analyst_id: str
    is_true_positive: bool
    assigned_priority: int = Field(ge=1, le=5, description="Analyst-assigned priority 1 (critical) to 5 (low)")
    notes: str = ""
    submitted_at: datetime = Field(default_factory=datetime.utcnow)


class IncidentSummary(BaseModel):
    """Lightweight incident summary stored in Redis."""

    id: UUID = Field(default_factory=uuid4)
    tenant_id: UUID
    title: str
    severity: AlertSeverity
    alert_count: int = 1
    alert_ids: list[str] = Field(default_factory=list)
    src_ips: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    correlation_keys: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
