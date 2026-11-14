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
from uuid import UUID, uuid4, uuid5

from pydantic import BaseModel, Field

# Fixed namespace for deriving the canonical, replay-stable alert UUID from an
# alert's dedup fingerprint (issue #568). Using uuid5 over a constant namespace
# means the same logical alert (same tenant + fingerprint) always resolves to
# the same UUID across RawAlert → FusedAlert → Kafka → Postgres → ledger → API,
# so a replayed source event maps to exactly one alert row instead of minting a
# fresh random id on every pass.
ALERT_ID_NAMESPACE = UUID("a15c0c00-0000-5568-a150-c000000a1e77")


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
    # Anonymizer or hosting class of `src_ip`, stamped at ingest from a
    # pinned local dataset (depth plan wave 2, 1.6), with the dataset version
    # that answered. None means the dataset had no entry, which is the
    # ordinary case: three of the five classes ship with no records and are
    # tenant-supplied. None must render as unknown, never as "not a VPN".
    src_ip_class: str | None = None
    src_ip_class_dataset_version: str | None = None

    # MITRE ATT&CK
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Raw event
    raw_event: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    risk_score: float = 0.0

    # Provenance (issue #568) — carried first-class end-to-end so downstream
    # (auto-triage, the investigation graph, the Splunk evidence tool) can
    # resolve the originating connector and source events WITHOUT parsing the
    # human-readable title/source strings.
    connector_id: UUID | None = None
    connector_type: str | None = None
    source_event_ids: list[str] = Field(default_factory=list)
    ocsf_class_uid: int | None = None
    rule_id: str | None = None  # detection rule / Splunk saved-search identifier
    rule_name: str | None = None
    # The source system's own identifier for the finding (OCSF `finding.uid`):
    # a Splunk notable's rule UID, an Elastic signal id, a QRadar offense id.
    # Ingest has always produced it and nothing downstream kept it, so the
    # alert row could not be traced back to the finding that raised it — and
    # therefore no verdict could be written back.
    external_id: str | None = None

    created_at: datetime = Field(default_factory=datetime.utcnow)
    event_time: datetime | None = None

    def deterministic_id(self) -> UUID:
        """Replay-stable canonical UUID derived from the dedup fingerprint.

        Same tenant + fingerprint ⇒ same UUID on every pass, so replays resolve
        to exactly one alert row (issue #568). This is intentionally aligned
        with :meth:`fingerprint` (the dedup key) — two events that dedup to the
        same row also share the same canonical id.
        """
        return uuid5(ALERT_ID_NAMESPACE, f"{self.tenant_id}:{self.fingerprint()}")

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
        """The key related alerts group under: entity and tactic, when both exist.

        When either is missing, the key **narrows instead of widening**. The
        previous fallback substituted the literal ``"unknown"`` for a missing
        field, and since neither detection engine has ever set
        ``mitre_tactics`` (the ruleset carries technique ids only), every
        detection alert's key read ``{tenant}:{entity}:unknown`` — all of an
        entity's detection alerts, whatever the rule or kill-chain stage,
        collapsed into one incident per window, titled after whichever alert
        arrived first. An exfiltration alert became row 37 inside an incident
        named for a port scan. Alerts with no entity either were worse:
        ``{tenant}:unknown:unknown`` merged unrelated alerts **tenant-wide**.

        The fallback ladder, most to least evidence of relatedness:

        * entity + tactic — unchanged, the designed key;
        * entity, no tactic — scoped to the detection rule. Same rule firing
          repeatedly on one entity is the storm correlation exists for;
          different rules on one entity are not known to be one incident, and
          merging them buries the one that mattered. The cost is stated: one
          event firing N tactic-less rules now makes N incidents rather than
          one, which fragments rather than buries — the recoverable
          direction, since a reviewer can join incidents and cannot unbury
          an alert nobody rendered;
        * no entity — never groups across rules, and a tactic (when present)
          narrows it further rather than standing alone tenant-wide;
        * no entity and no rule — groups by the dedup fingerprint, so exact
          repeats of one shape still collapse and nothing else does. Zero
          evidence of relatedness groups nothing.
        """
        entity = self.src_ip or self.hostname or self.username or self.domain
        tactic = self.mitre_tactics[0] if self.mitre_tactics else None
        if entity and tactic:
            return f"{self.tenant_id}:{entity}:{tactic}"
        rule = self.rule_id or self.rule_name
        if entity:
            scope = f"rule:{rule}" if rule else f"fp:{self.fingerprint()[:16]}"
            return f"{self.tenant_id}:{entity}:{scope}"
        if rule:
            return f"{self.tenant_id}:no-entity:rule:{rule}:{tactic or 'no-tactic'}"
        return f"{self.tenant_id}:no-entity:fp:{self.fingerprint()[:16]}"


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

    # Deterministic correlation narrative — Wave 6 of v1.5 SOC Console Parity.
    # Populated at fusion time by ``services.fusion.app.services.narrative.build_narrative``
    # and surfaced verbatim by the InvestigationRail on ``/alerts`` (no LLM
    # round-trip needed). The streaming LLM explanation lives behind a
    # "Deep Explain" button at ``POST /alerts/{id}/explain``. ``None`` here
    # only happens when the fusion engine cannot build a narrative for the
    # alert (e.g. minimal-content fixture rows in tests); the API will
    # lazily compute it on first read in that case.
    narrative: str | None = None

    # Depth plan 2.4 — which session this alert came out of, and how strongly
    # that grouping is known. `session_key_kind` travels beside the id rather
    # than being looked up because it changes what the console is allowed to
    # say: "17 other events in this session" means the vendor grouped them for
    # three of the four kinds and means we did for `derived`.
    #
    # All three are None on a vendor-asserted finding, which arrives on the
    # alerts topic rather than as a normalized event and genuinely has no
    # session. None renders as no session context, never as a session of one.
    session_id: UUID | None = None
    session_key_kind: str | None = None
    originating_human: str | None = None

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
