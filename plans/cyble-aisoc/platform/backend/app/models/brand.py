"""Brand & typosquat takedown models (t3c-brand-takedown).

The Brand Responder operates over three append-only-ish tables:

- :class:`BrandAsset` — the protected brand surface the tenant has
  registered. Owns the canonical names and TLDs we consider "self";
  detectors flag anything close-but-not-equal that matches one of
  these.

- :class:`TyposquatCandidate` — a discovered lookalike: a domain
  the detectors believe is impersonating the brand. Carries the
  algorithmic score, the matched reasons, and the lifecycle status
  (raw → triaged → takedown_filed → resolved).

- :class:`TakedownRequest` — one submitted abuse / takedown filing
  against a candidate. Status traces the live filing through the
  submitter providers (registrar, host, CDN, registry, browser
  safe-browsing). We keep the per-step audit so a human can see
  exactly which channels were tried and what they returned.

Why a separate model file? The Brand Responder is the closed-loop
"proactive takedown" path from §3d of the plan. Threat-graph
nodes / cases live elsewhere; this ledger is purely the brand
surface's own state machine.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import JSON, Column, Field, SQLModel


class CandidateStatus(str, Enum):
    """Lifecycle of a discovered impersonation candidate."""

    NEW = "new"
    """Just emitted by the detector; not yet reviewed."""
    TRIAGED = "triaged"
    """A human (or the Responder Agent) confirmed it's worth pursuing."""
    DISMISSED = "dismissed"
    """Reviewed and judged a false positive."""
    TAKEDOWN_FILED = "takedown_filed"
    """At least one :class:`TakedownRequest` is open against it."""
    RESOLVED = "resolved"
    """All open takedowns reached a terminal positive outcome."""


class TakedownStatus(str, Enum):
    """Live status of a single submitted takedown filing."""

    PENDING = "pending"
    """Created locally, not yet pushed to the provider."""
    EVIDENCE_BUILT = "evidence_built"
    """Evidence packet assembled; ready for submission."""
    SUBMITTED = "submitted"
    """Pushed to the abuse channel; awaiting acknowledgement."""
    ACKNOWLEDGED = "acknowledged"
    """Provider responded with a case/ticket id."""
    ACTIONED = "actioned"
    """Provider confirmed domain disabled / page removed."""
    FAILED = "failed"
    """Provider declined or the channel returned an error."""
    CANCELLED = "cancelled"
    """A human cancelled the filing before it terminated."""


class TakedownChannel(str, Enum):
    """Which abuse pipe a single filing targets.

    We treat each channel as an independent filing because most
    real-world takedowns require fanning out: registrar AND host
    AND safe-browsing in parallel often beats serial escalation.
    """

    REGISTRAR_ABUSE = "registrar_abuse"
    HOST_ABUSE = "host_abuse"
    REGISTRY_ABUSE = "registry_abuse"
    SAFE_BROWSING = "safe_browsing"
    BRAND_PROTECTION_VENDOR = "brand_protection_vendor"


class BrandAsset(SQLModel, table=True):
    """A protected brand surface registered by a tenant.

    The detector treats every active asset as a search target:
    daily sweeps query Cyble brand-intel + DNS/zone signals against
    each asset's ``root_domain`` (and any registered aliases).
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    name: str
    """Human-facing brand name (e.g. ``"Cyble"``)."""
    root_domain: str = Field(index=True)
    """Canonical domain to defend (e.g. ``"cyble.com"``)."""
    aliases: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Other domains we own that should NOT be flagged as squats.",
    )
    monitored_terms: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Extra brand strings to defend (product names, exec names).",
    )
    active: bool = Field(default=True, index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )


class TyposquatCandidate(SQLModel, table=True):
    """One discovered lookalike domain pointing at a registered brand.

    A candidate may produce zero, one, or many :class:`TakedownRequest`
    rows depending on policy (auto-takedown threshold) and the
    Responder Agent's decision.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    brand_asset_id: int = Field(foreign_key="brandasset.id", index=True)
    candidate_domain: str = Field(index=True)
    score: int = Field(index=True, description="0-100 risk score.")
    severity: str = Field(
        default="low",
        index=True,
        description="One of: low, medium, high, critical.",
    )
    reasons: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Why the detector flagged this (edit_distance, idn, ...).",
    )
    enrichment: dict = Field(
        default_factory=dict,
        sa_column=Column(JSON),
        description="WHOIS / DNS / brand-intel snapshot at discovery time.",
    )
    status: CandidateStatus = Field(default=CandidateStatus.NEW, index=True)
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )


class TakedownRequest(SQLModel, table=True):
    """A single takedown filing against a candidate on one channel."""

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(index=True)
    candidate_id: int = Field(
        foreign_key="typosquatcandidate.id", index=True
    )
    channel: TakedownChannel = Field(index=True)
    status: TakedownStatus = Field(
        default=TakedownStatus.PENDING, index=True
    )
    recipient: str = Field(
        default="",
        description="Abuse contact email or vendor endpoint ID.",
    )
    provider_ticket: Optional[str] = Field(
        default=None, description="ID returned by the provider on submit."
    )
    evidence: dict = Field(
        default_factory=dict,
        sa_column=Column(JSON),
        description="Frozen evidence packet shipped to the provider.",
    )
    status_history: list[dict] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="List of {at, status, note} dicts (append-only).",
    )
    submitted_by: str = Field(default="system", index=True)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )


__all__ = [
    "BrandAsset",
    "CandidateStatus",
    "TakedownChannel",
    "TakedownRequest",
    "TakedownStatus",
    "TyposquatCandidate",
]
