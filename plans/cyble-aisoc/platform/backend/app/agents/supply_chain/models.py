"""Internal dataclasses for the Supply-Chain Risk agent.

Transient artefacts that exist only during a single sweep. The durable
outputs live in :class:`Vendor`, :class:`VendorRiskSignal`, the threat
graph, and the :class:`Case` table.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.supply_chain import (
    SignalKind,
    VendorCategory,
    VendorCriticality,
)


@dataclass
class VendorSnapshot:
    """Detached, in-memory view of a :class:`Vendor` row.

    The agent loads vendors once at the start of a sweep into these
    snapshots so subsequent commits + per-vendor failure rollbacks
    don't expire the SQLAlchemy-managed Vendor instances and trigger
    refresh-on-access pain mid-loop.
    """

    id: int
    tenant_id: str
    slug: str
    name: str
    category: VendorCategory
    criticality: VendorCriticality
    description: str
    monitored_terms: list[str]
    monitored_domains: list[str]
    monitored_cves: list[str]
    affected_assets: list[str]
    affected_users: list[str]
    contact_email: str | None
    active: bool


@dataclass
class SignalObservation:
    """One CTI signal hit produced by the collect phase.

    The materialise phase consumes a list of these per vendor and
    decides whether the rolling sum crosses the case-open threshold.
    """

    kind: SignalKind
    source: str
    """CTI tool that produced the hit (e.g. ``cti.darkweb_search``)."""
    score: int
    """0-100 per-signal severity, before vendor-criticality multiplier."""
    summary: str
    """One-line analyst-facing description."""
    evidence: dict[str, Any] = field(default_factory=dict)
    """Structured payload — forum, ts, snippet, CVE id, etc."""


@dataclass
class VendorFinding:
    """All observations + computed risk for a single vendor this sweep.

    Built by the collect phase, consumed by materialise. ``risk_score``
    is the criticality-multiplied sum of the per-signal scores; that's
    the value compared against the case-open threshold.
    """

    vendor_id: int
    slug: str
    name: str
    risk_score: int
    """Criticality-weighted total of this sweep's signals (0-200ish)."""
    observations: list[SignalObservation] = field(default_factory=list)
    rolling_score: int = 0
    """``risk_score`` plus the still-fresh historical signals, used for
    case-open gating. Lets a vendor that crosses the threshold via
    accumulating moderate signals still trigger a case."""
    case_opened: int | None = None
    """Set by materialise when a Case was opened off this finding."""


@dataclass
class SupplyChainSweepResult:
    """Aggregate output of one per-tenant sweep.

    Same spirit as :class:`ActorProfilingResult`: every counter that
    matters for "did this sweep do useful work?" lives here so the
    scheduler logs and tests can assert against a single object.
    """

    tenant_id: str
    findings: list[VendorFinding] = field(default_factory=list)
    vendors_scanned: int = 0
    signals_recorded: int = 0
    """Total :class:`VendorRiskSignal` rows persisted this sweep."""
    cases_opened: list[int] = field(default_factory=list)
    """Case IDs opened during this sweep (NEW status)."""
    graph_nodes_upserted: int = 0
    graph_edges_upserted: int = 0
    errors: list[str] = field(default_factory=list)


__all__ = [
    "SignalObservation",
    "SupplyChainSweepResult",
    "VendorFinding",
    "VendorSnapshot",
]
