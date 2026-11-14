"""Threat actor profile models (t3e-actor-profiling).

Per-actor profiles let the platform answer the canonical CTI question:
*"What do we know about this adversary, and which of our IOCs / cases
touch them?"*

We model two persistence concerns separately:

- :class:`ThreatActor` — the canonical actor row. One row per actor
  identity per tenant scope. ``tenant_id="__global__"`` rows are the
  Cyble-curated profiles every tenant inherits; per-tenant rows are
  local overrides / annotations a SOC team has added on top.

- :class:`ActorIOCLink` — a denormalised IOC ↔ actor edge that powers
  fast "pivot from this IOC to the actor" lookups without paying a
  graph traversal every time. The graph is still the source of truth
  for relationships; this table is a materialised view of the
  ``ATTRIBUTED_TO`` edges that point at ``NodeType.ACTOR`` nodes.

Why two tables instead of just leaning on the graph?

1. The actor card needs a wide row (aliases, motivation, sophistication,
   geographic origin, ATT&CK techniques, target sectors, ...). Cramming
   that into ``GraphNode.props`` works but makes queries painful — you
   can't index a JSON column for "every FINANCIAL_GAIN actor of HIGH
   sophistication first seen since 2024".
2. IOC pivoting is read-hot. We want the lookup to be one SQL row, not
   a graph BFS, so the API answers in single-digit milliseconds even
   when the threat graph grows.

The :class:`ThreatActor` row is intentionally append-only-ish: we never
drop history, just refresh ``last_seen``, merge aliases, and bump
``confidence``. The graph stays the canonical relationship store, so
analysts can still "show me everything connected to APT29" without this
table existing.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlmodel import JSON, Column, Field, SQLModel, UniqueConstraint


class ActorMotivation(str, Enum):
    """Why does this actor operate?

    Standard CTI taxonomy (mirrors STIX 2.1 motivation vocab). We keep
    the set deliberately small because over-granular motivation tags
    rot fast and don't drive different downstream decisions.
    """

    FINANCIAL_GAIN = "financial_gain"
    """Ransomware crews, BEC, banking trojan operators."""
    ESPIONAGE = "espionage"
    """State-sponsored intelligence collection."""
    HACKTIVISM = "hacktivism"
    """Ideologically motivated, often public-facing campaigns."""
    SABOTAGE = "sabotage"
    """Destructive / wiper operations."""
    NOTORIETY = "notoriety"
    """Bragging-rights crews, defacers, script-kiddie collectives."""
    UNKNOWN = "unknown"
    """Insufficient signal to attribute motivation yet."""


class ActorSophistication(str, Enum):
    """Tradecraft level — used for triage prioritisation."""

    MINIMAL = "minimal"
    """Off-the-shelf tooling, low operational security."""
    INTERMEDIATE = "intermediate"
    """Custom tooling, some operational discipline."""
    ADVANCED = "advanced"
    """Bespoke malware, zero-days, multi-stage operations."""
    EXPERT = "expert"
    """Nation-state caliber: zero-days at will, supply-chain attacks."""
    UNKNOWN = "unknown"


class ThreatActor(SQLModel, table=True):
    """A profiled adversary.

    One row per actor handle per tenant scope. The natural key is
    ``(tenant_id, handle)``. ``handle`` is the canonical actor name
    (e.g. ``"APT29"``, ``"FIN7"``) — aliases live in
    :attr:`aliases` and are still searchable through the API.

    Tenant scope:

    - ``tenant_id == "__global__"`` — Cyble-shared profile. Visible to
      every tenant; only mutated by the platform's CTI sync path.
    - ``tenant_id == "<real-tenant>"`` — a tenant's local override or
      a tenant-private actor (e.g. an unnamed insider threat handle).
      Local rows shadow the global one when both exist.

    The actor card API returns the merged view (global as the base,
    tenant overlay on top) so downstream consumers don't have to know
    where each field came from.
    """

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "handle", name="uq_threatactor_tenant_handle"
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(default="__global__", index=True)
    handle: str = Field(index=True)
    """Canonical actor name (e.g. ``"APT29"``, ``"FIN7"``, ``"Lazarus"``)."""
    aliases: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Alternate names (e.g. APT29 ≡ Cozy Bear ≡ Nobelium).",
    )
    description: str = Field(
        default="",
        description="One-paragraph briefing on the actor.",
    )
    motivation: ActorMotivation = Field(
        default=ActorMotivation.UNKNOWN,
        index=True,
    )
    sophistication: ActorSophistication = Field(
        default=ActorSophistication.UNKNOWN,
        index=True,
    )
    origin_country: Optional[str] = Field(
        default=None,
        index=True,
        description="ISO-3166 alpha-2 country code (best-guess attribution).",
    )
    target_sectors: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Industries the actor preys on (finserv, healthcare, ...).",
    )
    target_regions: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Geographic regions (NA, EMEA, APAC, ...).",
    )
    techniques: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="MITRE ATT&CK technique IDs (e.g. ``T1566.001``).",
    )
    tools: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Known malware / tools (Cobalt Strike, BloodHound, ...).",
    )
    campaigns: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="Named campaigns attributed to this actor.",
    )
    references: list[str] = Field(
        default_factory=list,
        sa_column=Column(JSON),
        description="URLs to public write-ups, CTI reports.",
    )
    confidence: int = Field(
        default=50,
        index=True,
        description="0-100 attribution confidence.",
    )
    first_observed: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
        description="When this actor was first attributed to activity.",
    )
    last_observed: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
        description="Most recent activity timestamp.",
    )
    active: bool = Field(
        default=True,
        index=True,
        description="False once an actor has gone dark / been disrupted.",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )


class ActorIOCLink(SQLModel, table=True):
    """Denormalised IOC ↔ actor association.

    The threat graph already encodes this relationship via an
    ``ATTRIBUTED_TO`` edge, but graph BFS is overkill for the
    common case of "given this IOC, which actor(s) own it?". This
    table is the materialised view that keeps the actor-card pivot
    response fast.

    The agent owns this table — analysts shouldn't write to it
    directly. Use the API or let the profiling sweep rebuild it.
    """

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "actor_handle",
            "ioc_value",
            name="uq_actorioclink_tenant_actor_ioc",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    tenant_id: str = Field(default="__global__", index=True)
    actor_handle: str = Field(
        index=True,
        description="Matches :attr:`ThreatActor.handle` (or an alias).",
    )
    ioc_value: str = Field(
        index=True,
        description="Raw IOC string (ip, domain, hash, ...).",
    )
    ioc_type: str = Field(
        default="unknown",
        index=True,
        description="One of: ip, domain, url, hash, email, ...",
    )
    confidence: int = Field(
        default=50,
        description="0-100 confidence in this specific link.",
    )
    source: str = Field(
        default="cti.enrich_ioc",
        description="Where the link came from (CTI tool, manual, sweep).",
    )
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        index=True,
    )


__all__ = [
    "ActorIOCLink",
    "ActorMotivation",
    "ActorSophistication",
    "ThreatActor",
]
