"""Internal dataclasses for the Threat Actor Profiling Agent.

These are *transient* — they exist only during a single sweep. The
durable artifacts produced by the agent are :class:`ThreatActor`,
:class:`ActorIOCLink` rows, and graph nodes/edges in
:mod:`app.memory.graph`. We keep this module dependency-light
(no SQLModel imports) so unit tests can construct findings without
spinning up the DB.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ActorProfileFinding:
    """One actor profile materialised during a sweep.

    A finding carries both the canonical profile (from
    ``cti.actor_lookup``) and the *observed* set of IOCs we saw
    attributed to this actor in the tenant's corpus during the
    current sweep. The agent uses ``observed_iocs`` to build
    :class:`ActorIOCLink` rows and ``ATTRIBUTED_TO`` graph edges.
    """

    handle: str
    """Canonical actor name (e.g. ``"APT29"``)."""
    profile: dict[str, Any]
    """Raw payload returned by ``cti.actor_lookup`` (or ``{}`` if the
    actor is unknown to the catalogue — we still record the link so
    analysts can pivot on un-named handles)."""
    observed_iocs: list[dict[str, Any]] = field(default_factory=list)
    """Each entry: ``{"value": str, "type": str, "threat_score": int,
    "confidence": int, "source": str}``. Populated by the IOC scan
    phase, consumed by the materialisation phase."""
    catalogue_hit: bool = False
    """True when ``cti.actor_lookup`` returned ``found=True``. False
    means the IOC's ``actor`` field referenced a handle we don't have
    a canonical profile for yet (e.g. a fresh crew); we still create
    a stub :class:`ThreatActor` row so the API can list them."""


@dataclass
class ActorProfilingResult:
    """Aggregate output of one per-tenant sweep.

    Mirrors :class:`app.agents.exposure.models.ExposureSweepResult` in
    spirit: every counter that matters for "did this sweep do useful
    work?" lives here so the scheduler logs and tests can assert
    against a single object.
    """

    tenant_id: str
    findings: list[ActorProfileFinding] = field(default_factory=list)
    actors_upserted: int = 0
    """Total :class:`ThreatActor` rows touched (created or updated)."""
    actors_new: int = 0
    """Of those, how many were created this sweep."""
    ioc_links_upserted: int = 0
    """Total :class:`ActorIOCLink` rows touched."""
    ioc_links_new: int = 0
    graph_nodes_upserted: int = 0
    graph_edges_upserted: int = 0
    iocs_scanned: int = 0
    """Total IOC rows we examined for actor attribution."""
    catalogue_misses: int = 0
    """How many distinct actor handles we couldn't resolve via
    ``cti.actor_lookup``. High numbers indicate the catalogue needs
    a refresh — surfaced in the sweep summary log line."""
    errors: list[str] = field(default_factory=list)


__all__ = ["ActorProfileFinding", "ActorProfilingResult"]
