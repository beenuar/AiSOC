"""Threat Actor Profiling Agent (t3e-actor-profiling).

Proactive, scheduler-driven sub-agent that fuses Cyble's canonical
actor catalogue (``cti.actor_lookup``) with whatever attribution
signal lives in the tenant's IOC corpus (``cti.enrich_ioc``) and
materialises three first-class artifacts:

1.  :class:`ThreatActor` rows — the per-actor profile card (aliases,
    motivation, sophistication, origin, sectors, ATT&CK techniques,
    tooling, campaigns). Global rows are inherited from the catalogue;
    tenant-local rows accumulate observed activity (``last_observed``,
    confidence bumps).
2.  :class:`ActorIOCLink` rows — denormalised IOC → actor edges for
    sub-millisecond pivot queries (``GET /api/actors/pivot?ioc=...``).
3.  Threat-graph nodes/edges — ``NodeType.ACTOR`` plus
    ``EdgeType.ATTRIBUTED_TO`` from each IOC node back to its actor,
    keeping the graph as the canonical relationship store.

Design echoes :class:`ExposureAgent`: not a :class:`BaseAgent` subclass
(no case ownership), per-tenant instances, deterministic re-run safe,
and writes traces only when there's a case to attach them to.
"""
from app.agents.actor_profiler.agent import ThreatActorProfilingAgent
from app.agents.actor_profiler.models import (
    ActorProfileFinding,
    ActorProfilingResult,
)

__all__ = [
    "ActorProfileFinding",
    "ActorProfilingResult",
    "ThreatActorProfilingAgent",
]
