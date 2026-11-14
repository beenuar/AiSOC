"""Complexity gate: decide whether a case warrants the swarm.

Single-agent investigation is cheaper and fine for most alerts. The swarm only
fires above a complexity threshold — enough distinct entities and/or a broad
enough technique spread that competing explanations are plausible.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Defaults; overridable per tenant via a flag in the orchestrator.
DEFAULT_ENTITY_THRESHOLD = 3
DEFAULT_TECHNIQUE_THRESHOLD = 3


@dataclass(frozen=True)
class ComplexityAssessment:
    is_complex: bool
    entity_count: int
    technique_count: int
    reasons: list[str] = field(default_factory=list)


def _count_entities(signal: dict) -> int:
    keys = ("src_ip", "dst_ip", "domain", "file_hash", "url", "hostname", "username")
    iocs = signal.get("iocs", {}) if isinstance(signal.get("iocs"), dict) else {}
    distinct = {signal.get(k) for k in keys if signal.get(k)} | {iocs.get(k) for k in keys if iocs.get(k)}
    distinct.discard(None)
    # Also count explicitly-listed related entities.
    related = signal.get("related_entities") or []
    return len(distinct) + (len(related) if isinstance(related, list) else 0)


def assess_complexity(
    signal: dict,
    *,
    entity_threshold: int = DEFAULT_ENTITY_THRESHOLD,
    technique_threshold: int = DEFAULT_TECHNIQUE_THRESHOLD,
) -> ComplexityAssessment:
    """Assess whether ``signal`` (an alert-like dict) is complex enough to swarm."""
    entities = _count_entities(signal)
    techniques = len(signal.get("techniques") or signal.get("mitre_techniques") or [])
    reasons: list[str] = []
    if entities >= entity_threshold:
        reasons.append(f"{entities} distinct entities (>= {entity_threshold})")
    if techniques >= technique_threshold:
        reasons.append(f"{techniques} MITRE techniques (>= {technique_threshold})")
    return ComplexityAssessment(
        is_complex=bool(reasons),
        entity_count=entities,
        technique_count=techniques,
        reasons=reasons,
    )
