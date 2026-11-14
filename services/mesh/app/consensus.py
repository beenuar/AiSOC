"""The deterministic mesh verdict stage + the pre-publish preview.

``mesh_contribution`` turns community consensus for an alert's signature into a
bounded verdict adjustment (capped at ±0.10 so the mesh can nudge, never
dominate, a local verdict). This is the ``mesh.py`` stage the verdict engine
gains; it is pure and unit-tested, and its cap is the gate.

``mesh_preview`` shows an operator exactly what an artifact would reveal before
they enable sharing — the "no surprises" guarantee.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.artifacts import IocSighting, VerdictSignature

MESH_CAP = 0.10


@dataclass
class MeshContribution:
    delta: float  # bounded to [-MESH_CAP, +MESH_CAP]
    basis: str
    instances: int


def mesh_contribution(consensus: dict | None) -> MeshContribution:
    """Compute the bounded verdict delta from a hub ``query_signature`` result.

    High community FP-rate pulls a verdict down (toward benign); a
    community that overwhelmingly confirms true positives nudges up. The
    magnitude scales with how many distinct instances agree, capped at
    ±MESH_CAP. ``None`` (below k-anonymity) contributes nothing.
    """
    if not consensus:
        return MeshContribution(delta=0.0, basis="no community consensus (below k-anonymity)", instances=0)

    instances = int(consensus.get("instances", 0))
    fp_rate = float(consensus.get("fp_rate", 0.0))
    # Confidence in the community signal grows with agreement, saturating ~20 instances.
    weight = min(instances / 20.0, 1.0)
    # fp_rate 1.0 -> strongest downward pull; fp_rate 0.0 -> strongest upward.
    direction = (0.5 - fp_rate) * 2.0  # [-1, +1]
    delta = max(-MESH_CAP, min(MESH_CAP, direction * weight * MESH_CAP))
    pct = round(fp_rate * 100)
    basis = f"community: {instances} instances saw this signature, {pct}% FP"
    return MeshContribution(delta=round(delta, 4), basis=basis, instances=instances)


def mesh_preview(iocs: list[IocSighting], signatures: list[VerdictSignature]) -> dict:
    """Exactly what would be shared if sharing were enabled — no raw values."""
    return {
        "would_share": {
            "ioc_sightings": [{"ioc_hash": s.ioc_hash, "ioc_type": s.ioc_type, "severity": s.severity} for s in iocs],
            "verdict_signatures": [
                {
                    "signature_key": v.signature_key,
                    "category": v.category,
                    "connector_type": v.connector_type,
                    "primary_technique": v.primary_technique,
                    "verdict_counts": v.verdict_counts,
                }
                for v in signatures
            ],
        },
        "never_shared": [
            "raw IOC values (only SHA-256 hashes leave)",
            "entity names, hostnames, usernames, IPs",
            "tenant identifiers",
            "alert free text / descriptions",
        ],
        "counts": {"ioc_sightings": len(iocs), "verdict_signatures": len(signatures)},
    }
