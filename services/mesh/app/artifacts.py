"""The two mesh artifact types + the canonical bytes each instance signs.

1. IOC sighting — a hashed indicator with first/last-seen and severity. No raw
   IOC, no entity, no tenant data.
2. Verdict signature — the alert signature key already used by institutional
   memory (category + connector + primary technique) plus a verdict
   distribution and confidence stats. No tenant data, no entities, no free text.

The signed message is a stable, sorted JSON encoding so signatures are
reproducible and verifiable independent of dict ordering.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class IocSighting:
    """A privacy-preserving IOC sighting. ``ioc_hash`` is SHA-256(normalized IOC)."""

    ioc_hash: str
    ioc_type: str  # coarse type only (ip|domain|hash|url) — not the value
    severity: str  # info|low|medium|high|critical
    first_seen: str  # ISO-8601
    last_seen: str

    def signing_bytes(self) -> bytes:
        return _canonical({"kind": "ioc_sighting", **asdict(self)})


@dataclass(frozen=True)
class VerdictSignature:
    """Aggregate verdict distribution for an alert signature. No tenant data."""

    signature_key: str  # sha1 of category|connector|technique (see verdict_signature_key)
    category: str
    connector_type: str
    primary_technique: str
    verdict_counts: dict = field(default_factory=dict)  # {"true_positive": n, "false_positive": m, ...}
    mean_confidence: float = 0.0

    def signing_bytes(self) -> bytes:
        return _canonical(
            {
                "kind": "verdict_signature",
                "signature_key": self.signature_key,
                "category": self.category,
                "connector_type": self.connector_type,
                "primary_technique": self.primary_technique,
                "verdict_counts": self.verdict_counts,
                "mean_confidence": round(self.mean_confidence, 4),
            }
        )


def verdict_signature_key(category: str, connector_type: str, primary_technique: str) -> str:
    """Mirror the institutional-memory signature identity (sans severity band).

    Kept intentionally aligned with
    ``services/api/app/services/override_learning.py:AlertSignature`` so a
    signature computed locally matches what the mesh aggregates.
    """
    raw = f"{category.strip().lower()}|{connector_type.strip().lower()}|{primary_technique.strip().upper()}"
    return hashlib.sha1(raw.encode()).hexdigest()  # noqa: S324 - identity key, not a security control
