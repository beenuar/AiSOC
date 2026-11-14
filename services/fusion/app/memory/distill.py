"""Nightly distillation: overrides + verdict history → priors + few-shot bank.

Two outputs, both versioned and ledger-referenceable:

1. **Per-signature priors** — for each alert signature (category + connector +
   primary technique), the historical disposition (how often analysts corrected
   it to benign vs. confirmed it), consumed by the deterministic ``memory``
   verdict stage.
2. **Few-shot exemplar bank** — the top-N most-informative resolved cases per
   category, injected into the LLM band prompt.

Pure and deterministic so it's unit-testable and its output is reproducible
(the version is a content hash).
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime


def signature_key(category: str, connector_type: str, primary_technique: str) -> str:
    """Alert signature identity — aligned with the mesh + institutional-memory key."""
    raw = f"{category.strip().lower()}|{connector_type.strip().lower()}|{primary_technique.strip().upper()}"
    return hashlib.sha1(raw.encode()).hexdigest()  # noqa: S324 - identity key, not a security control


@dataclass(frozen=True)
class SignaturePrior:
    signature_key: str
    category: str
    sample_count: int
    fp_rate: float  # share resolved benign/false-positive, 0–1
    # A prior in [0, 1]: 1.0 = historically always a true positive, 0.0 = always benign.
    prior: float


@dataclass(frozen=True)
class Exemplar:
    category: str
    signature_key: str
    disposition: str  # true_positive | false_positive | ...
    summary: str


@dataclass(frozen=True)
class MemoryPack:
    version: str  # content hash — ledger-referenceable
    created_at: str
    priors: dict[str, SignaturePrior] = field(default_factory=dict)
    few_shot: list[Exemplar] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "version": self.version,
            "created_at": self.created_at,
            "priors": {k: asdict(v) for k, v in self.priors.items()},
            "few_shot": [asdict(e) for e in self.few_shot],
        }

    @classmethod
    def from_json(cls, data: dict) -> MemoryPack:
        priors = {k: SignaturePrior(**v) for k, v in data.get("priors", {}).items()}
        few_shot = [Exemplar(**e) for e in data.get("few_shot", [])]
        return cls(version=data["version"], created_at=data["created_at"], priors=priors, few_shot=few_shot)


_BENIGN_VERDICTS = {"false_positive", "likely_benign", "benign"}


def distill(overrides: list[dict], *, top_n_per_category: int = 3) -> MemoryPack:
    """Distill a memory pack from analyst override / verdict-history rows.

    Each row: ``{category, connector_type, primary_technique, corrected_verdict,
    summary?}``. ``corrected_verdict`` is the analyst's ground-truth disposition.
    """
    buckets: dict[str, list[dict]] = defaultdict(list)
    for row in overrides:
        key = signature_key(
            row.get("category", ""),
            row.get("connector_type", ""),
            row.get("primary_technique", ""),
        )
        buckets[key].append(row)

    priors: dict[str, SignaturePrior] = {}
    for key, rows in buckets.items():
        n = len(rows)
        benign = sum(1 for r in rows if str(r.get("corrected_verdict", "")).lower() in _BENIGN_VERDICTS)
        fp_rate = benign / n if n else 0.0
        priors[key] = SignaturePrior(
            signature_key=key,
            category=rows[0].get("category", ""),
            sample_count=n,
            fp_rate=round(fp_rate, 4),
            prior=round(1.0 - fp_rate, 4),
        )

    # Few-shot bank: top-N by sample_count per category (most-evidenced exemplars).
    by_category: dict[str, list[dict]] = defaultdict(list)
    for row in overrides:
        by_category[row.get("category", "")].append(row)
    few_shot: list[Exemplar] = []
    for category, rows in sorted(by_category.items()):
        # Prefer rows that carry a human summary; stable order by summary length desc.
        ranked = sorted(rows, key=lambda r: len(str(r.get("summary", ""))), reverse=True)
        for r in ranked[:top_n_per_category]:
            few_shot.append(
                Exemplar(
                    category=category,
                    signature_key=signature_key(category, r.get("connector_type", ""), r.get("primary_technique", "")),
                    disposition=str(r.get("corrected_verdict", "unknown")),
                    summary=str(r.get("summary", ""))[:280],
                )
            )

    body = json.dumps(
        {"priors": {k: asdict(v) for k, v in sorted(priors.items())}, "few_shot": [asdict(e) for e in few_shot]},
        sort_keys=True,
    )
    version = "mem:v1:" + hashlib.sha256(body.encode()).hexdigest()[:16]
    return MemoryPack(version=version, created_at=datetime.now(UTC).isoformat(), priors=priors, few_shot=few_shot)
