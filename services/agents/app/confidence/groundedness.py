"""Groundedness / hallucination eval axis (Wave 6).

The eval harness's four axes are substrate self-consistency gates (keyword
matching over synthetic descriptions), not measures of whether the *live agent*
invented facts. This module adds a distinct, blind axis: **groundedness** —
what fraction of the concrete indicators an agent asserts in its output actually
appear in the evidence it was given. An indicator in the output that is absent
from the evidence is a hallucination.

This is deliberately conservative and deterministic (regex indicator
extraction), so it can gate the agent in CI without an LLM in the loop, and it
grounds the "prove the AI's output" honesty bar: a confident verdict that cites
IOCs the evidence never contained should score low and be flagged.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Concrete, checkable indicators. Deliberately narrow — we only score things
# that must be traceable to evidence, not prose.
_PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "mitre": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
    "domain": re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE),
}

# Domains that are structural noise, not claimed indicators.
_DOMAIN_STOPWORDS = {"e.g", "i.e", "etc.al"}


@dataclass(frozen=True)
class GroundednessResult:
    score: float  # 1.0 = every claimed indicator is grounded in evidence
    grounded: list[str] = field(default_factory=list)
    hallucinated: list[str] = field(default_factory=list)

    @property
    def has_hallucination(self) -> bool:
        return bool(self.hallucinated)


def _extract(text: str) -> set[str]:
    found: set[str] = set()
    for kind, pattern in _PATTERNS.items():
        for match in pattern.findall(text or ""):
            token = match.lower()
            if kind == "domain" and (token in _DOMAIN_STOPWORDS or "." not in token):
                continue
            found.add(token)
    return found


def score_groundedness(output_text: str, evidence_text: str) -> GroundednessResult:
    """Fraction of the output's concrete indicators that appear in the evidence.

    No indicators claimed => perfectly grounded (score 1.0): the agent didn't
    assert any checkable fact to hallucinate.
    """
    claimed = _extract(output_text)
    if not claimed:
        return GroundednessResult(score=1.0)
    evidence = _extract(evidence_text)
    grounded = sorted(claimed & evidence)
    hallucinated = sorted(claimed - evidence)
    score = len(grounded) / len(claimed)
    return GroundednessResult(score=round(score, 4), grounded=grounded, hallucinated=hallucinated)
