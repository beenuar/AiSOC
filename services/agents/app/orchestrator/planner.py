"""Specialist planner — scored, bounded agent selection (Wave 4b).

``classify_signals`` fans out to ALL FOUR specialists whenever no keyword
matches, and runs every keyword-matched specialist with no ranking. That is
both imprecise (a novel alert brute-forces the whole roster) and expensive.

This planner scores each specialist by weighted signal strength (raw structured
fields count more than free-text keyword hits, and MITRE tactics add signal),
returns the top-N scoring specialists, and on a genuinely ambiguous alert picks
a single conservative default instead of the whole roster. It is pure and
deterministic, so it is cheap to run ahead of the (expensive) specialist LLMs.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.models.state import InvestigationState
from app.orchestrator.router import (
    _CLOUD_KEYWORDS,
    _CLOUD_RAW_FIELDS,
    _IDENTITY_KEYWORDS,
    _IDENTITY_RAW_FIELDS,
    _INSIDER_KEYWORDS,
    _INSIDER_RAW_FIELDS,
    _PHISHING_KEYWORDS,
    _PHISHING_RAW_FIELDS,
)

_SPECIALISTS: dict[str, tuple[set[str], set[str]]] = {
    "phishing": (_PHISHING_KEYWORDS, _PHISHING_RAW_FIELDS),
    "identity": (_IDENTITY_KEYWORDS, _IDENTITY_RAW_FIELDS),
    "cloud": (_CLOUD_KEYWORDS, _CLOUD_RAW_FIELDS),
    "insider": (_INSIDER_KEYWORDS, _INSIDER_RAW_FIELDS),
}

# A raw structured field is a much stronger routing signal than a free-text
# keyword mention, so it is weighted higher.
_KEYWORD_WEIGHT = 1.0
_RAW_FIELD_WEIGHT = 3.0

# When nothing scores, route to identity first: credential/access abuse is the
# most common cross-cutting root cause and the cheapest specialist to run.
_DEFAULT_ON_AMBIGUOUS = "identity"


@dataclass(frozen=True)
class Plan:
    specialists: list[str]
    scores: dict[str, float]
    ambiguous: bool = False
    rationale: list[str] = field(default_factory=list)


def _haystack(state: InvestigationState) -> str:
    parts = [state.alert_summary or ""]
    parts.extend(str(f) for f in (state.findings or []))
    raw = state.raw_alert or {}
    parts.append(" ".join(f"{k}:{v}" for k, v in raw.items() if isinstance(v, str | int | float)))
    return " ".join(parts).lower()


def plan_specialists(state: InvestigationState, *, max_agents: int = 2) -> Plan:
    """Return the top-scoring specialists to run for this alert (bounded)."""
    haystack = _haystack(state)
    raw_keys = {str(k).lower() for k in (state.raw_alert or {})}
    scores: dict[str, float] = {}
    for name, (keywords, raw_fields) in _SPECIALISTS.items():
        kw_hits = sum(1 for kw in keywords if kw in haystack)
        raw_hits = len(raw_keys & {f.lower() for f in raw_fields})
        score = kw_hits * _KEYWORD_WEIGHT + raw_hits * _RAW_FIELD_WEIGHT
        if score > 0:
            scores[name] = score

    if not scores:
        return Plan(
            specialists=[_DEFAULT_ON_AMBIGUOUS],
            scores={},
            ambiguous=True,
            rationale=[f"no specialist signal; conservative default '{_DEFAULT_ON_AMBIGUOUS}'"],
        )

    ranked = sorted(scores, key=lambda n: (scores[n], n), reverse=True)
    chosen = ranked[: max(1, max_agents)]
    return Plan(
        specialists=chosen,
        scores=scores,
        ambiguous=False,
        rationale=[f"{n}={scores[n]:.0f}" for n in ranked],
    )
