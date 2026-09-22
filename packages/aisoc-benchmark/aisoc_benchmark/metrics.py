"""Benchmark metrics: accuracy, hallucination, containment, cost.

Pillar 4. The existing scoreboard publishes MITRE accuracy and three
substrate self-consistency numbers. Three metrics the plan calls for are
absent, and each is absent for the same reason: they are the ones that make
an agent look worse.

**Hallucination rate.** Measured, not estimated: the fraction of concrete
indicators an agent cites that do not appear anywhere in the evidence it was
given. An agent that invents a plausible IP address to justify a verdict is
doing the single most dangerous thing an analyst-replacement can do, and no
accuracy number reveals it.

**Containment accuracy.** Whether the proposed action matches what the
incident needed. An agent that reaches the right verdict and proposes
isolating the wrong host has not helped.

**Calibration.** Confidence is only useful if it tracks correctness.
Published as the gap between mean confidence on correct answers and on wrong
ones; a small or negative gap means the confidence score carries no
information, and everything downstream that gates on a threshold is gating
on noise.

Abstention is treated as its own outcome throughout rather than folded into
either accuracy or error. "I do not know" is a correct answer that a
forced-choice benchmark punishes, and punishing it trains agents to guess.
The abstention rate is published beside accuracy so the two cannot be traded
off invisibly.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

#: Indicator shapes we can check against evidence. Free-text claims are not
#: graded: "the process behaved suspiciously" is not checkable, and scoring
#: it would measure phrasing.
_INDICATOR_PATTERNS = (
    re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),  # IPv4
    re.compile(r"\b[a-fA-F0-9]{64}\b"),  # SHA-256
    re.compile(r"\b[a-fA-F0-9]{40}\b"),  # SHA-1
    re.compile(r"\b[a-fA-F0-9]{32}\b"),  # MD5
    re.compile(r"\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b"),  # domain-ish
)


def is_checkable_indicator(value: str) -> bool:
    """Whether a cited indicator has a shape we can verify against evidence."""
    text = (value or "").strip()
    if not text:
        return False
    return any(pattern.search(text) for pattern in _INDICATOR_PATTERNS)


def evidence_corpus(incident: Any) -> str:
    """Everything the agent was given, flattened for containment checks."""
    parts = [
        str(getattr(incident, "title", "")),
        str(getattr(incident, "description", "")),
        repr(getattr(incident, "raw_alert", {})),
        repr(getattr(incident, "telemetry", [])),
    ]
    return " ".join(parts).lower()


@dataclass
class IncidentScore:
    """One incident's outcome. Kept per-incident so a published aggregate
    can be traced back to the cases that produced it."""

    incident_id: str
    abstained: bool = False
    disposition_correct: bool = False
    technique_recall: float = 0.0
    technique_precision: float = 0.0
    hallucinated_indicators: list[str] = field(default_factory=list)
    cited_checkable: int = 0
    containment_correct: bool | None = None
    confidence: float = 0.0
    latency_ms: int = 0
    tokens: int = 0
    usd_cost: float = 0.0
    distinct_tools: int = 0


@dataclass
class BenchmarkResult:
    """Aggregate scores. Every field is defined so a reader can reproduce it."""

    agent_name: str
    agent_version: str
    incidents: int = 0

    # Accuracy, computed over answered incidents only. Dividing by the whole
    # corpus would let an agent raise its score by abstaining more, which is
    # the exact behaviour the abstention rate exists to expose.
    disposition_accuracy: float = 0.0
    technique_recall: float = 0.0
    technique_precision: float = 0.0
    containment_accuracy: float | None = None

    # Honesty.
    abstention_rate: float = 0.0
    hallucination_rate: float = 0.0
    hallucinated_total: int = 0
    indicators_checked: int = 0

    # Calibration: mean confidence when right minus mean confidence when
    # wrong. Near zero means the confidence score carries no information.
    calibration_gap: float = 0.0
    mean_confidence_correct: float = 0.0
    mean_confidence_incorrect: float = 0.0

    # Cost and latency, reported not scored.
    mean_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    total_tokens: int = 0
    total_usd: float = 0.0
    mean_usd_per_incident: float = 0.0
    mean_distinct_tools: float = 0.0

    # Provenance. A corpus of synthetic incidents produces a synthetic
    # number, and a scoreboard that does not say so is misleading even when
    # every figure in it is arithmetically correct.
    corpus_provenance: dict[str, int] = field(default_factory=dict)

    per_incident: list[IncidentScore] = field(default_factory=list)

    def as_dict(self, *, include_per_incident: bool = False) -> dict[str, Any]:
        payload = asdict(self)
        if not include_per_incident:
            payload.pop("per_incident", None)
        return payload


def score_incident(
    incident: Any,
    verdict: Any,
    expected: dict[str, Any],
) -> IncidentScore:
    """Grade one verdict against ground truth."""
    score = IncidentScore(
        incident_id=str(getattr(incident, "incident_id", "")),
        abstained=bool(getattr(verdict, "abstained", False)),
        confidence=float(getattr(verdict, "confidence", 0.0) or 0.0),
        latency_ms=int(getattr(verdict, "latency_ms", 0) or 0),
        tokens=int(getattr(verdict, "tokens", 0) or 0),
        usd_cost=float(getattr(verdict, "usd_cost", 0.0) or 0.0),
        distinct_tools=int(getattr(verdict, "distinct_tools", 0) or 0),
    )

    # Hallucination is graded even on abstention: an agent that declines to
    # reach a verdict while citing an invented address has still invented it,
    # and that is the behaviour worth catching.
    corpus = evidence_corpus(incident)
    for indicator in getattr(verdict, "cited_indicators", None) or []:
        text = str(indicator).strip()
        if not is_checkable_indicator(text):
            continue
        score.cited_checkable += 1
        if text.lower() not in corpus:
            score.hallucinated_indicators.append(text)

    if score.abstained:
        return score

    expected_disposition = str(expected.get("disposition", "")).lower()
    if expected_disposition:
        score.disposition_correct = str(getattr(verdict, "disposition", "")).lower() == expected_disposition

    expected_techniques = {str(t).upper() for t in (expected.get("techniques") or [])}
    predicted = {str(t).upper() for t in (getattr(verdict, "techniques", None) or [])}
    if expected_techniques:
        hits = len(expected_techniques & predicted)
        score.technique_recall = hits / len(expected_techniques)
        score.technique_precision = hits / len(predicted) if predicted else 0.0

    expected_actions = {str(a).lower() for a in (expected.get("actions") or [])}
    if expected_actions:
        proposed = {str(a).lower() for a in (getattr(verdict, "proposed_actions", None) or [])}
        # Any overlap counts. Requiring an exact set would grade an agent on
        # matching our action vocabulary rather than on containing the
        # incident, and a vendor's verbs are legitimately their own.
        score.containment_correct = bool(expected_actions & proposed)

    return score


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def aggregate(
    agent_name: str,
    agent_version: str,
    scores: list[IncidentScore],
    *,
    corpus_provenance: dict[str, int] | None = None,
) -> BenchmarkResult:
    """Roll per-incident scores into the published figures."""
    result = BenchmarkResult(
        agent_name=agent_name,
        agent_version=agent_version,
        incidents=len(scores),
        per_incident=scores,
        corpus_provenance=dict(corpus_provenance or {}),
    )
    if not scores:
        return result

    answered = [s for s in scores if not s.abstained]
    result.abstention_rate = (len(scores) - len(answered)) / len(scores)

    if answered:
        result.disposition_accuracy = sum(s.disposition_correct for s in answered) / len(answered)
        result.technique_recall = sum(s.technique_recall for s in answered) / len(answered)
        result.technique_precision = sum(s.technique_precision for s in answered) / len(answered)

        containment = [s for s in answered if s.containment_correct is not None]
        if containment:
            result.containment_accuracy = sum(bool(s.containment_correct) for s in containment) / len(containment)

        correct = [s.confidence for s in answered if s.disposition_correct]
        wrong = [s.confidence for s in answered if not s.disposition_correct]
        result.mean_confidence_correct = sum(correct) / len(correct) if correct else 0.0
        result.mean_confidence_incorrect = sum(wrong) / len(wrong) if wrong else 0.0
        result.calibration_gap = result.mean_confidence_correct - result.mean_confidence_incorrect

    # Hallucination spans every incident, answered or not.
    result.indicators_checked = sum(s.cited_checkable for s in scores)
    result.hallucinated_total = sum(len(s.hallucinated_indicators) for s in scores)
    result.hallucination_rate = result.hallucinated_total / result.indicators_checked if result.indicators_checked else 0.0

    latencies = [float(s.latency_ms) for s in scores]
    result.mean_latency_ms = sum(latencies) / len(latencies)
    result.p95_latency_ms = _percentile(latencies, 0.95)
    result.total_tokens = sum(s.tokens for s in scores)
    result.total_usd = round(sum(s.usd_cost for s in scores), 6)
    result.mean_usd_per_incident = round(result.total_usd / len(scores), 6)
    result.mean_distinct_tools = sum(s.distinct_tools for s in scores) / len(scores)

    return result
