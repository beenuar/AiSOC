"""Three things about an agent's work that nothing in this repo measured.

Gap-closure wave 3.

`run_evals.py` has eleven suites. Hallucination rate, calibration and
token cost are real and useful. What none of them answer:

* **Did it reach for the right evidence?** An agent that lands on the
  correct verdict by reading the alert title and nothing else is not
  doing the job, and is one unusual alert away from being wrong. Grep
  for "tool selection" across the tree returns nothing.
* **Did it look at everything it was given?** Evidence completeness has
  the same zero hits. An investigation that ignored the one telemetry
  event that mattered can still produce a confident verdict.
* **How long did it take?** Latency is recorded per LLM call. Time from
  alert to verdict — the thing an analyst waits for — is not.

Why these three and not more
-------------------------------
Each is a *process* measurement rather than an outcome measurement, and
the distinction is the point. Verdict accuracy already exists and can be
satisfied by luck at the sample sizes this corpus supports. Two agents
that both answer "true positive" are not equally good if one checked the
host's criticality, the user's recent behaviour and the hash reputation,
and the other matched a keyword.

Scoring without being a second scoreboard
--------------------------------------------
Each returns a rate *and the denominator it came from*, and refuses to
produce a rate when its signal never appeared — the same contract the
injection metrics use, and for the same reason: an agent that calls no
tools scores 0-out-of-0 on tool selection, and rendering that as 0%
says the opposite of what happened.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "AgentRun",
    "QualityScore",
    "score_agent_quality",
]


@dataclass(frozen=True)
class AgentRun:
    """One investigation, as the harness observed it.

    `expected_tools` and `expected_evidence` are the corpus's answer key.
    They are deliberately *sets of acceptable* items rather than an
    ordered script: there is usually more than one reasonable way to
    investigate an alert, and grading an ordering would measure
    conformity to one author's habit.
    """

    incident_id: str
    verdict: str
    tools_called: tuple[str, ...] = ()
    evidence_cited: tuple[str, ...] = ()
    expected_tools: frozenset[str] = frozenset()
    expected_evidence: frozenset[str] = frozenset()
    #: Wall-clock from dispatch to verdict. `None` when the harness did
    #: not time it, which is different from "it was instant".
    seconds_to_verdict: float | None = None


@dataclass
class Measure:
    """A rate with its denominator, or a stated refusal to produce one."""

    numerator: int | None = None
    denominator: int | None = None
    reason: str | None = None

    @property
    def measured(self) -> bool:
        return self.numerator is not None and bool(self.denominator)

    @property
    def value(self) -> float | None:
        if not self.measured:
            return None
        assert self.numerator is not None and self.denominator is not None
        return round(self.numerator / self.denominator, 4)

    def render(self) -> str:
        if not self.measured:
            return f"not measured ({self.reason})"
        return f"{self.value:.1%} ({self.numerator}/{self.denominator})"

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "measured": self.measured,
            "reason": self.reason,
        }

    @classmethod
    def unmeasured(cls, reason: str) -> Measure:
        return cls(reason=reason)


@dataclass
class QualityScore:
    runs: int = 0
    tool_selection: Measure = field(default_factory=lambda: Measure.unmeasured("not computed"))
    evidence_completeness: Measure = field(default_factory=lambda: Measure.unmeasured("not computed"))
    #: Seconds. Reported with its sample count for the same reason every
    #: other mean here is: a mean over three runs and over three hundred
    #: are the same number and different facts.
    median_seconds_to_verdict: float | None = None
    p95_seconds_to_verdict: float | None = None
    timed_runs: int = 0
    #: Runs that called a tool the corpus does not list for that
    #: incident. Not a failure on its own — exploring is legitimate —
    #: but a rising number next to a flat completeness is the shape of
    #: an agent thrashing.
    unexpected_tool_runs: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "runs": self.runs,
            "tool_selection_accuracy": self.tool_selection.as_dict(),
            "evidence_completeness": self.evidence_completeness.as_dict(),
            "time_to_verdict": {
                "median_seconds": self.median_seconds_to_verdict,
                "p95_seconds": self.p95_seconds_to_verdict,
                "timed_runs": self.timed_runs,
                "measured": self.timed_runs > 0,
            },
            "unexpected_tool_runs": self.unexpected_tool_runs,
        }


def _percentile(values: Sequence[float], fraction: float) -> float | None:
    """Nearest-rank, which needs no interpolation story in the docs."""
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round(fraction * (len(ordered) - 1))))
    return round(ordered[index], 3)


def score_agent_quality(runs: Iterable[AgentRun]) -> QualityScore:
    """Grade tool selection, evidence completeness and time to verdict.

    Partial credit throughout, because the alternative grades an agent
    that found three of four required tools identically to one that
    found none — and the first is most of the way there.
    """
    materialised = list(runs)
    score = QualityScore(runs=len(materialised))
    if not materialised:
        reason = "no runs supplied"
        score.tool_selection = Measure.unmeasured(reason)
        score.evidence_completeness = Measure.unmeasured(reason)
        return score

    tool_hits = tool_total = 0
    evidence_hits = evidence_total = 0
    gradable_tool_runs = gradable_evidence_runs = 0
    timings: list[float] = []

    for run in materialised:
        if run.expected_tools:
            gradable_tool_runs += 1
            called = set(run.tools_called)
            tool_hits += len(run.expected_tools & called)
            tool_total += len(run.expected_tools)
            if called - run.expected_tools:
                score.unexpected_tool_runs += 1

        if run.expected_evidence:
            gradable_evidence_runs += 1
            cited = set(run.evidence_cited)
            evidence_hits += len(run.expected_evidence & cited)
            evidence_total += len(run.expected_evidence)

        if run.seconds_to_verdict is not None:
            timings.append(float(run.seconds_to_verdict))

    score.tool_selection = (
        Measure(tool_hits, tool_total)
        if gradable_tool_runs and tool_total
        else Measure.unmeasured(
            f"no incident among {len(materialised)} declares an expected tool, so there is nothing to grade a selection against"
        )
    )
    score.evidence_completeness = (
        Measure(evidence_hits, evidence_total)
        if gradable_evidence_runs and evidence_total
        else Measure.unmeasured(f"no incident among {len(materialised)} declares expected evidence, so completeness has no referent")
    )

    score.timed_runs = len(timings)
    score.median_seconds_to_verdict = _percentile(timings, 0.5)
    score.p95_seconds_to_verdict = _percentile(timings, 0.95)
    return score
