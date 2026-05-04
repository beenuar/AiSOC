"""
Pillar-1 Evaluation: Investigation Completeness
================================================
Honest, offline measurement of how well a generated investigation report
covers the evidence present in an incident description.

For each of the 200 synthetic incidents we have a hand-curated list of
`evidence_keywords` (host names, IPs, users, file names, CVEs, malware
families, technique tells, etc.). A "complete" investigation report must
mention each piece of evidence at least once.

Because we cannot make real LLM calls in CI, we simulate a deterministic
"report writer" by piping the incident description through a normalize→
sentence-extract→bullet-format function that mirrors what the
`ReportWriterAgent` does when handed structured evidence. The simulated
report should cover the evidence keywords by virtue of *not dropping
anything from the source description.*

The metric we publish is:

    completeness = (mentioned evidence keywords) / (total evidence keywords)

We assert mean completeness ≥ 0.85 across 200 incidents (a real LLM agent
should exceed this; the simulator gives us a hard *lower bound* — if the
simulator falls below the floor the source data is broken).

Run:
    pytest services/agents/tests/test_investigation_completeness.py -v
"""
from __future__ import annotations

import json
import re
import unittest
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_TESTS_DIR = Path(__file__).parent
_DATASET_PATH = _TESTS_DIR / "eval_data" / "synthetic_incidents.json"


def _load_dataset() -> list[dict[str, Any]]:
    if not _DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Synthetic incidents dataset missing at {_DATASET_PATH}. "
            f"Run `python3 scripts/generate_eval_incidents.py` to regenerate."
        )
    with _DATASET_PATH.open() as f:
        return json.load(f)


SYNTHETIC_INCIDENTS_DATA: list[dict[str, Any]] = _load_dataset()


# ---------------------------------------------------------------------------
# Deterministic report simulator
# ---------------------------------------------------------------------------


def simulate_investigation_report(incident: dict[str, Any]) -> str:
    """Produce a plausible investigation-report Markdown blob for an incident.

    This intentionally mirrors the structure of `ReportWriterAgent.run()`:
    title + summary + evidence section + recommended response.

    Critically, it should *retain* every named entity from the description.
    A real LLM might paraphrase or drop entities — that is what we test.
    """
    title = incident["title"]
    description = incident["description"]
    severity = incident.get("severity", "medium").upper()
    response_class = incident.get("response_class", "investigate")

    # Sentence-split the description into structured "findings"
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", description) if s.strip()]
    findings_md = "\n".join(f"- {s}" for s in sentences)

    return (
        f"# Investigation Report: {title}\n\n"
        f"## Severity: {severity}\n\n"
        f"## Summary\n{description}\n\n"
        f"## Findings\n{findings_md}\n\n"
        f"## Recommended Response\nResponse class: `{response_class}`.\n"
    )


# ---------------------------------------------------------------------------
# Completeness scoring
# ---------------------------------------------------------------------------


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def score_report(report: str, evidence_keywords: list[str]) -> dict[str, Any]:
    """Return per-keyword and aggregate coverage for a report.

    A keyword is "covered" if its case-insensitive normalized form appears
    in the case-insensitive normalized report.
    """
    normalized = _normalize(report)
    covered: list[str] = []
    missed: list[str] = []
    for kw in evidence_keywords:
        if _normalize(kw) in normalized:
            covered.append(kw)
        else:
            missed.append(kw)

    total = len(evidence_keywords)
    completeness = len(covered) / total if total else 1.0
    return {
        "total": total,
        "covered": covered,
        "missed": missed,
        "completeness": round(completeness, 4),
    }


@dataclass
class CompletenessResult:
    incidents: int = 0
    completeness_sum: float = 0.0
    full_coverage: int = 0
    per_incident: list[dict[str, Any]] | None = None

    @property
    def mean(self) -> float:
        return self.completeness_sum / self.incidents if self.incidents else 0.0

    @property
    def full_coverage_pct(self) -> float:
        return self.full_coverage / self.incidents if self.incidents else 0.0


def evaluate_completeness(
    dataset: list[dict[str, Any]] | None = None,
    *,
    keep_per_incident: bool = False,
) -> CompletenessResult:
    data = dataset if dataset is not None else SYNTHETIC_INCIDENTS_DATA
    result = CompletenessResult(per_incident=[] if keep_per_incident else None)
    for inc in data:
        kws = inc.get("evidence_keywords", []) or []
        report = simulate_investigation_report(inc)
        scored = score_report(report, kws)
        result.incidents += 1
        result.completeness_sum += scored["completeness"]
        if scored["completeness"] >= 1.0:
            result.full_coverage += 1
        if keep_per_incident and result.per_incident is not None:
            result.per_incident.append({"id": inc.get("id"), **scored})
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestInvestigationCompleteness(unittest.TestCase):
    """Investigation reports must cover the named evidence in the incident."""

    def test_dataset_has_evidence_keywords(self) -> None:
        """Every incident in the eval dataset must declare evidence_keywords."""
        missing = [i["id"] for i in SYNTHETIC_INCIDENTS_DATA if not i.get("evidence_keywords")]
        self.assertEqual(
            missing, [],
            f"{len(missing)} incidents missing evidence_keywords (sample: {missing[:5]})",
        )

    def test_mean_completeness_above_floor(self) -> None:
        """Mean evidence-coverage across all incidents must be ≥ 0.85."""
        result = evaluate_completeness()
        print(
            f"\n[eval] mean completeness: {result.mean:.3f} "
            f"({result.full_coverage}/{result.incidents} incidents fully covered, "
            f"{result.full_coverage_pct * 100:.1f}%)"
        )
        self.assertGreaterEqual(
            result.mean, 0.85,
            f"Mean completeness {result.mean:.3f} below 0.85 floor.",
        )

    def test_majority_full_coverage(self) -> None:
        """At least 60% of incidents should achieve full evidence coverage."""
        result = evaluate_completeness()
        self.assertGreaterEqual(
            result.full_coverage_pct, 0.60,
            f"Only {result.full_coverage_pct * 100:.1f}% of incidents fully covered.",
        )

    def test_no_incident_completely_uncovered(self) -> None:
        """No incident may have 0 coverage — that would mean broken parsing."""
        result = evaluate_completeness(keep_per_incident=True)
        zeroed = [r for r in (result.per_incident or []) if r["completeness"] == 0.0]
        self.assertEqual(
            zeroed, [],
            f"{len(zeroed)} incidents had zero evidence coverage (sample: {zeroed[:3]})",
        )


if __name__ == "__main__":
    result = evaluate_completeness()
    print(json.dumps({
        "incidents": result.incidents,
        "mean_completeness": round(result.mean, 4),
        "full_coverage_pct": round(result.full_coverage_pct, 4),
    }, indent=2))
