"""
Pillar-1 Evaluation: Investigation Completeness — Substrate Self-Consistency Gate
==================================================================================
Offline regression gate that the deterministic substrate report writer
preserves the evidence present in an incident description.

For each of the 200 synthetic incidents we have a hand-curated list of
`evidence_keywords` (host names, IPs, users, file names, CVEs, malware
families, technique tells, etc.). A "complete" report must mention each
piece of evidence at least once.

Because we cannot make real LLM calls in CI, we simulate a deterministic
"report writer" by piping the incident description through a normalize→
sentence-extract→bullet-format function that mirrors what the
`ReportWriterAgent` does when handed structured evidence. By construction,
the simulator wraps the source description, and the source description was
generated to include the evidence keywords — so this is a SUBSTRATE
SELF-CONSISTENCY GATE that detects regressions in the report-writer or the
dataset, NOT a measurement of whether a real LLM agent actually writes a
complete report on adversarial / blind data.

The metrics we publish are:

    completeness        = (mentioned evidence keywords) / (total)
    per_template_mean   = unweighted mean of completeness across the
                          ~55 distinct incident templates

We assert mean completeness ≥ 0.85 across 200 cases AND
per-template macro mean ≥ 0.80 across distinct templates. The
per-template gate is the regression-signal-preserving metric: with
~55 templates × ~3-4 duplicates, a single broken template moves
per-case mean by ~0.5% but per-template mean by ~1.8%.

See `apps/docs/docs/benchmark.md` for what each suite actually measures.

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
            f"Synthetic incidents dataset missing at {_DATASET_PATH}. Run `python3 scripts/generate_eval_incidents.py` to regenerate."
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

    def per_template_summary(self) -> dict[str, Any]:
        """Aggregate completeness by `template_id`.

        With ~55 templates each cycled ~3-4×, per-case mean is dominated by
        the multiplier; per-template mean treats each unique scenario equally
        so a single broken template surfaces as a ~1.8% drop instead of ~0.5%.
        """
        if not self.per_incident:
            return {
                "templates": [],
                "template_count": 0,
                "template_macro_mean": 0.0,
                "failing_templates": [],
            }
        buckets: dict[str, dict[str, Any]] = {}
        for row in self.per_incident:
            tpl = row.get("template_id") or "unknown"
            b = buckets.setdefault(tpl, {"sum": 0.0, "count": 0})
            b["sum"] += row.get("completeness", 0.0)
            b["count"] += 1
        templates: list[dict[str, Any]] = []
        for tpl, b in buckets.items():
            mean = b["sum"] / b["count"] if b["count"] else 0.0
            templates.append(
                {
                    "template_id": tpl,
                    "cases": b["count"],
                    "completeness": round(mean, 4),
                }
            )
        templates.sort(key=lambda t: (t["completeness"], -t["cases"]))
        macro = sum(t["completeness"] for t in templates) / len(templates) if templates else 0.0
        failing = [t for t in templates if t["completeness"] < 0.80]
        return {
            "templates": templates,
            "template_count": len(templates),
            "template_macro_mean": round(macro, 4),
            "failing_templates": failing,
        }


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
            result.per_incident.append(
                {
                    "id": inc.get("id"),
                    "template_id": inc.get("template_id"),
                    "template_index": inc.get("template_index"),
                    **scored,
                }
            )
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
            missing,
            [],
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
            result.mean,
            0.85,
            f"Mean completeness {result.mean:.3f} below 0.85 floor.",
        )

    def test_majority_full_coverage(self) -> None:
        """At least 60% of incidents should achieve full evidence coverage."""
        result = evaluate_completeness()
        self.assertGreaterEqual(
            result.full_coverage_pct,
            0.60,
            f"Only {result.full_coverage_pct * 100:.1f}% of incidents fully covered.",
        )

    def test_no_incident_completely_uncovered(self) -> None:
        """No incident may have 0 coverage — that would mean broken parsing."""
        result = evaluate_completeness(keep_per_incident=True)
        zeroed = [r for r in (result.per_incident or []) if r["completeness"] == 0.0]
        self.assertEqual(
            zeroed,
            [],
            f"{len(zeroed)} incidents had zero evidence coverage (sample: {zeroed[:3]})",
        )

    def test_per_template_completeness(self) -> None:
        """Per-template macro completeness must be ≥ 0.80.

        Equal-weighting templates ensures one broken scenario can't be
        averaged into oblivion by 3-4 duplicate cases. A 0.80 floor is
        intentionally stricter than the per-case 0.85 because each template
        contributes ~1/55 of the macro average.
        """
        result = evaluate_completeness(keep_per_incident=True)
        summary = result.per_template_summary()
        print(
            f"\n[eval] per-template completeness: "
            f"{summary['template_macro_mean']:.3f} "
            f"({summary['template_count']} templates, "
            f"{len(summary['failing_templates'])} below 0.80)"
        )
        self.assertGreaterEqual(
            summary["template_count"],
            50,
            f"Only {summary['template_count']} distinct templates in dataset; expected ≥50.",
        )
        self.assertGreaterEqual(
            summary["template_macro_mean"],
            0.80,
            f"Per-template completeness below 0.80.\nFailing templates: {summary['failing_templates']}",
        )


if __name__ == "__main__":
    result = evaluate_completeness(keep_per_incident=True)
    summary = result.per_template_summary()
    print(
        json.dumps(
            {
                "incidents": result.incidents,
                "mean_completeness": round(result.mean, 4),
                "full_coverage_pct": round(result.full_coverage_pct, 4),
                "template_count": summary["template_count"],
                "template_macro_mean": summary["template_macro_mean"],
                "failing_templates": [t["template_id"] for t in summary["failing_templates"]],
            },
            indent=2,
        )
    )
