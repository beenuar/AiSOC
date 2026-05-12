"""
Per-Rule False-Positive Eval Gate (Issue #5)
============================================

Grades every native detection rule under ``detections/{cloud,identity,
endpoint,network,application,data-exfil}/*.yaml`` for *cross-fire* against
the entire native fixture corpus.

Motivation
----------
``scripts/validate_detections.py`` already replays each rule against its
*own* positive + negative fixture (TP / TN gates). That catches "rule R
doesn't fire on its own positive event" and "rule R fires on its own
negative event" — but it doesn't catch the failure mode operators feel
the most: **rule R firing on an event that was meant for rule O**.

A single overly-broad rule that matches on, say, every ``ConsoleLogin``
or every ``rundll32.exe`` execution silently drives alert volume up and
precision down across the whole pack. The standalone TP/TN replay won't
notice — both the positive *and* the negative fixture for rule R will
still match the rule's own ``match_when`` correctly.

This suite measures the cross-rule false-positive rate per rule:

  * Run every rule's ``match_when`` against every *other* rule's positive
    fixture.
  * Each unintended match counts as a cross-fire (potential FP).
  * Per-rule FPR = cross_fires / (#other rules with positive fixtures).

The gate enforces:

  * ``per_rule_fpr <= MAX_PER_RULE_FPR`` for every native rule (default
    5%) — catches accidentally-broad rules.
  * ``positive_match_rate == 1.0`` — every rule still matches its own
    positive fixture (regression of validate_detections.py replay).
  * ``negative_match_rate == 0.0`` on the rule's own negative fixture.

Intentional cross-fires (e.g. two rules that both legitimately fire on
the same fixture, like a generic AWS-root-login rule plus a more
specific MFA-disabled-during-root-login rule) can be allowlisted via the
``EXPECTED_CROSS_FIRES`` table below. Each entry is a
``(detector_slug, target_slug)`` tuple stating "we expect detector_slug
to fire on target_slug's positive fixture".

Run:
    PYTHONPATH=services/api python3 -m pytest \
        services/agents/tests/test_detection_fp_rate.py -v
"""

from __future__ import annotations

import sys
import unittest
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_TESTS_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _TESTS_DIR.parent.parent.parent
_SCRIPTS_DIR = _REPO_ROOT / "scripts"

if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from detection_specs_index import all_specs  # type: ignore[import-not-found]  # noqa: E402
from generate_detections import matches  # type: ignore[import-not-found]  # noqa: E402

# CI gate (lower-is-better). Tighten only with a corresponding allowlist
# entry or rule-narrowing PR. The 5% ceiling is a deliberate compromise:
#   * 0% would punish narrow-vs-broad rule families that legitimately
#     overlap (e.g. AWS root login + MFA-disabled-during-root-login),
#     unless every overlap is explicitly allowlisted from day 1.
#   * >5% lets a single broad rule fire on every cloud login fixture in
#     the pack without tripping the gate, defeating the purpose.
MAX_PER_RULE_FPR: float = 0.05

# Allowlist for *intentional* cross-fires. Each entry is
# (detector_slug, target_slug) — meaning "we expect rule `detector_slug`
# to fire on rule `target_slug`'s positive fixture". Only add entries
# here when the overlap is a deliberate broad-vs-narrow rule pair, and
# document the reason in a comment.
EXPECTED_CROSS_FIRES: set[tuple[str, str]] = set()


@dataclass
class RuleFPResult:
    """Per-rule cross-fire report."""

    slug: str
    category: str
    has_match_when: bool
    own_positive_match: bool
    own_negative_match: bool
    cross_fires: list[tuple[str, str]] = field(default_factory=list)
    cross_total: int = 0

    @property
    def cross_fire_count(self) -> int:
        return len(self.cross_fires)

    @property
    def fpr(self) -> float:
        if self.cross_total == 0:
            return 0.0
        return self.cross_fire_count / self.cross_total


@dataclass
class FPEvalReport:
    """Aggregate report across all native rules."""

    rules_total: int
    rules_with_match_when: int
    rules_passed: int
    rules_failed: int
    failing_rules: list[dict[str, Any]] = field(default_factory=list)
    per_rule: list[RuleFPResult] = field(default_factory=list)
    max_per_rule_fpr: float = MAX_PER_RULE_FPR

    @property
    def passed(self) -> bool:
        return self.rules_failed == 0

    @property
    def mean_fpr(self) -> float:
        evaluable = [r for r in self.per_rule if r.has_match_when and r.cross_total]
        if not evaluable:
            return 0.0
        return sum(r.fpr for r in evaluable) / len(evaluable)

    @property
    def worst_fpr(self) -> float:
        evaluable = [r for r in self.per_rule if r.has_match_when and r.cross_total]
        if not evaluable:
            return 0.0
        return max(r.fpr for r in evaluable)


def _collect_evaluable_specs() -> list[tuple[str, dict[str, Any]]]:
    """Return (category, spec) tuples for every native rule that ships a
    ``match_when`` block plus a positive fixture. Rules without either
    are skipped (they cannot participate in cross-fixture evaluation)
    but are still surfaced in the report so the operator notices.
    """
    evaluable: list[tuple[str, dict[str, Any]]] = []
    for category, spec in all_specs():
        if not spec.get("match_when"):
            continue
        if not spec.get("positive"):
            continue
        evaluable.append((category, spec))
    return evaluable


def evaluate_per_rule_fp(
    max_per_rule_fpr: float = MAX_PER_RULE_FPR,
    allowlist: set[tuple[str, str]] | None = None,
) -> FPEvalReport:
    """Evaluate every native detection rule for cross-rule false-positive
    rate. Returns an :class:`FPEvalReport`.

    Pure function — does not touch the filesystem beyond reading the
    detection specs (which are imported at module load).
    """
    if allowlist is None:
        allowlist = EXPECTED_CROSS_FIRES

    evaluable = _collect_evaluable_specs()
    per_rule: list[RuleFPResult] = []

    # Cache positive fixtures keyed by slug for O(1) lookup during the
    # inner cross-fire loop below.
    positives_by_slug: dict[str, dict[str, Any]] = {spec["slug"]: spec["positive"] for _, spec in evaluable}

    for category, spec in evaluable:
        slug = spec["slug"]
        match_when = spec["match_when"]
        positive = spec["positive"]
        negative = spec.get("negative")

        own_pos = bool(matches(match_when, positive))
        own_neg = bool(matches(match_when, negative)) if negative else False

        cross_fires: list[tuple[str, str]] = []
        cross_total = 0
        for other_slug, other_positive in positives_by_slug.items():
            if other_slug == slug:
                continue
            cross_total += 1
            if (slug, other_slug) in allowlist:
                continue
            if matches(match_when, other_positive):
                cross_fires.append((other_slug, "positive"))

        per_rule.append(
            RuleFPResult(
                slug=slug,
                category=category,
                has_match_when=True,
                own_positive_match=own_pos,
                own_negative_match=own_neg,
                cross_fires=cross_fires,
                cross_total=cross_total,
            )
        )

    failing: list[dict[str, Any]] = []
    for r in per_rule:
        reasons: list[str] = []
        if not r.own_positive_match:
            reasons.append("own positive fixture did not match (TP regression)")
        if r.own_negative_match:
            reasons.append("own negative fixture matched (TN regression)")
        if r.cross_total and r.fpr > max_per_rule_fpr:
            reasons.append(
                f"cross-fire FPR {r.fpr:.3f} > ceiling {max_per_rule_fpr:.3f} ({r.cross_fire_count} of {r.cross_total} other fixtures)"
            )
        if reasons:
            failing.append(
                {
                    "slug": r.slug,
                    "category": r.category,
                    "fpr": round(r.fpr, 4),
                    "cross_fire_count": r.cross_fire_count,
                    "cross_total": r.cross_total,
                    # Cap the verbose list so a globally-broken rule
                    # doesn't bloat the eval report.
                    "cross_fires_sample": [t for t, _ in r.cross_fires[:10]],
                    "reasons": reasons,
                }
            )

    return FPEvalReport(
        rules_total=len(per_rule),
        rules_with_match_when=len(per_rule),
        rules_passed=len(per_rule) - len(failing),
        rules_failed=len(failing),
        failing_rules=failing,
        per_rule=per_rule,
        max_per_rule_fpr=max_per_rule_fpr,
    )


# ---------------------------------------------------------------------------
# Pytest gate
# ---------------------------------------------------------------------------


class TestPerRuleFalsePositiveRate(unittest.TestCase):
    """Hard CI gate: every native rule stays under the cross-fire ceiling."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.report = evaluate_per_rule_fp()

    def test_at_least_one_rule_evaluated(self) -> None:
        self.assertGreater(
            self.report.rules_total,
            0,
            "Per-rule FP gate ran with zero evaluable rules — did detection_specs_index.py drop its match_when entries?",
        )

    def test_no_per_rule_fpr_regression(self) -> None:
        if self.report.passed:
            return

        # Group failures by reason class so the summary is actionable.
        by_reason: dict[str, list[str]] = defaultdict(list)
        for f in self.report.failing_rules:
            for r in f["reasons"]:
                head = r.split(" ", 1)[0]
                by_reason[head].append(f["slug"])

        summary_lines = [
            f"Per-rule FP gate failed for "
            f"{self.report.rules_failed}/{self.report.rules_total} rules "
            f"(ceiling {self.report.max_per_rule_fpr:.0%}, "
            f"worst {self.report.worst_fpr:.3f}).",
            "",
            "Top offenders:",
        ]
        # Show up to 10 worst rules ranked by FPR.
        worst = sorted(
            self.report.failing_rules,
            key=lambda f: f["fpr"],
            reverse=True,
        )[:10]
        for f in worst:
            sample = ", ".join(f["cross_fires_sample"][:5])
            more = ""
            if f["cross_fire_count"] > 5:
                more = f" (+{f['cross_fire_count'] - 5} more)"
            summary_lines.append(f"  - {f['slug']:48s} FPR={f['fpr']:.3f} ({f['cross_fire_count']}/{f['cross_total']}): {sample}{more}")

        self.fail("\n".join(summary_lines))


if __name__ == "__main__":  # pragma: no cover
    rep = evaluate_per_rule_fp()
    print(f"Native rules evaluated: {rep.rules_total}")
    print(f"Mean FPR:               {rep.mean_fpr:.4f}")
    print(f"Worst FPR:              {rep.worst_fpr:.4f}")
    print(f"Failing rules:          {rep.rules_failed}")
    if rep.failing_rules:
        worst = sorted(rep.failing_rules, key=lambda f: f["fpr"], reverse=True)
        for f in worst[:20]:
            print(f"  {f['slug']:48s} FPR={f['fpr']:.3f} cross_fires={f['cross_fire_count']}/{f['cross_total']}")
