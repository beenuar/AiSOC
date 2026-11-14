"""
Pillar-1 Evaluation: AI-vs-AI Adversary — Graceful-Degradation Gate (w2-aivai)
==============================================================================
Sixth CI-gated eval suite. Loads the deterministic adversary-mutated dataset
produced by `scripts/generate_adversary_incidents.py` and grades the same
keyword tactic extractor that powers `test_mitre_accuracy.py`.

The dataset rewrites every defender-known keyword into evasive synonyms,
character obfuscation, and fragmentation across three intensity buckets:

    heavy   ≈ 45%   every keyword swapped
    medium  ≈ 35%   one expected tactic preserved cleanly
    light   ≈ 20%   light leetspeak only (control bucket)

Two regression floors are enforced:

  * **Overall catch rate ≥ 0.40** — under heavy adversarial mutation the
    defender is expected to drop ~50pp from its 0.95 baseline. The floor
    of 0.40 keeps "graceful degradation" honest: the substrate must still
    catch a meaningful fraction, but not anywhere near the unmutated
    baseline.
  * **Light-bucket catch rate ≥ 0.85** — light-tier obfuscation is just
    leetspeak; if the defender silently fails this bucket too, then a
    heavy-tier failure is hiding a deeper regression.

Both floors are intentionally below the 0.80 floor of the unmutated
suite. The point of this suite is NOT to prove the defender is great
under adversarial pressure — it's to prove the defender doesn't fall
off a cliff and to give us a measurable graceful-degradation curve we
can watch over time.

Run:
    pytest services/agents/tests/test_adversary_eval.py -v
    # or via the public eval harness:
    python scripts/run_evals.py --out eval_report.json
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

from .test_mitre_accuracy import extract_tactics_from_text  # type: ignore

_TESTS_DIR = Path(__file__).parent
_ADVERSARY_PATH = _TESTS_DIR / "eval_data" / "adversary_incidents.json"
_BASE_PATH = _TESTS_DIR / "eval_data" / "synthetic_incidents.json"


# Regression floors. See module docstring for rationale.
_OVERALL_FLOOR = 0.40
_LIGHT_BUCKET_FLOOR = 0.85
# Heavy-tier upper bound: if the heavy bucket starts catching too much,
# either the mutation grammar has drifted off the keyword catalogue or the
# defender has silently widened its substring matches. Either way it
# means the "adversarial" dataset isn't actually adversarial anymore.
_HEAVY_BUCKET_CEILING = 0.50


class AdversaryEvalResult:
    def __init__(self) -> None:
        self.total = 0
        self.correct = 0
        self.bucket_counts: dict[str, int] = {"heavy": 0, "medium": 0, "light": 0}
        self.bucket_correct: dict[str, int] = {"heavy": 0, "medium": 0, "light": 0}
        self.lost_all_tactics = 0
        self.per_tactic_lost: dict[str, int] = {}
        self.details: list[dict[str, Any]] = []

    @property
    def accuracy(self) -> float:
        return self.correct / self.total if self.total else 0.0

    def bucket_accuracy(self, bucket: str) -> float:
        n = self.bucket_counts.get(bucket, 0)
        return (self.bucket_correct.get(bucket, 0) / n) if n else 0.0

    def to_summary(self) -> dict[str, Any]:
        return {
            "incidents": self.total,
            "correct": self.correct,
            "accuracy": round(self.accuracy, 4),
            "lost_all_tactics": self.lost_all_tactics,
            "buckets": {
                b: {
                    "incidents": self.bucket_counts[b],
                    "correct": self.bucket_correct[b],
                    "accuracy": round(self.bucket_accuracy(b), 4),
                }
                for b in ("heavy", "medium", "light")
            },
            "per_tactic_lost": dict(sorted(self.per_tactic_lost.items())),
        }


def _load_adversary_dataset() -> list[dict[str, Any]]:
    if not _ADVERSARY_PATH.exists():
        raise FileNotFoundError(
            f"Adversary dataset missing at {_ADVERSARY_PATH}. Generate with: python3 scripts/generate_adversary_incidents.py"
        )
    return json.loads(_ADVERSARY_PATH.read_text())


def evaluate_adversary_accuracy() -> AdversaryEvalResult:
    """Run the keyword tactic extractor against the mutated dataset.

    Same scoring rule as `test_mitre_accuracy.py`: a case is correct if
    the predicted tactic set overlaps the expected set by at least one
    tactic. The point is graceful-degradation, not zero-error detection.
    """
    incidents = _load_adversary_dataset()
    result = AdversaryEvalResult()

    for inc in incidents:
        result.total += 1
        bucket = inc.get("adversary_intensity", "heavy")
        result.bucket_counts[bucket] = result.bucket_counts.get(bucket, 0) + 1

        expected = set(inc.get("expected_tactics", []))
        text = f"{inc['title']}\n{inc['description']}"
        predicted = extract_tactics_from_text(text)
        overlap = predicted & expected
        correct = bool(overlap)

        if correct:
            result.correct += 1
            result.bucket_correct[bucket] = result.bucket_correct.get(bucket, 0) + 1
        else:
            result.lost_all_tactics += 1

        for t in expected - predicted:
            result.per_tactic_lost[t] = result.per_tactic_lost.get(t, 0) + 1

        result.details.append(
            {
                "incident_id": inc.get("id"),
                "template_id": inc.get("template_id"),
                "adversary_intensity": bucket,
                "expected": sorted(expected),
                "predicted": sorted(predicted),
                "overlap": sorted(overlap),
                "correct": correct,
            }
        )

    return result


# ---------------------------------------------------------------------------
# pytest tests
# ---------------------------------------------------------------------------


class TestAdversaryEval(unittest.TestCase):
    """Sixth CI suite — graceful-degradation under adversarial mutation."""

    def test_dataset_present(self) -> None:
        self.assertTrue(
            _ADVERSARY_PATH.exists(),
            f"Adversary dataset missing at {_ADVERSARY_PATH}. Run scripts/generate_adversary_incidents.py to (re)generate it.",
        )
        # The mutated set must mirror the base set 1:1 so per-template
        # diffs are meaningful.
        base = json.loads(_BASE_PATH.read_text())
        mutated = json.loads(_ADVERSARY_PATH.read_text())
        self.assertEqual(
            len(base),
            len(mutated),
            f"Adversary dataset size {len(mutated)} != base dataset size {len(base)}",
        )

    def test_dataset_is_actually_mutated(self) -> None:
        """Make sure the generator actually changed the text — not a no-op.

        Some templates legitimately contain no defender keyword the grammar
        knows about (and the light bucket only applies leetspeak), so a
        meaningful fraction of the corpus will pass through unchanged. The
        floor here just guards against the grammar collapsing to a no-op.
        """
        mutated = _load_adversary_dataset()
        unchanged = sum(
            1 for inc in mutated if inc["title"] == inc.get("original_title") and inc["description"] == inc.get("original_description")
        )
        self.assertLess(
            unchanged,
            (len(mutated) * 35) // 100,
            f"{unchanged}/{len(mutated)} incidents unchanged — mutation grammar may have regressed.",
        )

    def test_overall_graceful_degradation(self) -> None:
        result = evaluate_adversary_accuracy()
        print(
            f"\n[eval] Adversary catch rate: {result.correct}/{result.total} = "
            f"{result.accuracy * 100:.1f}% "
            f"(heavy={result.bucket_accuracy('heavy') * 100:.1f}%, "
            f"medium={result.bucket_accuracy('medium') * 100:.1f}%, "
            f"light={result.bucket_accuracy('light') * 100:.1f}%)"
        )
        self.assertGreaterEqual(
            result.accuracy,
            _OVERALL_FLOOR,
            f"Adversary catch rate {result.accuracy:.1%} below "
            f"graceful-degradation floor of {_OVERALL_FLOOR:.0%}.\n" + json.dumps(result.to_summary(), indent=2)[:4000],
        )

    def test_light_bucket_still_caught(self) -> None:
        """Light-tier obfuscation is leetspeak only — defender should pass."""
        result = evaluate_adversary_accuracy()
        light_acc = result.bucket_accuracy("light")
        self.assertGreaterEqual(
            light_acc,
            _LIGHT_BUCKET_FLOOR,
            f"Light-bucket adversary accuracy {light_acc:.1%} below "
            f"control floor of {_LIGHT_BUCKET_FLOOR:.0%}. "
            "Defender keyword extractor may have regressed.",
        )

    def test_heavy_bucket_actually_evades(self) -> None:
        """Heavy-tier mutation must actually hurt the defender.

        If heavy catches too much, the dataset isn't adversarial anymore
        — either the grammar has regressed or the defender has silently
        widened its substring matches.
        """
        result = evaluate_adversary_accuracy()
        heavy_acc = result.bucket_accuracy("heavy")
        self.assertLessEqual(
            heavy_acc,
            _HEAVY_BUCKET_CEILING,
            f"Heavy-bucket adversary accuracy {heavy_acc:.1%} above "
            f"adversariality ceiling of {_HEAVY_BUCKET_CEILING:.0%}. "
            "Mutation grammar isn't actually evading detection — "
            "synonyms may be leaking defender keywords.",
        )

    def test_bucket_distribution(self) -> None:
        """Heavy bucket must be substantial — otherwise we're not testing it."""
        result = evaluate_adversary_accuracy()
        self.assertGreater(
            result.bucket_counts["heavy"],
            result.total // 4,
            f"Heavy bucket only {result.bucket_counts['heavy']}/{result.total} — mutation distribution may have drifted.",
        )
        self.assertGreater(
            result.bucket_counts["light"],
            0,
            "Light bucket is empty — no control sample.",
        )


if __name__ == "__main__":
    unittest.main()
