#!/usr/bin/env python3
"""
Standalone MITRE ATT&CK Accuracy Evaluation Script
====================================================
Usage:
    python scripts/eval_mitre_accuracy.py [--threshold 0.80] [--json]

Exit codes:
    0 — accuracy >= threshold (PASS)
    1 — accuracy < threshold (FAIL)

This script is also the entrypoint for the p1-eval CI step.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Allow running from repo root or scripts/ dir
_REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_REPO_ROOT / "services" / "agents"))

from tests.test_mitre_accuracy import evaluate_mitre_accuracy


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate MITRE tactic accuracy for AiSOC Pillar-1.")
    parser.add_argument("--threshold", type=float, default=0.80, help="Required accuracy (default: 0.80)")
    parser.add_argument("--json", action="store_true", help="Output JSON report to stdout")
    args = parser.parse_args()

    result = evaluate_mitre_accuracy(threshold=args.threshold)

    if args.json:
        print(result.to_json())
    else:
        print(f"\n{'='*60}")
        print(f"  AiSOC P1-Eval: MITRE ATT&CK Tactic Accuracy")
        print(f"{'='*60}")
        print(f"  Incidents evaluated : {result.total}")
        print(f"  Correctly predicted : {result.correct}")
        print(f"  Accuracy            : {result.accuracy * 100:.1f}%")
        print(f"  Threshold           : {args.threshold * 100:.0f}%")
        print(f"{'='*60}")

        # Print per-incident results
        for d in result.details:
            status = "PASS" if d["correct"] else "FAIL"
            print(
                f"  [{status}] {d['incident'][:70]}\n"
                f"      expected={d['expected']}  predicted={d['predicted']}"
                f"  overlap={d['overlap']}"
            )

        print(f"{'='*60}")
        passed = result.accuracy >= args.threshold
        verdict = "PASS" if passed else "FAIL"
        print(f"\n  {verdict}: {result.accuracy * 100:.1f}% ({'>=' if passed else '<'} {args.threshold * 100:.0f}%)")
        print()

    # Write JSON report to disk for CI artifact upload
    report_path = _REPO_ROOT / "eval_mitre_accuracy_report.json"
    report_path.write_text(result.to_json())
    if not args.json:
        print(f"  Report written to: {report_path}")

    sys.exit(0 if result.accuracy >= args.threshold else 1)


if __name__ == "__main__":
    main()
