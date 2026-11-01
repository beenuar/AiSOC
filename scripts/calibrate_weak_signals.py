#!/usr/bin/env python3
"""Calibrate the item 2.3 weak-signal threshold and publish its denominators.

The plan asks for the threshold to be "calibrated on the verdict corpus plus
new benign twins" and for "recall and the false-positive count at the chosen
threshold" to be published. This is that calibration, run over the balanced
verdict corpus — 36 strictly one-to-one twin pairs sharing their severity, so
severity alone separates nothing and a constant answer scores at most 0.500.

Two properties the corpus has that matter here:

* The twins' **identical severity distribution** is what stops the
  calibration rewarding a threshold that has merely learned "high severity
  means malicious".
* Item ids encode the label in their `-B` / `-M` suffix, so the id is never
  read. Only the envelope fields the aggregator would see in production are
  passed in.

Output is `docs/detections/weak-signal-calibration.json`: recall, the
false-positive count, both denominators, and the threshold sweep that
produced the choice. Every figure carries the count of items it was computed
over, because a rate without its denominator is not a measurement.

Usage:
    python3 scripts/calibrate_weak_signals.py
    python3 scripts/calibrate_weak_signals.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
OUT = ROOT / "docs" / "detections" / "weak-signal-calibration.json"
CORPUS_DIR = ROOT / "services" / "agents" / "tests" / "eval_data" / "verdict"

#: Dispositions that mean the item describes real malicious activity. The
#: corpus's four-term vocabulary splits benign two ways, and conflating them
#: would move the denominator without moving the measurement.
MALICIOUS = frozenset({"true_positive"})
BENIGN = frozenset({"benign", "false_positive", "benign_true_positive"})


def _load_corpus() -> list[dict[str, Any]]:
    """The 72 labelled items.

    They live under `decisions`, not `items` — `items` is the *count*, 72,
    and reading it as the list is how a first pass here found zero labelled
    records and would have published an UNMEASURED artefact over a corpus
    that is right there.
    """
    path = CORPUS_DIR / "verdict_corpus_v1.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return []
    decisions = data.get("decisions") if isinstance(data, dict) else None
    return [d for d in decisions or [] if isinstance(d, dict)]


def _envelope(item: dict[str, Any]) -> dict[str, Any]:
    """The fields the aggregator would see, with the label kept out.

    The corpus id carries the answer in its suffix, so nothing derived from
    it reaches the extractor. Only the alert envelope is passed.
    """
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    # `decisive_evidence` is the analyst's stated reason for the verdict and
    # is held out from the model by the corpus's own contract; the id
    # encodes the label in its -B / -M suffix. Neither reaches the
    # extractor. What does is the vendor evidence an alert would carry.
    envelope: dict[str, Any] = dict(evidence)
    for key in ("severity", "vendor", "title"):
        if key in item:
            envelope.setdefault(key, item[key])
    return envelope


def calibrate() -> dict[str, Any]:
    sys.path.insert(0, str(ROOT / "services" / "fusion"))
    from app.services.weak_signals import SIGNAL_WEIGHTS, extract_signals  # noqa: PLC0415

    items = _load_corpus()
    malicious = [i for i in items if str(i.get("expected_disposition", "")) in MALICIOUS]
    benign = [i for i in items if str(i.get("expected_disposition", "")) in BENIGN]

    if not malicious or not benign:
        return {
            "measured": False,
            "reason": (
                "UNMEASURED — the verdict corpus was not found, or carries no "
                "`expected_disposition`, so there is no labelled set to calibrate against. "
                f"{len(items)} items loaded, {len(malicious)} malicious, {len(benign)} benign. "
                "The shipped threshold is the module default and has not been measured."
            ),
            "corpus_items": len(items),
            "return_to_measured": (
                "A labelled corpus under services/agents/tests/eval_data/verdict carrying "
                "expected_disposition. Re-run scripts/calibrate_weak_signals.py."
            ),
        }

    def strength(item: dict[str, Any]) -> float:
        by_kind: dict[str, int] = {}
        for signal in extract_signals(_envelope(item), now=0.0):
            by_kind[signal.kind] = by_kind.get(signal.kind, 0) + 1
        return sum(SIGNAL_WEIGHTS.get(k, 0.0) * (1.0 + 0.1 * min(c - 1, 3)) for k, c in by_kind.items())

    malicious_strengths = [strength(i) for i in malicious]
    benign_strengths = [strength(i) for i in benign]

    if not any(malicious_strengths) and not any(benign_strengths):
        # Every item scored zero. That is not "the aggregator detects
        # nothing" — it is "this corpus carries none of the aggregator's
        # inputs", and publishing a sweep of 0.0000 recall would state the
        # first while having measured the second. A reader would conclude
        # the mechanism was graded and failed.
        return {
            "measured": False,
            "reason": (
                "UNMEASURED — the verdict corpus carries vendor alert *evidence* (eventName, "
                "mfaAuthenticated, sourceIPAddress), not the enriched event the aggregator reads. "
                "Every weak signal it scores is produced by fusion at evaluate time — the "
                "first-seen novelty booleans, the item 1.6 ip_class, the baseline deviation "
                "scores, the IdP risk verdict — and none of them exists in a static corpus. All "
                f"{len(malicious)} malicious and {len(benign)} benign items scored 0.0, so there "
                "is no distribution to pick a threshold from and the shipped value is the "
                "module default."
            ),
            "malicious_items": len(malicious),
            "benign_items": len(benign),
            "return_to_measured": (
                "A corpus of events replayed through fusion's enrichment — first-seen, baselines "
                "and ip_class — so the signals exist to be counted. The replay harness under "
                "services/fusion/tests can produce one; re-run scripts/calibrate_weak_signals.py."
            ),
        }

    sweep = []
    for step in range(0, 61):
        threshold = step / 10.0
        fired_malicious = sum(1 for s in malicious_strengths if s >= threshold)
        fired_benign = sum(1 for s in benign_strengths if s >= threshold)
        sweep.append(
            {
                "threshold": threshold,
                "recall": round(fired_malicious / len(malicious), 4),
                "malicious_fired": fired_malicious,
                "malicious_total": len(malicious),
                "false_positives": fired_benign,
                "benign_total": len(benign),
            }
        )

    return {
        "measured": True,
        "corpus": str(CORPUS_DIR.relative_to(ROOT)),
        "malicious_items": len(malicious),
        "benign_items": len(benign),
        "note": (
            "Every row carries both denominators. A recall without the count it was computed "
            "over is not a measurement, and the benign half is the only thing that gives a "
            "false-positive count a denominator at all."
        ),
        "sweep": sweep,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the published artefact is stale")
    args = parser.parse_args()

    payload = json.dumps(calibrate(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if not OUT.is_file():
            print(f"ERROR: {OUT.relative_to(ROOT)} missing — run scripts/calibrate_weak_signals.py", file=sys.stderr)
            return 1
        if OUT.read_text(encoding="utf-8") != payload:
            print(f"ERROR: {OUT.relative_to(ROOT)} is stale — run scripts/calibrate_weak_signals.py", file=sys.stderr)
            return 1
        print("weak-signal calibration: OK")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(payload, encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
