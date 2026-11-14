#!/usr/bin/env python3
"""Grade the ``hunts/`` corpus. A thin wrapper over the unified runner.

``hunts/README.md`` told contributors to run this script before opening a PR.
It had never existed, so the one instruction in that document a contributor
was most likely to follow failed at the shell. Gap-closure Phase 8.4.

Deliberately a wrapper rather than an implementation. ``scripts/run_evals.py``
already owns a ``hunt_corpus`` suite, with the floors CI gates on, and a
second scorer here would drift from the one the scoreboard publishes. That has
happened before in this repository: ``scripts/run_model_matrix.py`` is a thin
wrapper for the same reason, and a test asserts it defines no scoring of its
own. The same assertion covers this script.

So this adds exactly two things over ``run_evals.py --suite hunt_corpus``: a
name a contributor can guess, and output shaped for the question they are
actually asking, which is "does the hunt I just wrote fire on its positive and
stay quiet on its negative".

Usage:
    python scripts/run_hunt_evals.py                 # grade the whole corpus
    python scripts/run_hunt_evals.py --hunt hunt-x   # one hunt, with detail
    python scripts/run_hunt_evals.py --json          # machine-readable
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from pathlib import Path

from gate_toolkit import repo_root

#: Resolved through git rather than from ``__file__``. Two levels above this
#: script is whatever happens to be there, which is a different tree whenever
#: the script is copied, vendored or run from a scratch checkout.
_REPO_ROOT = repo_root()
_RUN_EVALS = _REPO_ROOT / "scripts" / "run_evals.py"


def _grade() -> dict:
    """Run the corpus suite through the runner that owns the floors."""
    sys.path.insert(0, str(_REPO_ROOT / "services" / "agents"))
    try:
        from tests.test_hunt_corpus import evaluate_hunt_corpus  # noqa: PLC0415
    except ImportError as exc:
        print(
            f"error: could not import the hunt corpus grader ({exc}).\n"
            f"Run from the repository root with the agents service's test dependencies installed:\n"
            f"  pip install pyyaml pydantic\n",
            file=sys.stderr,
        )
        raise SystemExit(2) from exc

    result = evaluate_hunt_corpus()
    return {
        "hunts": result.hunts_total,
        "positives_expected": result.positives_expected,
        "positives_caught": result.positives_caught,
        "positive_rate": round(result.positive_rate, 4),
        "negatives_expected": result.negatives_expected,
        "false_positives": result.false_positives,
        "false_positive_rate": round(result.false_positive_rate, 4),
        "misses": result.misses,
        "false_positive_details": result.false_positive_details,
        "orphan_incident_ids": result.orphan_incident_ids,
    }


def _report(data: dict, only: str | None) -> int:
    misses = [m for m in data["misses"] if only is None or m.get("hunt_id") == only]
    fps = [f for f in data["false_positive_details"] if only is None or f.get("hunt_id") == only]

    print(f"hunt corpus: {data['hunts']} hunts")
    print(f"  positives  {data['positives_caught']}/{data['positives_expected']} fired   (rate {data['positive_rate']:.3f}, floor 1.000)")
    print(
        f"  negatives  {data['false_positives']}/{data['negatives_expected']} fired   "
        f"(rate {data['false_positive_rate']:.3f}, ceiling 0.000)"
    )

    if misses:
        print("\nThese hunts did not fire on their positive scenario:")
        for miss in misses:
            reason = miss.get("reason")
            if reason == "no_matching_events":
                print(f"  - {miss['hunt_id']}: scenario {miss['scenario']} has no events in the telemetry corpus")
            else:
                print(
                    f"  - {miss['hunt_id']}: best score {miss.get('match_score')} < "
                    f"{miss.get('threshold')} over {miss.get('events_scanned')} event(s)"
                )

    if fps:
        print("\nThese hunts fired on their negative scenario:")
        for fp in fps:
            print(f"  - {fp['hunt_id']}: {fp['findings']} finding(s) on {fp['scenario']} (score {fp.get('match_score')})")

    if data["orphan_incident_ids"]:
        print("\nTelemetry left behind by a renamed or deleted hunt:")
        for orphan in data["orphan_incident_ids"]:
            print(f"  - {orphan}")

    ok = not misses and not fps and not data["orphan_incident_ids"]
    if only is not None and not ok:
        print(f"\n{only}: FAILED")
        return 1
    if ok:
        print("\nOK. Every hunt fires on its positive scenario and none fire on their negative.")
        print("Run scripts/check_hunt_scenarios.py as well: it checks that each negative inverts")
        print("the clause its hunt is about, which this grading cannot tell on its own.")
        return 0
    print("\nFAILED.")
    return 1


def _self_test() -> int:
    """Assert this script defines no scoring of its own.

    The failure mode a wrapper exists to prevent is becoming a second
    implementation, at which point two numbers describe the same corpus and
    disagree. Read from this file's own source rather than asserted in prose.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    ok = True

    imported: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.add(node.module or "")
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)

    delegates = "evaluate_hunt_corpus" in imported
    print(f"  {'PASS' if delegates else 'FAIL'}  delegates to the corpus grader run_evals.py uses")
    ok &= delegates

    # A scorer would need the matcher and the corpus loader. Checked as
    # *imports* rather than as substrings: the first version of this test
    # searched the file text and failed on the names inside its own assertion
    # message, which is a small instance of the thing it is checking for.
    scoring_names = {"HuntEngine", "HuntCorpus", "HuntDefinition", "_indicator_matches"}
    scoring_modules = {m for m in modules if "hunt.engine" in m or "hunt.loader" in m}
    cannot_score = not (imported & scoring_names) and not scoring_modules
    print(f"  {'PASS' if cannot_score else 'FAIL'}  imports neither the hunt engine nor the loader, so it cannot score")
    ok &= cannot_score

    runner_exists = _RUN_EVALS.exists()
    print(f"  {'PASS' if runner_exists else 'FAIL'}  the runner it defers to exists at scripts/run_evals.py")
    ok &= runner_exists

    print()
    print(f"run_hunt_evals.py: self-test {'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grade the hunts/ corpus against its synthetic scenarios.")
    parser.add_argument("--hunt", help="Report on one hunt id only, for instance hunt-lolbin-rundll32-network.")
    parser.add_argument("--json", action="store_true", help="Print the raw grading result as JSON.")
    parser.add_argument("--self-test", action="store_true", help="Assert this wrapper defines no scoring of its own.")
    args = parser.parse_args(argv)

    if args.self_test:
        return _self_test()

    data = _grade()
    if args.json:
        print(json.dumps(data, indent=2))
        return 0 if data["positive_rate"] >= 1.0 and data["false_positive_rate"] <= 0.0 else 1
    return _report(data, args.hunt)


if __name__ == "__main__":
    raise SystemExit(main())
