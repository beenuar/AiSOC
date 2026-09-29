#!/usr/bin/env python3
"""The live agent's groundedness has a floor, and the floor came from runs.

Why this exists
---------------

``services/agents/app/confidence/groundedness.py`` measures what fraction of
the concrete indicators an agent asserts — IPs, hashes, CVEs, MITRE
techniques, domains — actually appear in the evidence it was handed.
``fused_alert_consumer`` uses it in production to refuse to auto-close on
reasoning the evidence does not support. Two things were already gated on
every PR: that the scorer works, and that the worker demotes an ungrounded
verdict. Neither says anything about *the live agent's own output*, because a
hand-written string proves the scorer and only a real model's text proves the
agent.

``live-agent-eval.yml`` dispatches the real four-agent pipeline against a
locally-served model and scores exactly that. This gate is the assertion on
its result.

Why the floor is where it is
----------------------------

The number is not chosen, it is read out of ``FLOOR_FILE``, which records the
runs it came from: the model, how many incidents each run dispatched, every
observed mean, and where those runs happened. A floor invented before the
distribution existed would be a number nobody measured, which is the whole
reason the two claim-matrix rows waiting on it stayed PARTIAL rather than
being closed with a plausible-looking constant.

What this refuses
-----------------

``substrate``
    A report tagged anything other than ``mode: live``. The harness degrades
    to deterministic substrate numbers when the agent stack is unreachable,
    and asserting a floor against those would certify a model that was never
    called. ``--wet-require-live`` should have failed the run first; this is
    the second lock on the same door.

``unmeasured``
    ``groundedness.measured`` false, or fewer incidents scored than the floor
    was derived over. A mean of one incident is not the same measurement as a
    mean of twenty, and comparing them to the same floor would quietly change
    what the gate asserts.

``wrong model``
    A report from a model the floor was not derived against. Groundedness is
    a property of the model's output; a floor measured on one model says
    nothing about another. Pass ``--allow-model`` to grade a new model
    deliberately, which prints the comparison rather than hiding it.

``below the floor``
    The thing the gate is for.

Usage
-----
::

    python3 scripts/check_live_agent_floor.py --report live-agent-eval.wet.json
    python3 scripts/check_live_agent_floor.py --show
    python3 scripts/check_live_agent_floor.py --self-test

Exit codes: 0 clean, 1 findings, 2 the check itself could not run.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

#: Where the floor and its provenance live. A committed file rather than a
#: constant in this module, so the number and the runs behind it cannot be
#: edited apart.
FLOOR_REL = Path("services") / "agents" / "tests" / "eval_data" / "live_agent_floor.json"

REQUIRED_KEYS = ("axis", "model", "served_by", "incidents", "floor_mean", "observations", "derivation")


def load_floor(path: Path) -> dict[str, Any]:
    """Read the floor declaration, refusing one that does not carry its evidence."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    missing = [key for key in REQUIRED_KEYS if key not in doc]
    if missing:
        raise ValueError(f"{FLOOR_REL} is missing {', '.join(missing)} — a floor without its provenance is a number nobody can check")
    observations = doc.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError(f"{FLOOR_REL} records no observations — the floor must be derived from runs, not chosen")
    for index, entry in enumerate(observations):
        if not isinstance(entry, dict) or "mean" not in entry or "where" not in entry or "incidents" not in entry:
            raise ValueError(f"{FLOOR_REL} observations[{index}] needs mean, incidents and where")
    floor = doc["floor_mean"]
    if not isinstance(floor, int | float):
        raise ValueError(f"{FLOOR_REL} floor_mean is not a number")
    lowest = min(float(o["mean"]) for o in observations)
    if float(floor) > lowest:
        raise ValueError(
            f"{FLOOR_REL} declares a floor of {floor} above the lowest run it was derived from ({lowest}) — that floor is already failing"
        )
    return doc


def check(report: dict[str, Any], floor_doc: dict[str, Any], *, allow_model: bool) -> list[str]:
    """Return the reasons this report does not clear the floor. Empty means clear."""
    problems: list[str] = []

    mode = str(report.get("mode") or "")
    if mode != "live":
        problems.append(
            f"the report is tagged mode={mode!r}, not 'live'. The harness degrades to deterministic "
            "substrate numbers when the agent is unreachable, and a floor asserted against those would "
            "certify a model that was never called."
        )
        # Everything below reads numbers whose provenance has just been
        # rejected, so there is nothing further worth saying about them.
        return problems

    grounded = report.get("groundedness")
    if not isinstance(grounded, dict) or not grounded.get("measured"):
        note = (
            (grounded or {}).get("note", "no groundedness block in the report")
            if isinstance(grounded, dict)
            else "no groundedness block in the report"
        )
        problems.append(f"groundedness was not measured: {note}")
        return problems

    # A run where every agent caught its provider error and used its
    # deterministic path produces a report tagged `live`, at a tenth of a
    # second per investigation, with a flattering groundedness that no model
    # wrote. `--wet-require-live` refuses that at source; this refuses it
    # again here, because the report is the artefact a reader keeps.
    if "llm_calls_placed" in grounded and int(grounded.get("llm_calls_placed") or 0) <= 0:
        problems.append(
            "the report records zero LLM calls placed, so every agent used its deterministic fallback. "
            "These numbers describe the fallback, not the model."
        )
        return problems

    required_incidents = int(floor_doc["incidents"])
    scored = int(grounded.get("scored_incidents") or 0)
    if scored < required_incidents:
        problems.append(
            f"{scored} incident(s) scored, and the floor was derived over {required_incidents}. "
            "A mean over a smaller sample is a different measurement, not a cheaper one."
        )

    report_model = str(report.get("model") or "")
    floor_model = str(floor_doc["model"])
    if report_model != floor_model and not allow_model:
        problems.append(
            f"this report is from {report_model!r} and the floor was derived against {floor_model!r}. "
            "Groundedness is a property of the model's output. Pass --allow-model to grade a new model "
            "deliberately; the comparison is then printed rather than assumed."
        )

    mean = float(grounded.get("mean") or 0.0)
    floor = float(floor_doc["floor_mean"])
    if mean < floor:
        worst = ", ".join(str(o["mean"]) for o in floor_doc["observations"])
        problems.append(
            f"groundedness mean {mean:.4f} over {scored} incident(s) is below the floor of {floor:.4f}. "
            f"The floor was derived from these run means: {worst}. Either the agent, its prompts or the "
            "scorer changed — re-measure and move the floor in the same change, with the new runs recorded."
        )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assert the live agent's measured groundedness floor.")
    parser.add_argument("--report", type=Path, help="the wet-eval block written by run_evals.py --wet-out")
    parser.add_argument("--show", action="store_true", help="print the floor and the runs it came from, then exit")
    parser.add_argument("--allow-model", action="store_true", help="grade a model the floor was not derived against")
    parser.add_argument("--repo-root", type=Path, default=None)
    args = parser.parse_args(argv)

    root = args.repo_root.resolve() if args.repo_root else repo_root()
    floor_path = root / FLOOR_REL
    if not floor_path.is_file():
        print(f"ERROR: {FLOOR_REL} not found under {root} — there is no declared floor to assert", file=sys.stderr)
        return 2
    try:
        floor_doc = load_floor(floor_path)
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.show or args.report is None:
        print(f"axis      {floor_doc['axis']}")
        print(f"model     {floor_doc['model']}  ({floor_doc['served_by']})")
        print(f"slice     {floor_doc['incidents']} incidents, deterministic prefix")
        print(f"floor     {floor_doc['floor_mean']}")
        print("runs it came from:")
        for entry in floor_doc["observations"]:
            print(f"  mean={entry['mean']}  n={entry['incidents']}  {entry['where']}")
        print(f"derivation: {floor_doc['derivation']}")
        if args.report is None and not args.show:
            print("\nno --report given, so nothing was asserted", file=sys.stderr)
        return 0

    if not args.report.is_file():
        print(f"ERROR: {args.report} not found — the eval wrote no report, so there is nothing to assert on", file=sys.stderr)
        return 2
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: {args.report} is not JSON ({exc}) — the eval did not finish", file=sys.stderr)
        return 2

    problems = check(report, floor_doc, allow_model=args.allow_model)
    grounded = report.get("groundedness") or {}
    measured = (
        f"{grounded.get('mean')} over {grounded.get('scored_incidents')} incident(s) of {report.get('model')}"
        if grounded.get("measured")
        else "nothing measured"
    )

    if problems:
        print(f"live-agent-floor: {len(problems)} finding(s) — {measured}", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1

    print(f"live-agent-floor: OK — {measured}, floor {floor_doc['floor_mean']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
