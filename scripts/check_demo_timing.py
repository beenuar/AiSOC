#!/usr/bin/env python3
"""The demo stack has a bound on how long it may take to become usable (3.5+).

`packages/aisoc-sandbox` has a cold-start gate and the devcontainer has one.
The demo stack — the thing `make demo` seeds and `pnpm aisoc:demo` starts, and
the thing a first-time reader actually meets — had neither a Playwright run
against it nor any bound on how long it takes, so it could get slower
indefinitely with nobody noticing.

Where the number comes from
---------------------------
Not from a round figure somebody liked. `docs/perf/demo-timing.json` records
every run the ceiling was derived from, with the hardware and the method, and
this gate refuses to read a declaration that does not carry them — the same
structure `scripts/check_live_agent_floor.py` uses, for the same reason: a
bound invented before the distribution existed is a number nobody can check.

It differs from that floor in one way worth stating. A groundedness floor is
set just under the worst run, because the measurement is stable across
machines to within a few points. Wall clock is not: a shared GitHub runner is
not a warm laptop. So the ceiling follows the *other* precedent in this
repository — `perf.yml`'s floors, which sit orders of magnitude off the
measurement on the recorded reasoning that "a gate tuned close to a
measurement gets disabled the first week it flaps". This fires on a demo
stack that takes minutes instead of seconds, not on scheduling jitter.

What it refuses
---------------
A ceiling below the worst observation it cites, because that ceiling is
already failing. A declaration with no observations. A measurement file with
no `not_a_production_slo` marker, so a wall-clock ceiling cannot quietly be
read as a service level objective. And a run whose measured value is absent
rather than zero — an unmeasured startup must never render as instant.

Usage
-----

::

    python3 scripts/check_demo_timing.py --record results.json   # grade a run
    python3 scripts/check_demo_timing.py                         # validate the declaration
    python3 scripts/check_demo_timing.py --self-test

Exit codes: 0 clean, 1 over budget or a stale declaration, 2 could not run.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

DECLARATION = Path("docs") / "perf" / "demo-timing.json"

#: Phases that are not stack startup. The showcase lookup in particular is a
#: 60-second timeout today, and averaging a timeout into a startup figure
#: would publish a number that describes a bug rather than the stack.
EXCLUDED_PHASES = ("showcase", "browser")

REQUIRED_KEYS = ("metric", "harness", "ceiling_ms", "ceiling_derivation", "observations", "not_a_production_slo")


def load_declaration(root: Path) -> dict:
    path = root / DECLARATION
    if not path.exists():
        raise FileNotFoundError(f"{DECLARATION} is missing — there is no recorded measurement to grade against")
    doc = json.loads(path.read_text(encoding="utf-8"))

    missing = [key for key in REQUIRED_KEYS if key not in doc]
    if missing:
        raise ValueError(f"{DECLARATION} is missing {', '.join(missing)} — a ceiling without its provenance is a number nobody can check")
    if doc.get("not_a_production_slo") is not True:
        raise ValueError(f"{DECLARATION} must mark not_a_production_slo — a wall-clock ceiling read as an SLO is a claim nobody measured")

    observations = doc["observations"]
    if not isinstance(observations, list) or not observations:
        raise ValueError(f"{DECLARATION} records no observations — the ceiling must be derived from runs, not chosen")
    for index, entry in enumerate(observations):
        if not isinstance(entry, dict) or "total_to_usable_ms" not in entry or "where" not in entry:
            raise ValueError(f"{DECLARATION} observations[{index}] needs total_to_usable_ms and where")

    ceiling = doc["ceiling_ms"]
    if not isinstance(ceiling, int | float) or ceiling <= 0:
        raise ValueError(f"{DECLARATION} ceiling_ms is not a positive number")
    worst = max(float(o["total_to_usable_ms"]) for o in observations)
    if float(ceiling) < worst:
        raise ValueError(
            f"{DECLARATION} declares a ceiling of {ceiling} ms below the worst run it was "
            f"derived from ({worst} ms) — that ceiling is already failing"
        )
    return doc


def time_to_usable_ms(report: dict) -> float:
    """Sum the phases that are stack startup, from an aisoc-demo results file."""
    phases = report.get("phases")
    if not isinstance(phases, list) or not phases:
        raise ValueError("the results file records no phases; there is nothing to measure")
    total = 0.0
    counted = 0
    for phase in phases:
        name = str(phase.get("name", "")).lower()
        if any(token in name for token in EXCLUDED_PHASES):
            continue
        duration = phase.get("durationMs")
        if duration is None:
            # Absent, not zero. A phase that did not record its duration must
            # not contribute an instant one.
            raise ValueError(f"phase {phase.get('name')!r} recorded no durationMs — that is not measured, and must not be summed as 0")
        total += float(duration)
        counted += 1
    if counted == 0:
        raise ValueError("every phase was excluded; a clean verdict here would describe a run the gate never measured")
    return total


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bound how long the demo stack takes to become usable.")
    parser.add_argument("--record", type=Path, default=None, help="an aisoc-demo --results-file JSON to grade")
    parser.add_argument("--self-test", action="store_true", help="prove the gate fails closed and still detects each violation")
    parser.add_argument("--repo-root", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test_main(Path(__file__).name, [], extra=_injected_cases())

    root = (args.repo_root or repo_root()).resolve()
    try:
        doc = load_declaration(root)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}")
        return 2

    ceiling = float(doc["ceiling_ms"])
    worst = max(float(o["total_to_usable_ms"]) for o in doc["observations"])
    print(f"declaration: {DECLARATION}")
    print(f"  ceiling {ceiling:.0f} ms, derived from {len(doc['observations'])} run(s), worst {worst:.0f} ms")
    for defect in doc.get("known_open_defects", []):
        print(f"  open defect recorded alongside this number: {defect[:160]}…")

    if args.record is None:
        print("\nOK: the declaration carries its provenance. Pass --record to grade a run against it.")
        return 0

    try:
        measured = time_to_usable_ms(json.loads(args.record.read_text(encoding="utf-8")))
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}")
        return 2

    print(f"\nmeasured: {measured:.0f} ms to a usable demo stack")
    if measured > ceiling:
        print(f"\nFAIL: the demo stack took {measured:.0f} ms, over the {ceiling:.0f} ms ceiling.")
        print("  This is a regression ceiling, not an SLO — it is three times the worst run recorded, so")
        print(f"  exceeding it means something structural changed. Update {DECLARATION} with fresh runs only if")
        print("  the new cost is understood and intended.")
        return 1
    print(f"\nOK: under the {ceiling:.0f} ms ceiling with {ceiling - measured:.0f} ms of headroom")
    return 0


# ─── Self-test ───────────────────────────────────────────────────────────────

_GOOD_DOC = {
    "metric": "m",
    "harness": "h",
    "ceiling_ms": 300,
    "ceiling_derivation": "three times the worst run",
    "not_a_production_slo": True,
    "observations": [{"total_to_usable_ms": 100, "where": "local"}],
}


def _write(tmp: Path, doc: object, name: str = "decl.json") -> Path:
    tmp.mkdir(parents=True, exist_ok=True)
    path = tmp / name
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def _grade(doc: object, report: object | None, tmp: Path) -> int:
    root = tmp / "root"
    (root / DECLARATION.parent).mkdir(parents=True, exist_ok=True)
    (root / DECLARATION).write_text(json.dumps(doc), encoding="utf-8")
    argv = ["--repo-root", str(root)]
    if report is not None:
        argv += ["--record", str(_write(tmp, report, "run.json"))]
    with contextlib.redirect_stdout(io.StringIO()):
        return main(argv)


def _injected_cases() -> list[tuple[str, bool]]:
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="aisoc-demo-timing-"))
    fast = {"phases": [{"name": "Starting stack", "durationMs": 120}]}
    slow = {"phases": [{"name": "Starting stack", "durationMs": 9999}]}
    with_showcase = {"phases": [{"name": "Starting stack", "durationMs": 120}, {"name": "Locating the showcase case", "durationMs": 60000}]}
    absent = {"phases": [{"name": "Starting stack"}]}

    return [
        ("a run under the ceiling passes", _grade(_GOOD_DOC, fast, tmp / "a") == 0),
        ("a run over the ceiling fails", _grade(_GOOD_DOC, slow, tmp / "b") == 1),
        (
            "the showcase timeout is excluded rather than averaged into startup",
            _grade(_GOOD_DOC, with_showcase, tmp / "c") == 0,
        ),
        (
            "a phase with no recorded duration is refused, not summed as zero",
            _grade(_GOOD_DOC, absent, tmp / "d") == 2,
        ),
        (
            "a ceiling below the worst run it cites is refused as already failing",
            _grade({**_GOOD_DOC, "ceiling_ms": 50}, fast, tmp / "e") == 2,
        ),
        (
            "a declaration with no observations is refused",
            _grade({**_GOOD_DOC, "observations": []}, fast, tmp / "f") == 2,
        ),
        (
            "a declaration missing its derivation is refused",
            _grade({k: v for k, v in _GOOD_DOC.items() if k != "ceiling_derivation"}, fast, tmp / "g") == 2,
        ),
        (
            "a ceiling not marked as a non-SLO is refused",
            _grade({**_GOOD_DOC, "not_a_production_slo": False}, fast, tmp / "h") == 2,
        ),
        (
            "a results file with no phases is refused rather than called instant",
            _grade(_GOOD_DOC, {"phases": []}, tmp / "i") == 2,
        ),
        (
            "validating the declaration alone passes without grading a run",
            _grade(_GOOD_DOC, None, tmp / "j") == 0,
        ),
    ]


if __name__ == "__main__":
    raise SystemExit(main())
