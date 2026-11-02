#!/usr/bin/env python3
"""The published retro-hunt scale figures must be the ones that were measured.

Wave 2, Phase 5.5. The page at
`apps/docs/docs/benchmarks/retro-hunt-scale.md` publishes a sweep cost, a
bytes-per-row figure and — the number that matters — the lake size at which
one sweep exceeds its declared byte budget and is refused by the server.

Three ways that goes wrong, and this gate exists for all three.

**The prose drifts from the artefact.** A figure copied into a table goes
stale silently; the repository has shipped that defect often enough that
`check_alert_reduction_claims.py` exists for the same reason. So every
number in the published table is read back out of
`docs/perf/retro-hunt-scale.json`.

**The artefact loses its provenance.** A latency with no machine behind it
is not a result. The JSON must carry its hardware and the ClickHouse version
it ran against, or there is nothing to reproduce.

**The degradation point stops tracking the product.** The ceiling is derived
from `MAX_BYTES_PER_SWEEP` in `services/api/app/services/retro_hunt/sweep.py`
divided by the measured bytes-per-row. If somebody changes the budget — the
most likely future edit to that file — the published ceiling must move with
it or this build goes red. A published limit that quietly describes a budget
the product no longer has is worse than no limit at all.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PAGE = REPO_ROOT / "apps" / "docs" / "docs" / "benchmarks" / "retro-hunt-scale.md"
ARTEFACT = REPO_ROOT / "docs" / "perf" / "retro-hunt-scale.json"
SWEEP = REPO_ROOT / "services" / "api" / "app" / "services" / "retro_hunt" / "sweep.py"

_BUDGET_RE = re.compile(r"^MAX_BYTES_PER_SWEEP\s*=\s*(?P<expr>[0-9*\s]+)$", re.MULTILINE)

#: How far the page's stated ceiling may sit from the derived one, in
#: millions of rows. A tolerance rather than an equality because the page
#: rounds to one decimal place and the derivation does not.
CEILING_TOLERANCE_M = 0.2


def budget_bytes() -> int:
    """`MAX_BYTES_PER_SWEEP`, read from the module that declares it.

    Parsed rather than imported: `sweep.py` holds a ClickHouse client and a
    database session, so importing it pulls in SQLAlchemy and the settings
    object — the same reason `sql.py` was split out from it in the first
    place.
    """
    if not SWEEP.is_file():
        raise SystemExit(f"check_retro_hunt_scale_claims.py: {SWEEP.relative_to(REPO_ROOT)} is missing")
    match = _BUDGET_RE.search(SWEEP.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit("check_retro_hunt_scale_claims.py: no MAX_BYTES_PER_SWEEP in sweep.py")
    # A product of integer literals, which is how the constant is written.
    total = 1
    for part in match.group("expr").split("*"):
        total *= int(part.strip())
    return total


def violations(page_text: str, artefact: dict, budget: int) -> list[str]:
    """Every finding, rendered. Pure, so the self-test can drive it."""
    found: list[str] = []
    steps = artefact.get("steps") or []
    if not steps:
        return ["docs/perf/retro-hunt-scale.json carries no steps — nothing was measured"]

    for key, label in (("hardware", "hardware"), ("clickhouse_version", "ClickHouse version")):
        if not artefact.get(key):
            found.append(f"docs/perf/retro-hunt-scale.json carries no {label}. A latency with no machine behind it is not a result.")

    for step in steps:
        rows = int(step["lake_rows"])
        # Thousands separators, as the table renders them.
        if f"{rows:,}" not in page_text:
            found.append(f"the page does not mention the {rows:,}-row step the artefact measured")
        median = float(step["sweep_ms_median"])
        if f"{median:.2f}" not in page_text:
            found.append(f"the page does not quote {median:.2f} ms, the measured median at {rows:,} rows")

    # The claim that makes the page worth publishing.
    last = steps[-1]
    per_row = float(last["read_bytes_median"]) / float(last["lake_rows"])
    derived_m = budget / per_row / 1e6
    stated = re.search(r"approximately\s+(?P<m>[0-9.]+)\s*million rows", page_text)
    if stated is None:
        found.append(
            "the page states no degradation point. The lake size at which one sweep exceeds "
            f"MAX_BYTES_PER_SWEEP is the result; it is approximately {derived_m:.1f} million rows."
        )
    elif abs(float(stated.group("m")) - derived_m) > CEILING_TOLERANCE_M:
        found.append(
            f"the page says the budget is exceeded at {stated.group('m')}M rows; "
            f"MAX_BYTES_PER_SWEEP ({budget / 1024**3:.0f} GiB) over the measured "
            f"{per_row:.1f} bytes/row gives {derived_m:.1f}M. Re-measure, or move the page with "
            "the budget — a published limit describing a budget the product no longer has is "
            "worse than no limit."
        )

    # Extrapolation must be visible as extrapolation.
    if "extrapolat" not in page_text.lower():
        found.append(
            "the page quotes million-indicator figures without saying they are extrapolated. "
            "A literal million sequential sweeps was not run, and a reader must be able to tell."
        )
    return found


def _self_test() -> int:
    artefact = {
        "hardware": {"cpu": "test"},
        "clickhouse_version": "24.8",
        "steps": [{"lake_rows": 1_000_000, "sweep_ms_median": 11.59, "read_bytes_median": 93_660_000}],
    }
    budget = 8 * 1024 * 1024 * 1024
    derived = budget / (93_660_000 / 1_000_000) / 1e6
    good = (
        f"1,000,000 rows at 11.59 ms. Exceeds the budget at approximately {derived:.1f} million rows. "
        "The million-indicator row is extrapolated."
    )
    cases: tuple[tuple[str, str, dict, bool], ...] = (
        ("a page quoting what was measured passes", good, artefact, False),
        ("a stale median is caught", good.replace("11.59", "9.10"), artefact, True),
        ("a missing step is caught", good.replace("1,000,000", "2,000,000"), artefact, True),
        ("a stale degradation point is caught", good.replace(f"{derived:.1f}", "250.0"), artefact, True),
        ("an unlabelled extrapolation is caught", good.replace("extrapolated", "computed"), artefact, True),
        (
            "an artefact with no hardware is caught",
            good,
            {**artefact, "hardware": {}},
            True,
        ),
        ("an artefact with no steps is caught", good, {"steps": []}, True),
    )
    failures = 0
    for name, text, art, should_flag in cases:
        flagged = bool(violations(text, art, budget))
        ok = flagged == should_flag
        failures += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    print()
    if failures:
        print(f"check_retro_hunt_scale_claims.py: self-test FAILED ({failures})")
        return 1
    print("check_retro_hunt_scale_claims.py: self-test OK")
    return 0


def check() -> int:
    for path in (PAGE, ARTEFACT):
        if not path.is_file():
            print(
                f"check_retro_hunt_scale_claims.py: {path.relative_to(REPO_ROOT)} is missing — "
                "refusing to certify a measurement it never read",
                file=sys.stderr,
            )
            return 2

    budget = budget_bytes()
    artefact = json.loads(ARTEFACT.read_text(encoding="utf-8"))
    found = violations(PAGE.read_text(encoding="utf-8"), artefact, budget)

    steps = artefact.get("steps") or []
    print(
        f"retro-hunt scale: {len(steps)} measured step(s) up to "
        f"{max((int(s['lake_rows']) for s in steps), default=0):,} rows; "
        f"budget {budget / 1024**3:.0f} GiB"
    )
    if found:
        print()
        for line in found:
            print(f"  - {line}")
        return 1
    print("OK: the published retro-hunt scale figures are the ones that were measured.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    return _self_test() if args.self_test else check()


if __name__ == "__main__":
    raise SystemExit(main())
