#!/usr/bin/env python3
"""Enforce the claim-to-gate matrix (Phase 2).

`docs/audit/CLAIM_TO_GATE_MATRIX.md` maps every marketing/capability claim to
the CI job that proves it, or `NO GATE`. The Definition of Done requires zero
`NO GATE` rows. Until we get there, this gate is a **ratchet**: the number of
`NO GATE` rows may only decrease. A PR that adds a new claim without a gate
(or removes a gate) fails.

Usage:
    python3 scripts/check_claim_gate_matrix.py            # enforce ratchet
    python3 scripts/check_claim_gate_matrix.py --print    # print counts only

Exit codes: 0 ok, 1 regression (NO GATE increased) or malformed matrix.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
MATRIX = ROOT / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md"

# Ratchet baseline: the number of NO GATE rows allowed. Lower this as phases
# close gaps; never raise it. Phase 1 closed injection / non-Postgres isolation
# / no-exfiltration; Phase 2 closed insecure-defaults + secret/IaC scanning;
# Phase 10 moved connector "live Test connection" off NO GATE; Phase 11 moved
# OpenAPI breaking-change semantics to GATED. The last NO GATE row (wet-eval
# live-agent scoreboard tables) closes in Phase 4c (needs a budgeted live run).
MAX_NO_GATE = 0


def _parse_status_rows(text: str) -> list[str]:
    """Return the Status cell of every data row in the claim-to-gate table."""
    lines = text.splitlines()
    header_idx = None
    status_col = None
    for i, line in enumerate(lines):
        if line.strip().startswith("|") and "Status" in line and "Claim" in line:
            cols = [c.strip() for c in line.strip().strip("|").split("|")]
            try:
                status_col = cols.index("Status")
            except ValueError:
                continue
            header_idx = i
            break
    if header_idx is None or status_col is None:
        raise ValueError("could not locate the claim-to-gate table header (Claim ... Status)")

    statuses: list[str] = []
    # data rows start after the header separator (|---|---|...)
    for line in lines[header_idx + 2 :]:
        s = line.strip()
        if not s.startswith("|"):
            break  # table ended
        if re.match(r"^\|[\s:|-]+\|?$", s):
            continue  # separator
        cols = [c.strip() for c in s.strip("|").split("|")]
        if len(cols) <= status_col:
            continue
        statuses.append(cols[status_col])
    return statuses


#: Profiles a row may declare. A claim holds in the deployment it names, and
#: without saying which, "shipped" means nothing: most of the product used to
#: be built and dark in the `full` profile while the README read as though it
#: ran under `make up`.
VALID_PROFILES = frozenset({"core", "full"})


def _row_cells(text: str) -> list[tuple[int, list[str], dict[str, int]]]:
    """Every data row, as `(line number, cells, column index by name)`."""
    lines = text.splitlines()
    header_idx = None
    index: dict[str, int] = {}
    for i, line in enumerate(lines):
        if line.strip().startswith("|") and "Status" in line and "Claim" in line:
            cols = [c.strip() for c in line.strip().strip("|").split("|")]
            index = {name: n for n, name in enumerate(cols)}
            header_idx = i
            break
    if header_idx is None:
        return []

    out = []
    for offset, line in enumerate(lines[header_idx + 2 :], start=header_idx + 3):
        s = line.strip()
        if not s.startswith("|"):
            break
        if re.match(r"^\|[\s:|-]+\|?$", s):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        out.append((offset, cells, index))
    return out


def check_profiles(text: str) -> list[str]:
    """Every row declares a profile, and names a gate test.

    Two properties, because a row can be honest about where it holds and
    still cite nothing runnable. The second is what stops a row resting on
    prose: a `Gate` cell has to name a `.py` file or a workflow job.
    """
    problems: list[str] = []
    for line_no, cells, index in _row_cells(text):
        profile_i = index.get("Profile")
        gate_i = index.get("Gate (workflow :: job)")
        if profile_i is None:
            return ["the table has no Profile column; every row must declare core or full"]
        if len(cells) <= profile_i:
            problems.append(f"row at line {line_no} has no Profile cell")
            continue
        profile = cells[profile_i].lower()
        if profile not in VALID_PROFILES:
            claim = cells[0][:60] if cells else "?"
            problems.append(f"line {line_no}: profile {cells[profile_i]!r} is not one of {sorted(VALID_PROFILES)} ({claim})")
        if gate_i is not None and len(cells) > gate_i:
            gate = cells[gate_i]
            # A workflow filename is as good a gate reference as a test
            # path: `validate-detections.yml` names something CI runs. A
            # first version demanded `.py` or `::` and reported 23 rows
            # that cite a workflow by name, which is a defect in the rule
            # rather than in the rows.
            if not any(token in gate for token in (".py", ".yml", ".yaml", "::")):
                claim = cells[0][:60] if cells else "?"
                problems.append(f"line {line_no}: the Gate cell names no test file and no workflow job ({claim})")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print", dest="print_only", action="store_true")
    parser.add_argument("--max-no-gate", type=int, default=MAX_NO_GATE)
    args = parser.parse_args()

    if not MATRIX.exists():
        print(f"ERROR: {MATRIX} not found", file=sys.stderr)
        return 1

    text = MATRIX.read_text(encoding="utf-8")
    try:
        statuses = _parse_status_rows(text)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not statuses:
        print("ERROR: no claim rows parsed from the matrix", file=sys.stderr)
        return 1

    # Every row says which deployment it holds in, and names something
    # runnable. A claim with no profile reads as though it holds under
    # `make up`, and most of the product used to be dark in `full` while
    # the README said otherwise.
    problems = check_profiles(text)
    if problems:
        print(f"ERROR: {len(problems)} row(s) do not declare a profile or a gate:", file=sys.stderr)
        for problem in problems[:20]:
            print(f"  {problem}", file=sys.stderr)
        if len(problems) > 20:
            print(f"  ... and {len(problems) - 20} more", file=sys.stderr)
        return 1

    no_gate = sum(1 for s in statuses if "NO GATE" in s.upper())
    gated = sum(1 for s in statuses if s.upper().startswith("GATED"))
    partial = sum(1 for s in statuses if s.upper().startswith("PARTIAL"))

    print(f"claim-to-gate matrix: {len(statuses)} rows — {gated} GATED, {partial} PARTIAL, {no_gate} NO GATE")

    if args.print_only:
        return 0

    if no_gate > args.max_no_gate:
        print(
            f"ERROR: NO GATE rows increased to {no_gate} (ratchet ceiling {args.max_no_gate}). "
            "Every claim needs a CI gate — add the gate or delete the claim.",
            file=sys.stderr,
        )
        return 1

    print(f"OK: NO GATE rows ({no_gate}) within ratchet ceiling ({args.max_no_gate}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
