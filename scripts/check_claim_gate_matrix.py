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

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "docs" / "audit" / "CLAIM_TO_GATE_MATRIX.md"

# Ratchet baseline: the number of NO GATE rows allowed. Lower this as phases
# close gaps; never raise it. Phase 1 closed injection / non-Postgres isolation
# / no-exfiltration; Phase 2 closed insecure-defaults + secret/IaC scanning;
# Phase 10 moved connector "live Test connection" off NO GATE; Phase 11 moved
# OpenAPI breaking-change semantics to GATED. The last NO GATE row (wet-eval
# live-agent scoreboard tables) closes in Phase 4c (needs a budgeted live run).
MAX_NO_GATE = 1


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print", dest="print_only", action="store_true")
    parser.add_argument("--max-no-gate", type=int, default=MAX_NO_GATE)
    args = parser.parse_args()

    if not MATRIX.exists():
        print(f"ERROR: {MATRIX} not found", file=sys.stderr)
        return 1

    try:
        statuses = _parse_status_rows(MATRIX.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if not statuses:
        print("ERROR: no claim rows parsed from the matrix", file=sys.stderr)
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
