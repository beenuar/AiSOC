#!/usr/bin/env python3
"""SLO-coverage gate (Phase 12 — observability + governance).

Every service under `services/` must declare a reliability posture in
`docs/operations/slos.yaml` — either an `slo` block (availability + p95 latency
+ golden signals) or an `exempt` block with a reason. This gate fails when a
service is missing, so a new service cannot ship without declaring its SLO (the
same "no thing ships without an entry" pattern as the tenant-isolation
registry).

Usage:
    python3 scripts/check_slos.py            # fail on any uncovered service
    python3 scripts/check_slos.py --print     # list coverage
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SLOS = ROOT / "docs" / "operations" / "slos.yaml"
SERVICES_DIR = ROOT / "services"

_REQUIRED_SLO_FIELDS = {"availability_target", "latency_p95_ms", "golden_signals", "description"}


def _discovered_services() -> set[str]:
    return {p.name for p in SERVICES_DIR.iterdir() if p.is_dir() and not p.name.startswith(".")}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print", dest="print_only", action="store_true")
    args = parser.parse_args()

    if not SLOS.exists():
        print(f"ERROR: {SLOS.relative_to(ROOT)} not found", file=sys.stderr)
        return 1

    data = yaml.safe_load(SLOS.read_text(encoding="utf-8")) or {}
    slo_services = data.get("services") or {}
    exempt = data.get("exempt") or {}
    covered = set(slo_services) | set(exempt)
    discovered = _discovered_services()

    errors: list[str] = []

    missing = discovered - covered
    for svc in sorted(missing):
        errors.append(f"service '{svc}' has no SLO or exempt entry in {SLOS.relative_to(ROOT)}")

    stale = covered - discovered
    for svc in sorted(stale):
        errors.append(f"slos.yaml references '{svc}' which is not a directory under services/")

    for svc, block in slo_services.items():
        if not isinstance(block, dict):
            errors.append(f"SLO for '{svc}' is not a mapping")
            continue
        missing_fields = _REQUIRED_SLO_FIELDS - set(block)
        if missing_fields:
            errors.append(f"SLO for '{svc}' missing fields: {sorted(missing_fields)}")
        av = block.get("availability_target")
        if isinstance(av, (int, float)) and not (0.0 < av <= 1.0):
            errors.append(f"SLO for '{svc}': availability_target {av} not in (0, 1]")

    for svc, block in exempt.items():
        if not isinstance(block, dict) or not str(block.get("reason", "")).strip():
            errors.append(f"exempt entry '{svc}' needs a non-empty reason")

    if args.print_only:
        print(f"services discovered: {len(discovered)} | SLOs: {len(slo_services)} | exempt: {len(exempt)}")
        for svc in sorted(discovered):
            tag = "slo" if svc in slo_services else ("exempt" if svc in exempt else "MISSING")
            print(f"  {svc:<20} {tag}")

    if errors:
        print("ERROR: SLO coverage gate failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"OK: all {len(discovered)} services have an SLO or exempt entry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
