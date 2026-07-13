#!/usr/bin/env python3
"""Export the executable native detection corpus for the live worker (Phase A2).

The native detection specs (``match_when`` + metadata) live in
``scripts/detection_specs*.py`` at the repo root. Services only ship their
``app/`` subtree, so the fusion live-detection engine cannot import those specs
at runtime. This script serialises every executable native spec into a single
JSON artifact — ``services/fusion/app/data/detection_ruleset.json`` — that the
engine loads on startup.

``--check`` drift-gates the committed artifact against the specs (the same
pattern as the connector-count and detection-truth-table gates), so a spec
change that isn't re-exported fails CI.

Usage:
    python3 scripts/export_detection_ruleset.py            # regenerate
    python3 scripts/export_detection_ruleset.py --check     # fail on drift
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

OUT = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"


def _build() -> list[dict]:
    from detection_specs_index import all_specs  # noqa: PLC0415

    rules: list[dict] = []
    seen: dict[str, int] = {}
    for category, spec in all_specs():
        match_when = spec.get("match_when")
        if not match_when:
            continue
        slug = spec["slug"]
        # Rule id mirrors generate_detections.py: det-{category}-{NNN}.
        seen[category] = seen.get(category, 0) + 1
        rule_id = f"det-{category}-{seen[category]:03d}"
        log_source = spec.get("log_source") or {}
        rules.append(
            {
                "id": rule_id,
                "slug": slug,
                "name": spec["name"],
                "severity": spec["severity"],
                "category": category,
                "product": log_source.get("product", ""),
                "service": log_source.get("service", ""),
                "mitre": [str(m).upper() for m in spec.get("mitre", [])],
                "match_when": match_when,
            }
        )
    return rules


def _serialise(rules: list[dict]) -> str:
    return json.dumps(
        {"version": 1, "count": len(rules), "rules": rules},
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    rules = _build()
    payload = _serialise(rules)

    if args.check:
        if not OUT.exists():
            print(f"ERROR: {OUT.relative_to(ROOT)} missing — run scripts/export_detection_ruleset.py", file=sys.stderr)
            return 1
        if OUT.read_text(encoding="utf-8").strip() != payload.strip():
            print(
                f"ERROR: {OUT.relative_to(ROOT)} is stale. Detection specs changed but the exported "
                "ruleset was not regenerated. Run: python3 scripts/export_detection_ruleset.py",
                file=sys.stderr,
            )
            return 1
        print(f"OK: detection ruleset current ({len(rules)} executable rules)")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(payload + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)} — {len(rules)} executable rules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
