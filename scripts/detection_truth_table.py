#!/usr/bin/env python3
"""Detection content truth table (Phase 4 — honest coverage).

The Phase 0 reality audit's overclaim #2: the README advertises "6000+ imported
detection rules", but ~97% of the imported set lives under `_quarantine/`
(`enabled: false`) because its upstream query language (SPL / YARA-L / CAR
pseudocode) does not execute on the AiSOC engine. The ATT&CK heatmap counts
metadata tags, not rules that fire.

This script walks `detections/` and classifies every rule as **executable**
(fires in AiSOC today) or **non-executable** (present for provenance /
coverage-mapping only), then renders an honest breakdown to
`docs/detections/truth-table.md`. `--check` fails CI when the committed doc
drifts from the on-disk reality — so the headline number can never quietly
diverge from what actually runs.

A rule is EXECUTABLE when it is not quarantined (not under `_quarantine/`, not
`enabled: false`) AND its `detection` body is in a form the engine evaluates:
the native AiSOC `condition` DSL, a Sigma `selection`/`condition`, or one of the
runtime-engine languages. A rule is NON-EXECUTABLE when quarantined or when its
only body is an untranslated upstream language (`splunk_spl`, `chronicle_yaral`,
CAR pseudocode).

Usage:
    python3 scripts/detection_truth_table.py            # regenerate the doc
    python3 scripts/detection_truth_table.py --check     # fail on drift
    python3 scripts/detection_truth_table.py --json      # print counts as JSON
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DETECTIONS = ROOT / "detections"
DOC = ROOT / "docs" / "detections" / "truth-table.md"

# Directories under detections/ that are not rules.
SKIP_DIRS = {"fixtures", "playbooks"}

NATIVE_CATEGORIES = {"endpoint", "cloud", "identity", "network", "application", "data-exfil"}

# detection-body keys that the AiSOC engine can actually evaluate.
EXECUTABLE_BODY_KEYS = {"condition", "selection", "sigma", "yara", "kql", "eql", "lucene", "regex", "query", "keywords"}
# untranslated upstream query languages — present for provenance, do not fire.
NON_EXECUTABLE_BODY_KEYS = {"splunk_spl", "chronicle_yaral", "yaral", "spl", "car_pseudocode", "car"}


@dataclass
class Counts:
    total: int = 0
    unparseable: int = 0
    executable: int = 0
    non_executable: int = 0
    by_tier: dict[str, int] = field(default_factory=dict)
    executable_by_tier: dict[str, int] = field(default_factory=dict)
    non_exec_reason: dict[str, int] = field(default_factory=dict)

    def bump(self, d: dict[str, int], key: str) -> None:
        d[key] = d.get(key, 0) + 1


def _tier_for(path: Path) -> str:
    rel = path.relative_to(DETECTIONS)
    top = rel.parts[0]
    if top in NATIVE_CATEGORIES:
        return "native"
    if top.endswith("-imports"):
        return top[: -len("-imports")] + " (imported)"
    if top == "community":
        return "community"
    return top


def _is_quarantined(path: Path, data: dict) -> tuple[bool, str]:
    if "_quarantine" in path.parts:
        return True, "quarantine_dir"
    enabled = data.get("enabled")
    if enabled is False:
        return True, "disabled"
    return False, ""


def _has_executable_body(data: dict) -> bool:
    det = data.get("detection")
    if not isinstance(det, dict):
        return False
    keys = set(det.keys())
    if keys & EXECUTABLE_BODY_KEYS:
        return True
    # A body that is only an untranslated upstream language does not fire.
    if keys & NON_EXECUTABLE_BODY_KEYS:
        return False
    # Unknown shape — treat as non-executable so the honest count never
    # over-reports what fires.
    return False


def _iter_rule_files() -> list[Path]:
    out: list[Path] = []
    for path in sorted(DETECTIONS.rglob("*.yaml")):
        rel = path.relative_to(DETECTIONS)
        if rel.parts[0] in SKIP_DIRS:
            continue
        if path.name.lower() in {"readme.yaml", "index.yaml"}:
            continue
        out.append(path)
    return out


def compute() -> Counts:
    counts = Counts()
    for path in _iter_rule_files():
        counts.total += 1
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            counts.unparseable += 1
            counts.non_executable += 1
            counts.bump(counts.non_exec_reason, "unparseable")
            continue
        if not isinstance(data, dict):
            counts.unparseable += 1
            counts.non_executable += 1
            counts.bump(counts.non_exec_reason, "unparseable")
            continue

        tier = _tier_for(path)
        counts.bump(counts.by_tier, tier)

        quarantined, reason = _is_quarantined(path, data)
        if quarantined:
            counts.non_executable += 1
            counts.bump(counts.non_exec_reason, reason)
            continue
        if _has_executable_body(data):
            counts.executable += 1
            counts.bump(counts.executable_by_tier, tier)
        else:
            counts.non_executable += 1
            counts.bump(counts.non_exec_reason, "untranslated_upstream_language")
    return counts


def render_markdown(c: Counts) -> str:
    lines: list[str] = []
    lines.append("# Detection content — truth table")
    lines.append("")
    lines.append("> Generated by `scripts/detection_truth_table.py`. `--check` gates this")
    lines.append("> file in `validate-detections.yml`, so the numbers below can never quietly")
    lines.append("> diverge from what the engine actually runs. **Do not edit by hand.**")
    lines.append("")
    lines.append("A rule is **executable** when it fires in AiSOC today: not quarantined")
    lines.append("(`_quarantine/` or `enabled: false`) and its `detection` body is the native")
    lines.append("AiSOC condition DSL, a Sigma selection/condition, or a runtime-engine language.")
    lines.append("A rule is **non-executable** when quarantined or when its only body is an")
    lines.append("untranslated upstream language (SPL / YARA-L / CAR pseudocode) — present for")
    lines.append("provenance and coverage-mapping, not firing.")
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append("| metric | count |")
    lines.append("|--------|------:|")
    lines.append(f"| rules on disk (total) | {c.total} |")
    lines.append(f"| **executable (fire today)** | **{c.executable}** |")
    lines.append(f"| non-executable (provenance/coverage only) | {c.non_executable} |")
    lines.append("")
    lines.append("## By tier")
    lines.append("")
    lines.append("| tier | on disk | executable |")
    lines.append("|------|--------:|-----------:|")
    for tier in sorted(c.by_tier):
        lines.append(f"| {tier} | {c.by_tier[tier]} | {c.executable_by_tier.get(tier, 0)} |")
    lines.append("")
    lines.append("## Why rules are non-executable")
    lines.append("")
    lines.append("| reason | count |")
    lines.append("|--------|------:|")
    reason_labels = {
        "quarantine_dir": "under `_quarantine/` (untranslated on import)",
        "disabled": "`enabled: false`",
        "untranslated_upstream_language": "body is an untranslated upstream language",
        "unparseable": "unparseable YAML",
    }
    for reason in sorted(c.non_exec_reason):
        label = reason_labels.get(reason, reason)
        lines.append(f"| {label} | {c.non_exec_reason[reason]} |")
    lines.append("")
    lines.append("## How to read the README claim")
    lines.append("")
    lines.append(f"The imported corpus is large ({c.total} rules on disk) and valuable as a")
    lines.append("provenance-tracked ATT&CK-mapped library, but the number that matters")
    lines.append(f"operationally is **{c.executable} executable rules** — the ones the engine")
    lines.append("fires against live telemetry. The README and marketplace must cite the")
    lines.append("executable figure when describing detection *coverage*, and may cite the")
    lines.append("on-disk figure only when explicitly describing the imported *library*.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed doc is stale")
    parser.add_argument("--json", dest="as_json", action="store_true", help="print counts as JSON")
    args = parser.parse_args()

    counts = compute()
    rendered = render_markdown(counts)

    if args.as_json:
        print(
            json.dumps(
                {
                    "total": counts.total,
                    "executable": counts.executable,
                    "non_executable": counts.non_executable,
                    "unparseable": counts.unparseable,
                    "by_tier": counts.by_tier,
                    "executable_by_tier": counts.executable_by_tier,
                    "non_exec_reason": counts.non_exec_reason,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.check:
        if not DOC.exists():
            print(f"ERROR: {DOC.relative_to(ROOT)} does not exist — run scripts/detection_truth_table.py", file=sys.stderr)
            return 1
        current = DOC.read_text(encoding="utf-8")
        if current.strip() != rendered.strip():
            print(
                f"ERROR: {DOC.relative_to(ROOT)} is stale. The detection content changed but the "
                "truth table was not regenerated. Run: python3 scripts/detection_truth_table.py",
                file=sys.stderr,
            )
            return 1
        print(f"OK: detection truth table current — {counts.executable} executable / {counts.total} on disk")
        return 0

    DOC.parent.mkdir(parents=True, exist_ok=True)
    DOC.write_text(rendered + "\n", encoding="utf-8")
    print(f"wrote {DOC.relative_to(ROOT)} — {counts.executable} executable / {counts.total} on disk")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
