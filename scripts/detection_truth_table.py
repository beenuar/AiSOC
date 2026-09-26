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

A rule is EXECUTABLE when the engine actually loads it — that is, when its id
appears in `services/fusion/app/data/detection_ruleset.json`, the compiled
ruleset `DetectionEngine` reads at startup.

That definition is deliberate, and it replaces an earlier one that classified a
rule by its file path and the key names inside its `detection:` body. The
earlier definition was wrong in a way that mattered, because the YAML under
`detections/` is a *generated projection* of the Python spec modules in
`scripts/detection_specs*.py` — the engine never reads it. So a rule could
carry `enabled: true` and a rendered `condition:` block, be counted here as
executable, and be entirely unknown to the engine. Three concrete cases this
file used to over-report:

* **77 imported Sigma rules** were counted because their body has a `selection`
  key. There is no Sigma evaluator anywhere in the repo.
* **44 native rules** have YAML and fixtures but no Python spec, so
  `export_detection_ruleset.py` never emitted them.
* The headline read **947** while the engine loaded **825**.

The practical consequence was worse than a wrong number: because the old
classifier keyed off `_quarantine/` membership, moving files out of quarantine
would have raised the published figure without changing what fires. A gate that
certifies a no-op is the specific failure this project's governance forbids, so
the count is now derived from the artifact the engine consumes.

Rules that look executable but are not loaded are reported separately as
`counted_but_not_loaded` rather than silently folded into either side — they
are real work items, and a reader deserves to see them.

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

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
DETECTIONS = ROOT / "detections"
DOC = ROOT / "docs" / "detections" / "truth-table.md"

#: The compiled ruleset `services/fusion` loads at startup. This is the only
#: artifact that determines what fires, so it is the source of truth here.
RULESET = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
#: Imported rules the compiler translated and proved fireable. The engine
#: loads this beside the native ruleset, so it is equally a source of truth.
IMPORTED_RULESET = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset_imported.json"

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
    #: Rules whose body shape looks evaluable but whose id is absent from the
    #: compiled ruleset, so the engine has never seen them. Reported separately
    #: because they are the work items the old classifier was hiding.
    counted_but_not_loaded: int = 0
    not_loaded_by_tier: dict[str, int] = field(default_factory=dict)
    #: Ids present in the compiled ruleset with no corresponding YAML file.
    #: Should be zero; a non-zero value means the projection is out of sync.
    loaded_without_yaml: int = 0
    engine_rule_count: int = 0

    def bump(self, d: dict[str, int], key: str) -> None:
        d[key] = d.get(key, 0) + 1


def _ids_in(path: Path, *, required: bool) -> set[str]:
    if not path.exists():
        if required:
            print(
                f"WARNING: {path.relative_to(ROOT)} is missing — run scripts/export_detection_ruleset.py. Reporting zero executable rules.",
                file=sys.stderr,
            )
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        print(f"WARNING: could not read {path.relative_to(ROOT)}: {exc}", file=sys.stderr)
        return set()
    return {str(rule["id"]) for rule in data.get("rules") or [] if rule.get("id")}


def _engine_rule_ids() -> set[str]:
    """Ids the detection engine actually loads.

    The engine reads two artifacts: the native specs exported by
    ``export_detection_ruleset.py`` and the imported rules translated and
    proven fireable by ``compile_sigma_ruleset.py``. Both count, because the
    definition of executable here is "the engine loads it" — reading only the
    first would under-report by exactly the corpus this file exists to keep
    honest about.

    An empty set is returned when the ruleset is missing, which makes the
    headline read zero rather than falling back to the body-shape heuristic.
    Reporting zero executable rules is loud and obviously wrong; quietly
    reverting to a heuristic that over-reports is not.
    """
    return _ids_in(RULESET, required=True) | _ids_in(IMPORTED_RULESET, required=False)


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
    engine_ids = _engine_rule_ids()
    counts.engine_rule_count = len(engine_ids)
    seen_ids: set[str] = set()

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

        rule_id = str(data.get("id") or "")
        if rule_id:
            seen_ids.add(rule_id)

        # Engine membership decides executability. Everything else is a reason.
        if rule_id and rule_id in engine_ids:
            counts.executable += 1
            counts.bump(counts.executable_by_tier, tier)
            continue

        counts.non_executable += 1
        quarantined, reason = _is_quarantined(path, data)
        if quarantined:
            counts.bump(counts.non_exec_reason, reason)
        elif _has_executable_body(data):
            # The case the old classifier called executable: an enabled rule
            # with an evaluable-looking body that the engine does not load,
            # because no Python spec produced a `match_when` for it.
            counts.counted_but_not_loaded += 1
            counts.bump(counts.not_loaded_by_tier, tier)
            counts.bump(counts.non_exec_reason, "no_compiled_spec")
        else:
            counts.bump(counts.non_exec_reason, "untranslated_upstream_language")

    counts.loaded_without_yaml = len(engine_ids - seen_ids)
    return counts


def render_markdown(c: Counts) -> str:
    lines: list[str] = []
    lines.append("# Detection content — truth table")
    lines.append("")
    lines.append("> Generated by `scripts/detection_truth_table.py`. `--check` gates this")
    lines.append("> file in `validate-detections.yml`, so the numbers below can never quietly")
    lines.append("> diverge from what the engine actually runs. **Do not edit by hand.**")
    lines.append("")
    lines.append("A rule is **executable** when the detection engine actually loads it — when")
    lines.append("its id appears in `services/fusion/app/data/detection_ruleset.json`, the")
    lines.append("compiled ruleset `DetectionEngine` reads at startup.")
    lines.append("")
    lines.append("That is the only definition that means anything, because the YAML under")
    lines.append("`detections/` is a *generated projection* of the Python spec modules in")
    lines.append("`scripts/detection_specs*.py` — the engine never reads it. Editing a")
    lines.append("`condition:` block or flipping `enabled:` has no effect on what fires. The")
    lines.append("lever that reaches the engine is adding a spec and re-running")
    lines.append("`scripts/export_detection_ruleset.py`.")
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append("| metric | count |")
    lines.append("|--------|------:|")
    lines.append(f"| rules on disk (total) | {c.total} |")
    lines.append(f"| **executable (loaded by the engine)** | **{c.executable}** |")
    lines.append(f"| non-executable (provenance/coverage only) | {c.non_executable} |")
    lines.append(f"| — of which: enabled, but no compiled spec | {c.counted_but_not_loaded} |")
    lines.append("")
    if c.counted_but_not_loaded:
        lines.append(f"Those {c.counted_but_not_loaded} rules are the ones an earlier version of this")
        lines.append("table counted as executable. They carry `enabled: true` and a body whose")
        lines.append("shape looks evaluable, and the engine has never seen them because no spec")
        lines.append("produced a `match_when` for them. They are genuine work items, listed by")
        lines.append("tier below, not a rounding error.")
        lines.append("")
    if c.loaded_without_yaml:
        lines.append(f"**{c.loaded_without_yaml} ids are in the compiled ruleset with no YAML file.**")
        lines.append("The projection is out of sync — re-run `scripts/generate_detections.py`.")
        lines.append("")
    lines.append("## By tier")
    lines.append("")
    lines.append("| tier | on disk | executable | enabled but not loaded |")
    lines.append("|------|--------:|-----------:|-----------------------:|")
    for tier in sorted(c.by_tier):
        lines.append(f"| {tier} | {c.by_tier[tier]} | {c.executable_by_tier.get(tier, 0)} | {c.not_loaded_by_tier.get(tier, 0)} |")
    lines.append("")
    lines.append("## Why rules are non-executable")
    lines.append("")
    lines.append("| reason | count |")
    lines.append("|--------|------:|")
    reason_labels = {
        "quarantine_dir": "under `_quarantine/` (untranslated on import)",
        "disabled": "`enabled: false`",
        "untranslated_upstream_language": "body is an untranslated upstream language",
        "no_compiled_spec": "enabled, but no compiled spec — the engine does not load it",
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
    lines.append("loads and fires against live telemetry. The README and marketplace must cite")
    lines.append("the executable figure when describing detection *coverage*, and may cite the")
    lines.append("on-disk figure only when explicitly describing the imported *library*.")
    lines.append("")
    lines.append("Two things this table cannot tell you, stated so nobody infers them:")
    lines.append("")
    lines.append("1. A loaded rule still has to match on a field some connector emits. That")
    lines.append("   property is enforced separately by `scripts/check_detection_fields.py`.")
    lines.append("2. Executable is not the same as tuned. `false_positives:` is prose and is")
    lines.append("   not machine-checked; there is no per-rule false-positive-rate gate.")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the committed doc is stale")
    parser.add_argument("--json", dest="as_json", action="store_true", help="print counts as JSON")
    parser.add_argument(
        "--max-phantoms",
        type=int,
        default=0,
        help=(
            "how many enabled-but-never-loaded rules to tolerate. A phantom is "
            "counted as shipped coverage and detects nothing, so the ceiling is zero."
        ),
    )
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
                    "counted_but_not_loaded": counts.counted_but_not_loaded,
                    "not_loaded_by_tier": counts.not_loaded_by_tier,
                    "loaded_without_yaml": counts.loaded_without_yaml,
                    "engine_rule_count": counts.engine_rule_count,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0

    if args.check:
        if counts.counted_but_not_loaded > args.max_phantoms:
            # These are the rules that look shipped and are not: enabled on
            # disk, absent from what the engine loads. They were the whole
            # reason this file stopped classifying by file path, so letting a
            # new one through would reopen the hole rather than widen a
            # tolerance.
            print(
                f"ERROR: {counts.counted_but_not_loaded} rule(s) are enabled but the engine never loads them "
                f"(limit {args.max_phantoms}): {counts.not_loaded_by_tier}.\n"
                "Either give the rule a compiled spec, or set `enabled: false` with a "
                "`quarantine_reason` saying what it would need.",
                file=sys.stderr,
            )
            return 1
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
