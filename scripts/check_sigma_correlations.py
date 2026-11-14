#!/usr/bin/env python3
"""CI gate: every Sigma correlation compiles into the windowed engine, or is refused.

The gap this closes
-------------------
`scripts/compile_sigma_ruleset.py` translates Sigma *rule* documents into the
stateless matcher. It has never looked at a `correlation:` block, and the
3,132 imported rule documents do not contain one, so the two facts hid each
other: there was no importer and no corpus for it to fail on. A correlation
quietly ignored by an importer is the worst shape available — the rule is in
the tree, it is in the count of what was imported, and it detects nothing.

What this enforces
------------------
* every correlation document in `detections/sigma-correlations/` either
  compiles or carries a refusal reason, and the two sets do not overlap;
* a compiled correlation's selector fields, `group-by` and `distinct_by` are
  names some connector, ingest template or the Go normalizer actually emits —
  the same standard `check_detection_fields.py` holds the native corpus to,
  applied here with **no ceiling**, because this corpus is new and starts
  clean;
* everything under `_refused/` is in fact refused, so a file cannot be parked
  there to dodge the checks above;
* the compiled output is what `windowed_ruleset.json` ships.

Usage:
    python3 scripts/check_sigma_correlations.py             # enforce
    python3 scripts/check_sigma_correlations.py --check     # same, for CI
    python3 scripts/check_sigma_correlations.py --report    # the taxonomy
    python3 scripts/check_sigma_correlations.py --self-test # prove the gate works
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SKELETON, refuses_an_empty_tree, repo_root, self_test_main
from sigma_compiler import Refusal, compile_rule
from sigma_correlation import CorrelationRefusal, compile_correlation

ROOT = repo_root()
CORPUS = ROOT / "detections" / "sigma-correlations"
WINDOWED = ROOT / "services" / "fusion" / "app" / "data" / "windowed_ruleset.json"
REFUSED_DIR = "_refused"


def _documents(path: Path) -> list[dict[str, Any]]:
    try:
        docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except yaml.YAMLError:
        return []
    return [d for d in docs if isinstance(d, dict)]


def compile_corpus() -> tuple[list[dict[str, Any]], list[tuple[str, str]], int]:
    """Returns (compiled windowed rules, [(file, reason)], documents read).

    The document count is returned so a caller can refuse a corpus that read
    nothing: a compiler over zero files produces zero refusals and zero
    rules, which reads exactly like a clean corpus.
    """
    compiled: list[dict[str, Any]] = []
    refused: list[tuple[str, str]] = []
    seen = 0

    for path in sorted(CORPUS.rglob("*.yml")) + sorted(CORPUS.rglob("*.yaml")):
        docs = _documents(path)
        if not docs:
            continue
        seen += len(docs)
        relative = str(path.relative_to(ROOT))

        selectors: dict[str, dict[str, Any]] = {}
        base_refusals: list[str] = []
        for doc in docs:
            if doc.get("correlation"):
                continue
            name = str(doc.get("name") or doc.get("id") or "").strip()
            if not name:
                base_refusals.append("a base rule has neither a name nor an id")
                continue
            try:
                selectors[name] = compile_rule(doc).match_when
            except Refusal as exc:
                base_refusals.append(f"base rule {name!r}: {exc}")

        correlation_ids = {str(d.get("id") or "") for d in docs if d.get("correlation")}
        for doc in docs:
            if not doc.get("correlation"):
                continue
            try:
                if base_refusals:
                    raise CorrelationRefusal("a referenced rule did not compile", "; ".join(base_refusals))
                compiled.append(compile_correlation(doc, selectors=selectors, correlations=frozenset(correlation_ids)))
            except CorrelationRefusal as exc:
                refused.append((relative, str(exc)))
    return compiled, refused, seen


def _namespace() -> set[str]:
    spec = importlib.util.spec_from_file_location("check_detection_fields", ROOT / "scripts" / "check_detection_fields.py")
    if spec is None or spec.loader is None:  # pragma: no cover
        raise SystemExit("cannot load scripts/check_detection_fields.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_detection_fields"] = module
    spec.loader.exec_module(module)
    return module._connector_namespace() | module._template_namespace() | module._go_normalizer_namespace()


def _selector_fields(rule: dict[str, Any]) -> set[str]:
    spec = importlib.util.spec_from_file_location("check_detection_fields", ROOT / "scripts" / "check_detection_fields.py")
    module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
    sys.modules["check_detection_fields"] = module
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    clauses = [rule["match_when"]] if rule.get("match_when") else list(rule.get("sequence") or [])
    found: set[str] = set()
    for clause in clauses:
        found |= module._rule_fields(clause)
    for key in ("group_by", "distinct_by"):
        if rule.get(key):
            found.add(str(rule[key]))
    return found


def check(compiled: list[dict[str, Any]], refused: list[tuple[str, str]], seen: int, shipped: set[str]) -> list[str]:
    problems: list[str] = []
    if seen == 0:
        problems.append(f"no correlation documents read under {CORPUS.relative_to(ROOT)} — refusing to report a corpus of zero as clean")
        return problems

    namespace = _namespace()
    compiled_by_id: dict[str, dict[str, Any]] = {}
    for rule in compiled:
        rule_id = str(rule.get("id") or "")
        if rule_id in compiled_by_id:
            problems.append(f"two correlations share the id {rule_id!r}")
        compiled_by_id[rule_id] = rule

        unknown = sorted(f for f in _selector_fields(rule) if f not in namespace)
        if unknown:
            problems.append(
                f"{rule_id} names field(s) nothing emits: {', '.join(unknown)}. "
                "A correlation grouping on a field no source produces counts nothing forever."
            )
        if rule_id not in shipped:
            problems.append(f"{rule_id} compiled but is not in {WINDOWED.name} — re-run scripts/export_windowed_ruleset.py")

    # Everything under `_refused/` must in fact be refused, or the directory
    # becomes a place to park a rule away from the checks above.
    parked = {path for path, _ in refused}
    for path in sorted(CORPUS.rglob("*.yml")):
        relative = str(path.relative_to(ROOT))
        in_refused_dir = REFUSED_DIR in path.relative_to(CORPUS).parts
        if in_refused_dir and relative not in parked:
            problems.append(f"{relative} sits under {REFUSED_DIR}/ but compiled cleanly — move it out or say why it cannot run")
        if not in_refused_dir and relative in parked:
            reason = next(r for p, r in refused if p == relative)
            problems.append(f"{relative} was refused but is not under {REFUSED_DIR}/: {reason}")
    return problems


def _self_test_injections(
    compiled: list[dict[str, Any]], refused: list[tuple[str, str]], seen: int, shipped: set[str]
) -> list[tuple[str, bool]]:
    results = [("the corpus as committed has no findings to begin with", not check(compiled, refused, seen, shipped))]

    invented = [*compiled, {**compiled[0], "id": "aisoc-corr-injected", "group_by": "a_field_nothing_emits"}]
    results.append(
        (
            "catches a correlation grouping on a field nothing emits",
            any("nothing emits" in p for p in check(invented, refused, seen, shipped | {"aisoc-corr-injected"})),
        )
    )

    results.append(("catches a compiled correlation missing from the windowed ruleset", bool(check(compiled, refused, seen, set()))))

    duplicated = [*compiled, dict(compiled[0])]
    results.append(("catches two correlations sharing an id", any("share the id" in p for p in check(duplicated, refused, seen, shipped))))

    # Drop the real refusals so the files under `_refused/` look as though
    # they compiled. Expressed by removing them from the refusal list rather
    # than by writing a file, because the check reads the directory and a
    # self-test that mutates the tree is one that can leave it dirty.
    as_if_compiling = [entry for entry in refused if REFUSED_DIR not in entry[0]]
    results.append(
        (
            "catches a rule parked under _refused/ that in fact compiles",
            any("compiled cleanly" in p for p in check(compiled, as_if_compiling, seen, shipped)),
        )
    )

    results.append(("refuses a corpus it read nothing from", bool(check(compiled, refused, 0, shipped))))

    skeleton_refused, detail = refuses_an_empty_tree(Path(__file__).name, ["--check"], shape=SKELETON)
    results.append((f"refuses a tree whose directories exist and hold no correlations ({detail.splitlines()[0]})", skeleton_refused))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="enforce (the default; accepted so CI can be explicit)")
    parser.add_argument("--report", action="store_true", help="print the compiled and refused taxonomy")
    parser.add_argument("--self-test", action="store_true", help="prove the gate catches what it claims to")
    args = parser.parse_args()

    if not CORPUS.is_dir():
        print(f"{Path(sys.argv[0]).name}: no correlation corpus at {CORPUS} — nothing to check", file=sys.stderr)
        return 2

    compiled, refused, seen = compile_corpus()
    shipped: set[str] = set()
    if WINDOWED.is_file():
        shipped = {str(r.get("id")) for r in json.loads(WINDOWED.read_text(encoding="utf-8")).get("rules") or []}

    if args.self_test:
        if not compiled:
            print("sigma correlations: nothing compiled, so the injections below would prove nothing", file=sys.stderr)
            return 1
        return self_test_main(Path(__file__).name, ["--check"], extra=_self_test_injections(compiled, refused, seen, shipped))

    if args.report:
        for rule in compiled:
            kind = rule.get("correlation_type")
            print(f"COMPILED  {rule['id']}  [{kind}] group_by={rule['group_by']} window={rule['window_seconds']}s")
        for path, reason in refused:
            print(f"REFUSED   {path}: {reason}")
        return 0

    problems = check(compiled, refused, seen, shipped)
    kinds: dict[str, int] = {}
    for rule in compiled:
        kind = str(rule.get("correlation_type"))
        kinds[kind] = kinds.get(kind, 0) + 1
    print(f"sigma correlations: {seen} documents read, {len(compiled)} compiled, {len(refused)} refused")
    for kind, count in sorted(kinds.items()):
        print(f"      {count:4d} {kind}")
    for path, reason in refused:
        print(f"      refused {Path(path).name}: {reason}")

    if problems:
        print(f"\nERROR: {len(problems)} problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("\nOK: every correlation compiles into the windowed engine or is refused with a reason")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
