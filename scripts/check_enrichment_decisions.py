#!/usr/bin/env python3
"""CI gate: a rule that still cannot fire carries a reason, not just an absence.

Depth plan 3.3 built two enrichment inputs — per-tenant identity privilege
and a per-tenant first-seen store — and said of what remained: *"build them
where cheap, otherwise quarantine with a reason."*

Quarantining is the dangerous half, because deleting a rule and fixing a rule
move `MAX_UNREACHABLE` by the same amount. This gate makes them different:

* every rule in `enrichment_decisions.DECISIONS` names a real spec, carries a
  known kind and a reason long enough to act on;
* every retired rule is in fact gone from the stateless corpus, so a decision
  that was recorded and never applied fails here;
* **no rule is retired whose fields the platform now computes** — the check
  that stops a working rule being quarantined to make a number move. It is
  the one that would catch the lazy version of this whole item.

Usage:
    python3 scripts/check_enrichment_decisions.py             # enforce
    python3 scripts/check_enrichment_decisions.py --check     # same, for CI
    python3 scripts/check_enrichment_decisions.py --list      # every decision
    python3 scripts/check_enrichment_decisions.py --self-test # prove it works
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SKELETON, refuses_an_empty_tree, repo_root, self_test_main

ROOT = repo_root()
RULESET = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"

#: A reason shorter than this is not a reason. It is the only record a reader
#: of the catalogue gets of why a shipped rule does not run.
_MIN_REASON_CHARS = 60


def _load(name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:  # pragma: no cover
        raise SystemExit(f"{Path(sys.argv[0]).name}: cannot load scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def check(
    decisions: dict[str, Any],
    kinds: frozenset[str],
    specs: dict[str, dict[str, Any]],
    engine_ids: set[str],
    lock: dict[str, str],
    fields_gate: Any,
) -> list[str]:
    problems: list[str] = []
    if not specs:
        problems.append("no detection specs were read — refusing to report a tree with no rules as clean")
        return problems

    namespace = fields_gate._connector_namespace() | fields_gate._template_namespace() | fields_gate._go_normalizer_namespace()

    for key, decision in decisions.items():
        if key not in specs:
            problems.append(f"{key} is decided but no spec declares it; a slug was renamed or removed")
            continue
        if decision.kind not in kinds:
            problems.append(f"{key} is refused with an unknown kind {decision.kind!r}")
        if len(decision.reason.strip()) < _MIN_REASON_CHARS:
            problems.append(f"{key} is refused with a reason too short to act on ({len(decision.reason.strip())} chars)")

        rule_id = lock.get(key)
        if rule_id and rule_id in engine_ids:
            problems.append(f"{key} ({rule_id}) is retired but still in {RULESET.name} — scripts/export_detection_ruleset.py must drop it")

        # The check that matters. A rule every one of whose fields the
        # platform can now resolve is a rule that works, and retiring it
        # lowers the ratchet by removing a detection rather than by closing
        # a gap.
        missing = [
            f
            for f in fields_gate._rule_fields(specs[key].get("match_when") or {})
            if f not in namespace and not fields_gate._is_derivable(f, namespace)
        ]
        if not missing:
            problems.append(
                f"{key} is retired, but every field it reads is now resolvable. "
                "Retiring a rule that works lowers the ratchet without closing anything — un-retire it."
            )
    return problems


def _self_test_injections(
    decisions: dict[str, Any],
    kinds: frozenset[str],
    specs: dict[str, dict[str, Any]],
    engine_ids: set[str],
    lock: dict[str, str],
    fields_gate: Any,
) -> list[tuple[str, bool]]:
    module = _load("enrichment_decisions")
    results = [("the tree as committed has no findings to begin with", not check(decisions, kinds, specs, engine_ids, lock, fields_gate))]

    first = next(iter(decisions))

    blunt = dict(decisions)
    blunt[first] = module.Refusal(module.NEEDS_INVENTORY, "too hard")
    results.append(("catches a refusal with no usable reason", bool(check(blunt, kinds, specs, engine_ids, lock, fields_gate))))

    typo = dict(decisions)
    typo[first] = module.Refusal("needs-something", decisions[first].reason)
    results.append(
        ("catches a refusal kind that is not one of the declared families", bool(check(typo, kinds, specs, engine_ids, lock, fields_gate)))
    )

    invented = dict(decisions)
    invented["identity/a-slug-that-does-not-exist"] = decisions[first]
    results.append(("catches a decision for a rule no spec declares", bool(check(invented, kinds, specs, engine_ids, lock, fields_gate))))

    still_shipped = set(engine_ids) | {lock.get(first, "")}
    results.append(
        ("catches a retired rule the exporter still ships", bool(check(decisions, kinds, specs, still_shipped, lock, fields_gate)))
    )

    # The important one: retire a rule that works, and require it to be
    # caught. Picked from the corpus rather than invented, so the injection
    # is a rule the engine really does load and really can fire.
    working = next(
        key
        for key, spec in specs.items()
        if key not in decisions
        and spec.get("match_when")
        and not [
            f
            for f in fields_gate._rule_fields(spec["match_when"])
            if f not in (fields_gate._connector_namespace() | fields_gate._template_namespace() | fields_gate._go_normalizer_namespace())
            and not fields_gate._is_derivable(f, set())
        ]
    )
    over_retired = dict(decisions)
    over_retired[working] = decisions[first]
    results.append(
        (
            f"catches a working rule retired to move the ratchet ({working})",
            any("every field it reads is now resolvable" in p for p in check(over_retired, kinds, specs, engine_ids, lock, fields_gate)),
        )
    )

    results.append(("refuses a corpus it read no specs from", bool(check(decisions, kinds, {}, engine_ids, lock, fields_gate))))

    skeleton_refused, detail = refuses_an_empty_tree(Path(__file__).name, ["--check"], shape=SKELETON)
    results.append((f"refuses a tree whose directories exist and hold no rules ({detail.splitlines()[0]})", skeleton_refused))
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="enforce (the default; accepted so CI can be explicit)")
    parser.add_argument("--list", action="store_true", help="print every decision")
    parser.add_argument("--self-test", action="store_true", help="prove the gate catches what it claims to")
    args = parser.parse_args()

    if not RULESET.is_file():
        print(f"{Path(sys.argv[0]).name}: no detection ruleset at {RULESET} — nothing to check", file=sys.stderr)
        return 2

    module = _load("enrichment_decisions")
    fields_gate = _load("check_detection_fields")
    sys.path.insert(0, str(ROOT / "scripts"))
    from detection_specs_index import all_specs  # noqa: PLC0415
    from generate_detections import load_id_lock  # noqa: PLC0415

    specs = {f"{category}/{spec['slug']}": spec for category, spec in all_specs()}
    lock = load_id_lock()
    engine_ids = {str(r.get("id")) for r in json.loads(RULESET.read_text(encoding="utf-8")).get("rules") or []}

    if args.self_test:
        return self_test_main(
            Path(__file__).name,
            ["--check"],
            extra=_self_test_injections(module.DECISIONS, module.KINDS, specs, engine_ids, lock, fields_gate),
        )

    if args.list:
        for key, decision in module.DECISIONS.items():
            print(f"RETIRED  {key} [{decision.kind}] {decision.reason.splitlines()[0]}")
        return 0

    problems = check(module.DECISIONS, module.KINDS, specs, engine_ids, lock, fields_gate)
    kinds: dict[str, int] = {}
    for decision in module.DECISIONS.values():
        kinds[decision.kind] = kinds.get(decision.kind, 0) + 1
    print(f"enrichment decisions: {len(module.DECISIONS)} rules retired with a reason")
    for kind, count in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print(f"      {count:4d} {kind}")

    if problems:
        print(f"\nERROR: {len(problems)} problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("\nOK: every retired rule names a real spec, a reason, and a gap the platform genuinely has")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
