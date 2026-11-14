#!/usr/bin/env python3
"""CI gate: a `det-*` rule that needs a window is translated or refused, never dropped.

The hole this closes
--------------------
74 engine-loaded rules name a counter no source emits — ``fail_count``,
``events_per_minute``, ``distinct_secrets_per_minute`` — so each one reads
``None`` on its first clause and can never fire, while still being loaded and
still counted toward the published executable total.
``scripts/windowed_translation.py`` decides what happens to each.

Without this gate the decision table is a suggestion. Two cheap ways to make
the unreachable ratchet go down without detecting anything more exist, and
both look like progress in a diff:

* delete the ``det-*`` spec, and the rule leaves the corpus with no
  replacement;
* write a ``wd-*`` rule with a rounder threshold or a wider window than the
  original, so the translation is a new detection wearing the old one's name
  and severity.

So this re-derives every translation from the ``det-*`` spec it came from and
compares it with what is committed, checks that the clauses the translation
did not consume survived verbatim into the windowed rule, and refuses a
decision that is neither a translation nor a reason.

What it deliberately does not do
--------------------------------
It does not require ``group_by`` to be in the statically-recovered emitted
namespace. That namespace is an under-approximation for payloads a connector
lifts wholesale rather than naming key by key — five windowed rules that
predate this gate group by Windows ``EventData`` keys the ``windows_event``
connector lifts generically, and failing them would be a false alarm about
rules that work. Those are **reported**, the same way
``check_detection_fields.py`` reports its vendor-payload class, and the
evidence that a translated rule fires is replay through the real engine
(``services/fusion/tests/test_windowed_translation_replay.py``) rather than a
name lookup.

Usage:
    python3 scripts/check_windowed_translation.py             # enforce
    python3 scripts/check_windowed_translation.py --check     # same, for CI
    python3 scripts/check_windowed_translation.py --list      # every decision
    python3 scripts/check_windowed_translation.py --self-test # prove the gate works
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SKELETON, refuses_an_empty_tree, repo_root, self_test_main

ROOT = repo_root()
RULESET = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
WINDOWED = ROOT / "services" / "fusion" / "app" / "data" / "windowed_ruleset.json"

#: Reasons shorter than this are not reasons. A refusal is the only record a
#: reader of the catalogue gets of why a shipped rule does not run.
_MIN_REASON_CHARS = 60

#: Windowed rules whose *selector* names a computed field, which no source
#: emits, so the rule cannot fire however correct its window is. This is the
#: reachability ratchet the windowed corpus never had: `check_detection_fields`
#: reads the stateless ruleset only, so until now a windowed rule could name
#: anything.
#:
#: Two standing entries read `role_priv` when this was written. Depth plan
#: 3.3 built that enrichment, so the ceiling came down with it. Never raise
#: it to make a red build green: a windowed rule naming a computed field
#: counts nothing forever.
MAX_UNREACHABLE_WINDOWED = 0


def _load_sibling(name: str) -> Any:
    """Import a script beside this one by path, not by package.

    `scripts/` is not a package and several of these files are run directly,
    so an ordinary import works only when the process happened to start in
    the right directory.
    """
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:  # pragma: no cover - unreachable with a real tree
        raise SystemExit(f"{Path(sys.argv[0]).name}: cannot load scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def windowed_family(fields_gate: Any) -> dict[str, str]:
    """`det-*` rules the reachability gate attributes to the windowed family.

    Keyed by rule id, valued by the `<category>/<slug>` the decision table
    uses. Derived from that gate's own classifier rather than from a second
    copy of the pattern, so the two cannot drift into disagreeing about which
    rules this one is responsible for.
    """
    sys.path.insert(0, str(ROOT / "scripts"))
    from detection_specs_index import all_specs  # noqa: PLC0415
    from generate_detections import load_id_lock  # noqa: PLC0415

    lock = load_id_lock()
    key_by_id = {lock.get(f"{category}/{spec['slug']}"): f"{category}/{spec['slug']}" for category, spec in all_specs()}

    derived, _vendor, _namespace, _total = fields_gate.scan()
    out: dict[str, str] = {}
    for rule_id, missing in derived:
        if any(fields_gate._family(name) == "windowed evaluator" for name in missing):
            key = key_by_id.get(rule_id)
            if key:
                out[rule_id] = key
    return out


def _read_rules(path: Path, label: str) -> list[dict[str, Any]]:
    if not path.is_file():
        raise SystemExit(f"{Path(sys.argv[0]).name}: {label} missing at {path} — nothing to check")
    payload = json.loads(path.read_text(encoding="utf-8"))
    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise SystemExit(f"{Path(sys.argv[0]).name}: {path} declares no rules — refusing to report a clean tree")
    return rules


def check(
    translation: Any,
    specs: dict[str, tuple[str, dict[str, Any]]],
    windowed: list[dict[str, Any]],
    engine_ids: set[str],
    family: dict[str, str],
) -> list[str]:
    """Every rule this gate enforces, in one pass. Returns the failures."""
    problems: list[str] = []
    committed = {rule["id"]: rule for rule in windowed if isinstance(rule, dict) and rule.get("id")}

    # R1 — nothing in the family may be undecided.
    for rule_id, key in sorted(family.items()):
        if key not in translation.DECISIONS:
            problems.append(
                f"{rule_id} ({key}) needs a window and has no decision — add a Translation or a Refusal to scripts/windowed_translation.py"
            )

    for key, decision in translation.DECISIONS.items():
        if key not in specs:
            problems.append(f"{key} is decided but no spec declares it; a slug was renamed or removed")
            continue
        category, spec = specs[key]
        rule_id = key

        if isinstance(decision, translation.Refusal):
            # R5 — a refusal is only worth anything if it says why.
            if decision.kind not in translation.REFUSAL_KINDS:
                problems.append(f"{key} is refused with an unknown kind {decision.kind!r}")
            if len(decision.reason.strip()) < _MIN_REASON_CHARS:
                problems.append(f"{key} is refused with a reason too short to act on ({len(decision.reason.strip())} chars)")
            continue

        if isinstance(decision, translation.Covered):
            if decision.by not in committed:
                problems.append(f"{key} claims {decision.by} already covers it, but no such windowed rule is committed")
            continue

        # R2 — the committed windowed rule must be what the spec derives to.
        try:
            expected = translation.derive(category, spec, decision)
        except translation.ShapeError as exc:
            problems.append(f"{key} is translated but its clauses do not form a window: {exc}")
            continue
        actual = committed.get(expected["id"])
        if actual is None:
            problems.append(
                f"{key} translates to {expected['id']}, which is not in {WINDOWED.name} — re-run scripts/export_windowed_ruleset.py"
            )
            continue
        for attribute in ("threshold", "window_seconds", "severity", "category", "match_when", "group_by"):
            if actual.get(attribute) != expected[attribute]:
                problems.append(
                    f"{expected['id']} {attribute} is {actual.get(attribute)!r} in {WINDOWED.name} but the "
                    f"{rule_id} spec derives {expected[attribute]!r} — a translation may not restate its original's numbers"
                )
        if actual.get("distinct_by", "") != expected.get("distinct_by", ""):
            problems.append(f"{expected['id']} distinct_by disagrees with the decision table")

        # R3 — a clause the translation did not consume must survive verbatim.
        shape = translation.parse_shape(spec["match_when"])
        survivors = {k: v for k, v in spec["match_when"].items() if k not in shape.consumed}
        if survivors != expected["match_when"]:
            problems.append(
                f"{expected['id']} dropped or rewrote a clause of {rule_id}: expected {survivors!r}, got {expected['match_when']!r}"
            )

    # R4 — a decision has to take effect, or the rule still ships unreachable.
    sys.path.insert(0, str(ROOT / "scripts"))
    from generate_detections import load_id_lock  # noqa: PLC0415

    lock = load_id_lock()
    for key in translation.DECISIONS:
        locked_id = lock.get(key)
        if locked_id and locked_id in engine_ids:
            problems.append(
                f"{key} ({locked_id}) is decided but still in {RULESET.name} — scripts/export_detection_ruleset.py must drop a decided rule"
            )
    return problems


def _unemitted_entities(fields_gate: Any, windowed: list[dict[str, Any]]) -> list[tuple[str, list[str]]]:
    """Windowed rules whose entity fields are outside the static namespace."""
    namespace = fields_gate._connector_namespace() | fields_gate._template_namespace() | fields_gate._go_normalizer_namespace()
    out: list[tuple[str, list[str]]] = []
    for rule in windowed:
        missing = [f"{k}={rule[k]}" for k in ("group_by", "distinct_by") if rule.get(k) and rule[k] not in namespace]
        if missing:
            out.append((str(rule.get("id")), missing))
    return out


def unreachable_windowed(fields_gate: Any, windowed: list[dict[str, Any]]) -> list[tuple[str, list[str]]]:
    """Windowed rules selecting on a field that is computed, not observed.

    The same question ``check_detection_fields.py`` asks of the stateless
    corpus, asked of the windowed one, which nothing asked before. Entity
    fields are excluded on purpose and reported separately: the static
    namespace under-approximates payloads a connector lifts wholesale, so a
    missing entity name is weak evidence, while a *computed* field name is
    conclusive — nothing anywhere produces it.
    """
    namespace = fields_gate._connector_namespace() | fields_gate._template_namespace() | fields_gate._go_normalizer_namespace()
    out: list[tuple[str, list[str]]] = []
    for rule in windowed:
        computed = sorted(
            name
            for name in fields_gate._rule_fields(rule.get("match_when") or {})
            if name not in namespace and not fields_gate._is_derivable(name, namespace) and fields_gate._DERIVED_FIELD_PATTERN.search(name)
        )
        if computed:
            out.append((str(rule.get("id")), computed))
    return out


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def _self_test_injections(
    translation: Any,
    specs: dict[str, tuple[str, dict[str, Any]]],
    windowed: list[dict[str, Any]],
    engine_ids: set[str],
    family: dict[str, str],
) -> list[tuple[str, bool]]:
    """One injected violation per rule, each proved to be caught.

    Injected into copies of the gate's inputs rather than into the tree: the
    rules are properties of the decision table against the corpus, and a
    scratch checkout would have to carry the whole corpus to express them.
    """
    results: list[tuple[str, bool]] = []
    baseline = check(translation, specs, windowed, engine_ids, family)
    results.append(("the tree as committed has no findings to begin with", not baseline))

    first_translated = next(k for k, d in translation.DECISIONS.items() if isinstance(d, translation.Translation))
    first_refused = next(k for k, d in translation.DECISIONS.items() if isinstance(d, translation.Refusal))

    # R1 — an undecided family member. Injected rather than produced by
    # removing a decision, because once every decided rule has left the
    # stateless corpus the family is empty, so there is nothing to un-decide.
    # R1 guards the *next* rule somebody writes with a counter in its clauses,
    # and a self-test that cannot express that is a self-test for a rule
    # nobody is checking.
    newcomer = dict(family)
    newcomer["det-cloud-999"] = "cloud/a-rule-nobody-decided"
    results.append(("R1 catches a windowed rule with no decision", bool(check(translation, specs, windowed, engine_ids, newcomer))))

    # R2 — a committed rule whose threshold was nudged.
    nudged = []
    target = translation.DECISIONS[first_translated]
    target_id = target.wd_id or f"wd-{first_translated.split('/', 1)[1]}"
    for rule in windowed:
        clone = dict(rule)
        if clone.get("id") == target_id:
            clone["threshold"] = int(clone.get("threshold", 1)) + 5
        nudged.append(clone)
    results.append(
        ("R2 catches a translated threshold that drifted from its original", bool(check(translation, specs, nudged, engine_ids, family)))
    )

    # R3 — a selector clause silently dropped from the committed rule.
    pruned = []
    for rule in windowed:
        clone = dict(rule)
        if clone.get("id") == target_id and clone.get("match_when"):
            clone["match_when"] = {}
        pruned.append(clone)
    results.append(("R3 catches a selector clause dropped in translation", bool(check(translation, specs, pruned, engine_ids, family))))

    # R4 — a decided rule still shipped in the stateless corpus.
    sys.path.insert(0, str(ROOT / "scripts"))
    from generate_detections import load_id_lock  # noqa: PLC0415

    still_there = set(engine_ids) | {load_id_lock().get(first_translated, "")}
    results.append(
        ("R4 catches a decided rule the stateless exporter still ships", bool(check(translation, specs, windowed, still_there, family)))
    )

    # R5 — a refusal with no usable reason.
    blunt = dict(translation.DECISIONS)
    blunt[first_refused] = translation.Refusal(translation.AGGREGATE, "too hard")
    results.append(
        ("R5 catches a refusal with no usable reason", bool(_with_decisions(translation, blunt, specs, windowed, engine_ids, family)))
    )

    # An unknown refusal kind, which is how a typo would silently create a
    # family nothing reports on.
    typo = dict(translation.DECISIONS)
    typo[first_refused] = translation.Refusal("aggregates", translation.DECISIONS[first_refused].reason)
    results.append(
        (
            "R5 catches a refusal kind that is not one of the declared families",
            bool(_with_decisions(translation, typo, specs, windowed, engine_ids, family)),
        )
    )

    # The shape that actually recurs: the directories exist and the corpus is
    # gone. `self_test_main` probes the bare tree; this probes the skeleton,
    # because "the tree is not there" and "the rules are not there" are
    # different questions and a gate can answer them differently.
    skeleton_refused, detail = refuses_an_empty_tree(Path(__file__).name, ["--check"], shape=SKELETON)
    results.append((f"refuses a tree whose directories exist and hold no rules ({detail.splitlines()[0]})", skeleton_refused))
    return results


def _with_decisions(translation: Any, decisions: dict[str, Any], specs: Any, windowed: Any, engine_ids: Any, family: Any) -> list[str]:
    original = translation.DECISIONS
    try:
        translation.DECISIONS = decisions
        return check(translation, specs, windowed, engine_ids, family)
    finally:
        translation.DECISIONS = original


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="enforce (the default; accepted so CI can be explicit)")
    parser.add_argument("--list", action="store_true", help="print every decision")
    parser.add_argument("--self-test", action="store_true", help="prove the gate catches each violation it claims to")
    args = parser.parse_args()

    fields_gate = _load_sibling("check_detection_fields")
    translation = _load_sibling("windowed_translation")
    sys.path.insert(0, str(ROOT / "scripts"))
    from detection_specs_index import all_specs  # noqa: PLC0415

    specs = {f"{category}/{spec['slug']}": (category, spec) for category, spec in all_specs()}
    windowed = _read_rules(WINDOWED, "windowed ruleset")
    engine_ids = {str(rule.get("id")) for rule in _read_rules(RULESET, "detection ruleset")}
    family = windowed_family(fields_gate)

    if args.self_test:
        return self_test_main(
            Path(__file__).name,
            ["--check"],
            extra=_self_test_injections(translation, specs, windowed, engine_ids, family),
        )

    if args.list:
        for key, decision in translation.DECISIONS.items():
            if isinstance(decision, translation.Translation):
                wd_id = decision.wd_id or f"wd-{key.split('/', 1)[1]}"
                print(f"TRANSLATED  {key} -> {wd_id}")
            elif isinstance(decision, translation.Covered):
                print(f"COVERED     {key} -> {decision.by}")
            else:
                print(f"REFUSED     {key} [{decision.kind}] {decision.reason.splitlines()[0]}")
        return 0

    problems = check(translation, specs, windowed, engine_ids, family)

    translated = sum(1 for d in translation.DECISIONS.values() if isinstance(d, translation.Translation))
    refused = sum(1 for d in translation.DECISIONS.values() if isinstance(d, translation.Refusal))
    covered = sum(1 for d in translation.DECISIONS.values() if isinstance(d, translation.Covered))
    # Zero undecided is the state this gate exists to hold, not a sign it
    # found nothing: every rule of the family has left the stateless corpus
    # for a windowed rule or a refusal, so the only way the first figure moves
    # is somebody writing a new rule with a counter in its clauses.
    print(f"windowed translation: {len(family)} undecided det-* rules need a window, {len(translation.DECISIONS)} decided")
    print(f"  {translated} translated into wd-* rules")
    print(f"  {covered} covered by a windowed rule that already ships")
    print(f"  {refused} refused with a reason")
    kinds: dict[str, int] = {}
    for decision in translation.DECISIONS.values():
        if isinstance(decision, translation.Refusal):
            kinds[decision.kind] = kinds.get(decision.kind, 0) + 1
    for kind, count in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print(f"      {count:4d} {kind}")

    unemitted = _unemitted_entities(fields_gate, windowed)
    print(f"  {len(unemitted)} of {len(windowed)} windowed rules group by a field outside the static namespace (reported, not gated)")
    for rule_id, missing in unemitted:
        print(f"      {rule_id}: {', '.join(missing)}")

    unreachable = unreachable_windowed(fields_gate, windowed)
    print(f"  {len(unreachable)} windowed rules select on a computed field — cannot fire (ceiling {MAX_UNREACHABLE_WINDOWED})")
    for rule_id, computed in unreachable:
        print(f"      {rule_id}: {', '.join(computed)}")
    if len(unreachable) > MAX_UNREACHABLE_WINDOWED:
        problems.append(
            f"{len(unreachable)} windowed rules select on a computed field, over the ceiling of "
            f"{MAX_UNREACHABLE_WINDOWED}. Build the enrichment or refuse the rule; never raise the ceiling."
        )

    if problems:
        print(f"\nERROR: {len(problems)} problem(s):", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("\nOK: every det-* rule that needs a window is translated or refused with a reason")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
