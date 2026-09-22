#!/usr/bin/env python3
"""CI gate: a detection rule must match on fields some connector actually emits.

The detection matcher does a plain `event.get(field)` against the flat,
connector-normalized dict recovered from `raw_data`. There is no dotted-path
traversal and no aliasing. So a rule that names a field no connector ever
produces reads `None`, fails its first clause, and can never fire — while
still being loaded by the engine, still passing fixture replay, and still
counting toward the published executable total.

It passes fixture replay because fixtures are *synthesized from the rule*:
`build_positive(when)` in `scripts/detection_specs_part3_helpers.py` derives a
field value from the operator in the clause, so replaying it against the same
`match_when` is a tautology. The fixture gate proves the matcher works. It says
nothing about whether the field exists.

This gate closes that hole. It collects the field namespace connectors emit and
reports any rule that references something outside it.

Because the namespace is recovered by static analysis rather than by running
every connector, it deliberately **over**-approximates: every string-literal
dict key in a connector module counts as emitted. A false pass is a rule this
gate failed to catch; a false failure would be a rule wrongly blocked. Given
the gate's job is to stop regressions rather than to prove the corpus clean,
over-approximating is the safe direction.

Ratchet, not a clean bill of health. The corpus already contains unreachable
rules, and blocking CI on all of them would either stop every unrelated PR or
invite someone to weaken the gate. `MAX_UNREACHABLE` pins the current count so
it can only go down, exactly like `scripts/check_claim_gate_matrix.py`.

Usage:
    python3 scripts/check_detection_fields.py             # enforce the ratchet
    python3 scripts/check_detection_fields.py --list      # name every rule
    python3 scripts/check_detection_fields.py --fields    # dump the namespace
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULESET = ROOT / "services" / "fusion" / "app" / "data" / "detection_ruleset.json"
CONNECTORS = ROOT / "services" / "connectors" / "app" / "connectors"
#: The AI SDK is a first-party emitter too — it posts spans straight to an
#: inbox token, so the fields it produces are as real as a connector's.
AI_SDK = ROOT / "packages" / "aisoc-ai-sdk" / "aisoc_ai"
TEMPLATES = ROOT / "services" / "ingest" / "internal" / "normalizer" / "templates"
NORMALIZER = ROOT / "services" / "ingest" / "internal" / "normalizer" / "normalizer.go"

#: Current number of engine-loaded rules that depend on a DERIVED or STATEFUL
#: field. This may only ever decrease. Lower it in the same PR that fixes
#: rules; never raise it to make a red build green.
MAX_UNREACHABLE = 138

#: Fields that no telemetry carries because they are computed, not observed:
#: sliding-window counters, allowlist membership, privilege flags, and
#: actor/target comparisons. A rule naming one of these cannot fire no matter
#: which connector is attached, because nothing computes it.
#:
#: They need one of two things that do not exist yet: evaluation in
#: `services/fusion/app/services/windowed_detection.py` (which has three
#: hardcoded rules and no loader), or a fusion-time enrichment step that
#: resolves the predicate. Until then they are honest work items.
_DERIVED_FIELD_PATTERN = re.compile(
    r"(_count$|^count_|_per_|time_window|_window_"
    r"|_in_allowlist$|_not_in_allowlist$"
    r"|_priv$|_is_admin$|_is_dc$|_eq_|_neq|^is_"
    r"|_age_days$|_age_hours$|_ratio$|_percent$"
    r"|^active_|_baseline|_is_first_|_seen_before$|_deviation)"
)

#: Operator suffixes the matcher strips to recover the field name. Order
#: matters: longer suffixes must be tried first so `not_contains_any` is not
#: shortened to `contains_any`. Mirrors `OPERATORS` in
#: `services/fusion/app/services/detection_matcher.py`.
_OPERATOR_SUFFIXES = (
    "not_contains_any",
    "not_startswith_any",
    "not_endswith_any",
    "not_startswith",
    "not_endswith",
    "contains_any",
    "contains_all",
    "pattern_match_any",
    "pattern_match",
    "startswith_any",
    "startswith",
    "endswith_any",
    "endswith",
    "match_any",
    "has_any",
    "not_in",
    "contains",
    "match",
    "gte",
    "lte",
    "in",
    "gt",
    "lt",
)

#: Fields the platform synthesizes rather than a connector emitting them:
#: fusion enrichment, the windowed engine's counters, and OCSF top-level keys
#: the engine falls back to when `raw_data` is absent.
_PLATFORM_FIELDS = frozenset(
    {
        "severity",
        "severity_id",
        "class_uid",
        "category_uid",
        "activity_id",
        "connector_type",
        "source",
        "tenant_id",
        "event_time",
        "time",
        "message",
        "raw_data",
        "raw_event",
        "title",
        "description",
        "external_id",
        "created_at",
    }
)


def _strip_operator(key: str) -> str:
    for suffix in _OPERATOR_SUFFIXES:
        if key.endswith("_" + suffix):
            return key[: -len(suffix) - 1]
    return key


def _rule_fields(match_when: dict) -> set[str]:
    """Field names a `match_when` clause reads, descending into any_of/all_of."""
    found: set[str] = set()
    for key, value in match_when.items():
        if key in {"any_of", "all_of"}:
            if isinstance(value, list):
                for sub in value:
                    if isinstance(sub, dict):
                        found |= _rule_fields(sub)
            continue
        found.add(_strip_operator(key))
    return found


def _connector_namespace() -> set[str]:
    """Every string-literal dict key appearing in a connector module.

    Static over-approximation, by design: see the module docstring. Parsing the
    AST rather than regexing means a key split across lines or built with an
    f-string prefix is still picked up as a literal where one exists.
    """
    namespace: set[str] = set(_PLATFORM_FIELDS)
    sources = list(CONNECTORS.rglob("*.py"))
    if AI_SDK.is_dir():
        sources += list(AI_SDK.rglob("*.py"))
    for path in sorted(sources):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key in node.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str):
                        namespace.add(key.value)
            # `d["key"] = v` and `d.get("key")` also declare a field name.
            elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
                if isinstance(node.slice.value, str):
                    namespace.add(node.slice.value)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"get", "pop", "setdefault"} and node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        namespace.add(first.value)
    return namespace


def _template_namespace() -> set[str]:
    """Source field names declared by inbox webhook templates.

    Read as text rather than with a YAML parser so this script has no
    third-party dependency; the shape is a flat `a.b.c: x.y.z` mapping.
    """
    namespace: set[str] = set()
    if not TEMPLATES.is_dir():
        return namespace
    for path in sorted(TEMPLATES.glob("*.yaml")):
        for line in path.read_text(encoding="utf-8").split("\n"):
            match = re.match(r"^\s{2,}([A-Za-z0-9_.]+)\s*:", line)
            if match:
                # Both ends of the mapping are legitimate field names: the left
                # is what arrives, the right is what the rule may match on.
                namespace.add(match.group(1).split(".")[-1])
                namespace.add(match.group(1))
    return namespace


def _go_normalizer_namespace() -> set[str]:
    """Field names the Go OCSF normalizer maps, from its connectorProfiles."""
    namespace: set[str] = set()
    if not NORMALIZER.exists():
        return namespace
    for match in re.finditer(r'"([A-Za-z0-9_.]+)"\s*:\s*"([A-Za-z0-9_.]+)"', NORMALIZER.read_text(encoding="utf-8")):
        for side in match.groups():
            namespace.add(side)
            namespace.add(side.split(".")[-1])
    return namespace


def scan() -> tuple[list[tuple[str, list[str]]], list[tuple[str, list[str]]], set[str], int]:
    """Returns (derived-field rules, vendor-field rules, namespace, total).

    Two classes, and only the first is a hard failure.

    **Derived / stateful** — the field is computed, not observed. No connector
    can ever supply it, so the rule is broken regardless of deployment. These
    are ratcheted.

    **Vendor payload** — the field is a real vendor key nested under
    `raw_event`. `DetectionEngine._raw_fields` merges that payload into the
    match namespace, so these are reachable whenever the attached vendor sends
    the field. Whether any given deployment does cannot be known statically,
    so these are reported for visibility rather than gated: failing on them
    would block correct rules for vendors nobody has connected yet.
    """
    if not RULESET.exists():
        print(f"ERROR: {RULESET.relative_to(ROOT)} missing — run scripts/export_detection_ruleset.py", file=sys.stderr)
        raise SystemExit(2)

    namespace = _connector_namespace() | _template_namespace() | _go_normalizer_namespace()
    rules = json.loads(RULESET.read_text(encoding="utf-8")).get("rules") or []

    derived: list[tuple[str, list[str]]] = []
    vendor: list[tuple[str, list[str]]] = []
    for rule in rules:
        missing = {f for f in _rule_fields(rule.get("match_when") or {}) if f not in namespace}
        if not missing:
            continue
        rule_id = str(rule.get("id", "?"))
        computed = sorted(f for f in missing if _DERIVED_FIELD_PATTERN.search(f))
        if computed:
            derived.append((rule_id, computed))
        else:
            vendor.append((rule_id, sorted(missing)))
    return derived, vendor, namespace, len(rules)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="name every unreachable rule")
    parser.add_argument("--fields", action="store_true", help="dump the emitted field namespace")
    parser.add_argument(
        "--max-unreachable",
        type=int,
        default=MAX_UNREACHABLE,
        help=f"ratchet ceiling (default {MAX_UNREACHABLE})",
    )
    args = parser.parse_args()

    derived, vendor, namespace, total = scan()

    if args.fields:
        for name in sorted(namespace):
            print(name)
        return 0

    if args.list:
        print("# rules depending on a derived/stateful field (gated)")
        for rule_id, missing in derived:
            print(f"{rule_id}: {', '.join(missing)}")
        print("\n# rules depending on a vendor-payload field (informational)")
        for rule_id, missing in vendor:
            print(f"{rule_id}: {', '.join(missing)}")
        return 0

    print(f"detection fields: {total} engine rules examined")
    print(f"  {len(derived)} depend on a derived/stateful field — cannot fire on any connector (gated)")
    print(f"  {len(vendor)} reference a vendor-payload field — reachable when that vendor is attached")

    if len(derived) > args.max_unreachable:
        print(
            f"\nERROR: {len(derived)} rules depend on a computed field, over the ratchet "
            f"ceiling of {args.max_unreachable}.\n"
            "Such a field is never present in telemetry, so the rule cannot fire whatever\n"
            "is connected. Fixture replay will not catch it, because fixtures are\n"
            "synthesized from the rule being tested.\n"
            "Run with --list to see which. The fix is either a windowed-engine rule or a\n"
            "fusion-time enrichment that actually computes the predicate.",
            file=sys.stderr,
        )
        return 1

    if len(derived) < args.max_unreachable:
        print(f"\nThe ratchet can be tightened: lower MAX_UNREACHABLE to {len(derived)} " "in scripts/check_detection_fields.py.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
