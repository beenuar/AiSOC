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

**Scope: native rules only.** This reads `detection_ruleset.json` and not the
imported ruleset beside it, which is deliberate rather than an oversight.
Imported rules are held to a stronger standard than this gate can apply:
`scripts/compile_sigma_ruleset.py` replays each one, as a vendor-shaped event,
through the real connector and the real engine, and ships it only if it fires.
That is direct evidence where this file has only static approximation, so
adding them here would substitute a weaker check for a stronger one.

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

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()
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
# 133 before parity 5.5, which closed the 15-rule per-tenant-allowlist
# family by deriving the booleans from the tenant overlay. 14 rules moved
# (one rule carried two clauses), leaving the four families that genuinely
# need engine or enrichment work.
#
# 119 before depth plan 3.1, which decided all 74 rules of the windowed
# family: 50 became `wd-*` rules replayed through the real engine, and 24
# were refused with a reason and stopped being published as executable
# (`scripts/windowed_translation.py`, gated by
# `scripts/check_windowed_translation.py`). Two of the 74 carried a second
# clause as well, which is why the identity-enrichment family moved from 24
# to 22 and the comparison family from 8 to 7.
#
# 45 before depth plan 3.3, which closed the rest in four steps and left two:
#   * five rules were never unreachable — this gate's operator list had not
#     been given `neq` when the matcher was, so `approver_role_neq` was read
#     as a field name rather than as `approver_role` with `!=`;
#   * 18 rules now resolve their `*_priv` booleans from the tenant's own
#     directory import (`tenant_overlay.IDENTITY_FIELDS`);
#   * 2 resolve from the per-tenant first-seen store (`first_seen.py`);
#   * 18 are retired with a reason in `scripts/enrichment_decisions.py`,
#     gated by `scripts/check_enrichment_decisions.py`, which refuses to let
#     a rule whose fields *are* resolvable be retired to move this number.
#
# The two that remain both need the behavioural baseline of depth plan 3.4.
MAX_UNREACHABLE = 2

#: Fields that no telemetry carries because they are computed, not observed:
#: sliding-window counters, allowlist membership, privilege flags, and
#: actor/target comparisons. A rule naming one of these cannot fire no matter
#: which connector is attached, because nothing computes it.
#:
#: They need one of two things. The windowed family needs a `wd-*` rule in
#: `services/fusion/app/services/windowed_detection.py`; the rest need a
#: fusion-time enrichment step that resolves the predicate.
#:
#: This comment used to say the windowed engine "has three hardcoded rules
#: and no loader". That was true when written and has not been true since the
#: exporter landed: the engine loads `app/data/windowed_ruleset.json` on top
#: of its builtins, runs in the fusion consumer, and fires real alerts. The
#: stale half mattered, because it told a reader the engine was unusable when
#: the actual gap is narrower and more actionable — **nobody has translated
#: these `det-*` rules into windowed form.** The two corpora are disjoint:
#: not one of the `wd-*` ids appears in `detections/`, so building the engine
#: moved none of these rules off this list and the count did not move either.
#:
#: Migrating one means *authoring* a `wd-*` rule, not flipping a flag.
#: Parity 5.5 removed `_in_allowlist` from this pattern. It is no longer
#: a field nothing computes: `services/fusion/app/services/tenant_overlay.py`
#: derives it per tenant from the allowlists the console writes, and the
#: engine merges it into the match namespace before evaluating.
#:
#: Per tenant rather than in the shared derived-field pass, deliberately:
#: a global allowlist would make one tenant's exceptions apply to
#: everybody. An unconfigured allowlist contributes no key at all rather
#: than `False`, because a `not_in_allowlist` clause against a missing key
#: is true for every event, which is the negation-flips-on-absence failure
#: already recorded for the Sigma import.
_DERIVED_FIELD_PATTERN = re.compile(
    r"(_count$|^count_|_per_|time_window|_window_"
    r"|_priv$|_is_admin$|_is_dc$|_eq_|_neq|^is_"
    r"|_age_days$|_age_hours$|_ratio$|_percent$"
    r"|^active_|_baseline|_is_first_|_seen_before$|_deviation)"
)

#: Operator suffixes the matcher strips to recover the field name. Order
#: matters: longer suffixes must be tried first so `not_contains_any` is not
#: shortened to `contains_any`. Mirrors `OPERATORS` in
#: `services/fusion/app/services/detection_matcher.py`, and
#: `services/fusion/tests/test_detection_matcher_parity.py` asserts the two
#: lists agree in **both** directions.
#:
#: They did not. `neq` was added to the matcher and not here, so five rules
#: whose clauses the engine reads correctly as `<field>` + `!=` were reported
#: by this gate as naming a field called `<field>_neq` — unreachable,
#: ratcheted, and fine all along. A list that mirrors another and is checked
#: in one direction only drifts in exactly the direction things change.
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
    "neq",
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


#: Fields the engine derives at match time from an event it already has.
#: `services/fusion/app/services/derived_fields.py` computes them, so a rule
#: matching on one is reachable even though no connector emits it.
#:
#: Named here rather than imported, for the reason the rest of this file is
#: parsed rather than imported: a field-coverage gate that needs the fusion
#: package installed is a gate that gets disabled the first time an import
#: breaks.
_DERIVED_TIME_FIELDS = frozenset({"is_business_hours", "is_after_hours", "is_weekend"})

#: Booleans the **tenant overlay** computes, from that tenant's own directory
#: import (`identity_nodes.privilege_tier`). Depth plan 3.3.
#:
#: Named here rather than pattern-matched on `_priv$`, because four booleans
#: in the same family are deliberately *not* computed — `scope_priv`,
#: `act_as_user_priv`, `gpo_link_priv` and `account_is_dc` have no subject
#: field any source emits. A pattern would have swept those in and reported
#: four rules reachable that are not.
#:
#: `services/fusion/tests/test_tenant_tuning_overlay.py` asserts this set and
#: `tenant_overlay.IDENTITY_FIELDS` agree in both directions, so the list
#: cannot drift the way the operator list below did.
_TENANT_DERIVED_FIELDS = frozenset(
    {
        "user_priv",
        "target_user_priv",
        "role_priv",
        "actor_role_priv",
        "actor_is_admin",
    }
)

#: Booleans and ages the **first-seen store** computes
#: (`services/fusion/app/services/first_seen.py`). Depth plan 3.3.
#:
#: Only observation-shaped subjects are here. `domain_age_days`,
#: `key_age_days` and the other ages-of-a-thing are not, and will not be:
#: answering "how old is this domain" with "when did we first see it" would
#: fire a newly-registered-domain rule on most of the internet.
#: `services/fusion/tests/test_first_seen.py` asserts this set and the
#: store's own tables agree in both directions.
_FIRST_SEEN_DERIVED_FIELDS = frozenset(
    {
        "publisher_ip_seen_before",
        "device_fingerprint_seen_before",
        "session_age_hours",
    }
)

#: `<left>_eq_<right>` / `<left>_neq_<right>`, resolved by comparing two
#: fields of the same event. Reachable only when *both* sides are in the
#: namespace — a comparison against a field nothing emits is still dead, and
#: counting it as covered would be the fake-gate failure this file exists to
#: prevent.
_DERIVED_COMPARISON_RE = re.compile(r"^(?P<left>.+?)_(?:eq|neq)_(?P<right>.+)$")


def _is_derivable(field: str, namespace: set[str]) -> bool:
    """True when the engine can compute this field from what it already has."""
    if field in _DERIVED_TIME_FIELDS or field in _TENANT_DERIVED_FIELDS or field in _FIRST_SEEN_DERIVED_FIELDS:
        return True
    match = _DERIVED_COMPARISON_RE.match(field)
    if not match:
        return False
    return match.group("left") in namespace and match.group("right") in namespace


#: What each unreachable field would need, so the headline number is
#: actionable rather than a bare count. "133 rules are dead" invites
#: someone to delete 133 rules; "73 need the windowed evaluator, 24 need
#: identity enrichment" names four pieces of work.
#:
#: Ordered: first match wins, so the more specific patterns come first.
_FIELD_FAMILIES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "windowed evaluator",
        re.compile(r"_count$|^count_|_per_|time_window|_window_|_5min|_ratio$"),
    ),
    ("identity enrichment", re.compile(r"_priv$|_is_admin$|_is_dc$")),
    ("per-tenant allowlist", re.compile(r"_in_allowlist$|_not_in_allowlist$")),
    ("age / first-seen enrichment", re.compile(r"_age_days$|_age_hours$|_seen_before$")),
    ("behavioural baseline", re.compile(r"_baseline|_deviation|^active_|_is_first_")),
    (
        # Both operands invented by the rule author. Distinct from the rest:
        # the engine can compute a comparison, it just cannot compare two
        # fields that do not exist. This is content work, not engine work.
        "comparison over fields nothing emits",
        _DERIVED_COMPARISON_RE,
    ),
)


def _family(field: str) -> str:
    for name, pattern in _FIELD_FAMILIES:
        if pattern.search(field):
            return name
    return "other"


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
        missing = {f for f in _rule_fields(rule.get("match_when") or {}) if f not in namespace and not _is_derivable(f, namespace)}
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
    families: dict[str, int] = {}
    for _rule_id, fields in derived:
        for name in {_family(f) for f in fields}:
            families[name] = families.get(name, 0) + 1
    for name, count in sorted(families.items(), key=lambda kv: -kv[1]):
        print(f"      {count:4d} need {name}")
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
        print(f"\nThe ratchet can be tightened: lower MAX_UNREACHABLE to {len(derived)} in scripts/check_detection_fields.py.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
