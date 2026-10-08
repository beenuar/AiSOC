#!/usr/bin/env python3
"""Every connector type names an OCSF class, or says why it does not.

Why this exists
---------------
``should_promote()`` in ``services/fusion/app/services/promoter.py`` promotes
an event to an alert when it is OCSF **category 2** (Findings) *or* its
``severity_id`` is at least 4. The category is the class uid divided by a
thousand, so the class a connector's events carry decides whether its routine
telemetry reaches an analyst's queue or stays in the lake.

Before the table this gate reads, 72 of the 84 declared connector types had no
class of their own. They fell to the ``2001`` Security Finding default inside
``canonicalProfile()`` — category 2, therefore **always promoted** — and that
default was invisible: nothing named it, nothing counted it, and no reviewer
saw a list of the sources it covered.

For the connectors whose ``fetch_alerts`` really does return the vendor's own
findings, 2001 is right. For the ones returning raw telemetry it meant every
permitted DNS lookup, every allowed proxy request, every accepted VPC flow
record and every routine Windows event became an alert carrying severity
``info`` — fusion's alert-reduction property inverted, for the sources that
emit the most volume. Reproduced on the pre-fix tree by
``TestRoutineTelemetryWasPromotedBeforeTheClassTable`` in the normalizer's own
suite.

What it checks
--------------
Two directions, because a one-directional check is this repository's dominant
gate defect — it compares A against B, never B against A, so drift in the
direction things actually change slips past while the gate prints OK.

  PY -> GO    every ``connector_id`` the connectors service declares has
              either a class mapping or a recorded reason it stays on the
              default. Neither is the failure this gate exists for.
  GO -> PY    every entry in the Go table names a connector that exists, no
              entry carries both a class and a reason, and no entry names a
              class uid absent from the service's own closed set.
  SCHEMA      every class in that closed set declares the category its uid
              implies, so a typo cannot change which promotion branch a
              connector's events take.
  PROMOTION   every class a connector is mapped to can actually promote: it
              is category 2, or the profile carrying it ships a severity map
              that reaches the floor of 4. A new class with an empty severity
              map is archived to the lake and never alerts, silently, which is
              exactly how the borrowed ``splunk_enterprise`` profile broke 26
              connectors.

It also reports the **count of connector types on the generic mapping**, which
is the figure the depth plan's Phase 2 is graded against, and holds it with
``--check`` against the committed number so it can only go down by a decision
somebody made rather than drift up by accident.

Usage
-----
    python3 scripts/check_ocsf_class_coverage.py              # gate
    python3 scripts/check_ocsf_class_coverage.py --check      # + drift on the count
    python3 scripts/check_ocsf_class_coverage.py --json
    python3 scripts/check_ocsf_class_coverage.py --self-test   # prove it bites

``--repo-root`` overrides the tree under inspection. The resolved root, every
file read and every count are printed before the verdict, and an empty read is
a hard error rather than a quiet zero.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this runs as a program but not when a test
# loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root

CLASSES_REL = Path("services/ingest/internal/normalizer/ocsf_classes.go")
NORMALIZER_REL = Path("services/ingest/internal/normalizer/normalizer.go")
CONNECTORS_REL = Path("services/connectors/app/connectors")

#: Connector types on the generic mapping, as committed. The figure the depth
#: plan grades Phase 2 against, so it lives in code with a drift gate rather
#: than in prose that goes stale silently.
#:
#: 72 at capture (commit ee33b02f): 84 declared, and only 12 with a class of
#: their own — 8 through a hand-written profile and 4 more through the
#: five-entry override map this table replaced. It may fall as connectors are
#: classified. It may **not** rise: a new connector arrives with a decision or
#: the gate fails, which is the whole point of counting it.
#:
#: The number that must stay at zero is `unclassified`, which is a hard
#: failure rather than a ceiling: every one of the 42 below carries a reason.
MAX_GENERIC = 42

#: OCSF categories whose events fusion promotes unconditionally.
FINDINGS_CATEGORY = 2

#: The severity_id floor the promoter applies to everything else.
PROMOTE_SEVERITY_FLOOR = 4


class GateError(RuntimeError):
    """An input could not be read. Never downgraded to a passing result."""


# --------------------------------------------------------------------------
# Go side
# --------------------------------------------------------------------------
def _go_block(src: str, header: str) -> str:
    """The brace-balanced literal following `header`."""
    start = src.find(header)
    if start == -1:
        raise GateError(f"could not find `{header}`")
    depth, i = 0, src.index("{", start)
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    raise GateError(f"unbalanced braces after `{header}`")


def parse_class_consts(src: str) -> dict[str, int]:
    """Go constant name -> uid, from the const block."""
    return {name: int(uid) for name, uid in re.findall(r"^\t(class\w+)\s*=\s*(\d+)$", src, re.MULTILINE)}


def parse_classes(src: str, consts: dict[str, int]) -> dict[int, tuple[str, int]]:
    """uid -> (caption, declared category), from `ocsfClasses`."""
    block = _go_block(src, "var ocsfClasses = map[int]ocsfClass{")
    out: dict[int, tuple[str, int]] = {}
    for key, uid_ref, caption, category in re.findall(r'^\t(class\w+):\s*\{(class\w+),\s*"([^"]+)",\s*(\d+)\},?$', block, re.MULTILINE):
        if key not in consts:
            raise GateError(f"ocsfClasses keys off {key!r}, which the const block does not declare")
        if uid_ref != key:
            raise GateError(f"ocsfClasses row {key!r} carries uid {uid_ref!r}; a row must describe its own key")
        out[consts[key]] = (caption, int(category))
    return out


def parse_connector_classes(src: str, consts: dict[str, int]) -> dict[str, dict]:
    """connector type -> {"class_uid": int|None, "reason": str|None}."""
    block = _go_block(src, "var connectorOCSFClass = map[string]connectorClass{")
    out: dict[str, dict] = {}
    for name, body in re.findall(r'^\t"([a-z0-9_]+)":\s*\{([^}]*)\},?$', block, re.MULTILINE):
        class_match = re.search(r"classUID:\s*(class\w+)", body)
        reason_match = re.search(r'genericReason:\s*"([^"]*)"', body)
        class_uid = None
        if class_match:
            key = class_match.group(1)
            if key not in consts:
                raise GateError(f"connector {name!r} names class constant {key!r}, which is not declared")
            class_uid = consts[key]
        out[name] = {"class_uid": class_uid, "reason": reason_match.group(1) if reason_match else None}
    return out


def parse_profile_classes(src: str) -> dict[str, dict]:
    """profile key -> {"class_uid", "class_name", "severity_promotes"}.

    ``severity_promotes`` answers the question the promoter asks: can any
    value in this profile's severity map reach the floor of 4? A profile whose
    map is empty, or tops out at 3, cannot promote a non-finding event however
    severe the vendor thought it was. Shared-ladder references are resolved
    rather than treated as unknown, because the whole point of naming the
    shared ladder was that a reader can see what it contains.
    """
    block = _go_block(src, "var connectorProfiles = map[string]connectorProfile{")
    shared = {
        name: [int(v) for v in re.findall(r":\s*(\d+)", _go_block(src, f"var {name} = map[string]int{{"))]
        for name in re.findall(r"var (_\w*[Ss]everityMap) = map\[string\]int\{", src)
    }
    out: dict[str, dict] = {}
    for match in re.finditer(r'^\t"([a-z0-9_]+)":\s*\{$', block, re.MULTILINE):
        key = match.group(1)
        entry = _go_block(block, match.group(0))
        class_match = re.search(r"classUID:\s*(\d+)", entry)
        if not class_match:
            raise GateError(f"profile {key!r} declares no classUID")
        name_match = re.search(r'className:\s*"([^"]+)"', entry)
        ref = re.search(r"severityMap:\s*(_\w+),", entry)
        if ref:
            values = shared.get(ref.group(1))
            if values is None:
                raise GateError(f"profile {key!r} references severity map {ref.group(1)!r}, which is not declared")
        else:
            sev_block = re.search(r"severityMap:\s*map\[string\]int\{(.*?)\}", entry, re.DOTALL)
            values = [int(v) for v in re.findall(r":\s*(\d+)", sev_block.group(1))] if sev_block else []
        out[key] = {
            "class_uid": int(class_match.group(1)),
            "class_name": name_match.group(1) if name_match else None,
            "severity_promotes": any(v >= PROMOTE_SEVERITY_FLOOR for v in values),
        }
    return out


def parse_canonical_severity_promotes(src: str) -> bool:
    """Whether the ladder every canonical envelope uses can reach the floor."""
    block = _go_block(src, "var _canonicalSeverityMap = map[string]int{")
    return any(int(v) >= PROMOTE_SEVERITY_FLOOR for v in re.findall(r":\s*(\d+)", block))


# --------------------------------------------------------------------------
# Python side
# --------------------------------------------------------------------------
def parse_declared_connectors(directory: Path) -> set[str]:
    """Every `connector_id` the connectors service declares."""
    out: set[str] = set()
    for path in sorted(directory.glob("*.py")):
        if path.name in {"__init__.py", "base.py"}:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            for stmt in cls.body:
                # The value is bound in each branch rather than read off
                # `stmt` afterwards: past the if/elif the name is still an
                # `ast.stmt`, which has no `.value`, so the later read was
                # four unchecked attribute accesses that happened to be safe.
                if isinstance(stmt, ast.Assign):
                    target = next((getattr(t, "id", None) for t in stmt.targets), None)
                    value: ast.expr | None = stmt.value
                elif isinstance(stmt, ast.AnnAssign):
                    target = getattr(stmt.target, "id", None)
                    value = stmt.value
                else:
                    continue
                if target == "connector_id" and isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                    out.add(value.value)
    return out


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------
def evaluate(
    declared: set[str],
    classes: dict[int, tuple[str, int]],
    connector_classes: dict[str, dict],
    profiles: dict[str, dict],
    canonical_severity_promotes: bool,
    max_generic: int,
    check_count: bool,
) -> tuple[list[tuple[str, str]], dict]:
    failures: list[tuple[str, str]] = []

    # SCHEMA. A uid whose declared category disagrees with uid/1000 would
    # change which promotion branch a connector's events take.
    for uid, (caption, category) in sorted(classes.items()):
        if uid // 1000 != category:
            failures.append(
                (
                    "class-category-mismatch",
                    f"class {uid} ({caption}) declares category {category}, but uid/1000 is {uid // 1000}; "
                    "fusion derives the category from the uid, so the two cannot differ",
                )
            )

    # GO -> PY. Every entry names something real and says exactly one thing.
    for name, entry in sorted(connector_classes.items()):
        if name not in declared:
            failures.append(("class-names-nothing", f"connectorOCSFClass names {name!r}, which no connector declares"))
        if entry["class_uid"] is None and not entry["reason"]:
            failures.append(("class-entry-empty", f"{name!r} has an entry carrying neither a class nor a reason"))
        if entry["class_uid"] is not None and entry["reason"]:
            failures.append(
                (
                    "class-entry-ambiguous",
                    f"{name!r} declares both a class and a generic reason; one of them is not what happens",
                )
            )
        if entry["class_uid"] is not None and entry["class_uid"] not in classes:
            failures.append(
                (
                    "class-uid-unknown",
                    f"{name!r} maps to class uid {entry['class_uid']}, which is not in the service's closed set",
                )
            )
        if entry["reason"] and len(entry["reason"]) < 15:
            failures.append(
                (
                    "class-reason-thin",
                    f"{name!r} stays generic for the reason {entry['reason']!r}, which does not say enough "
                    "for a reviewer to disagree with it",
                )
            )

    # PY -> GO. The direction the defect lived in: a declared connector with
    # no decision at all, reaching the default silently.
    generic: list[str] = []
    for name in sorted(declared):
        decision = connector_classes.get(name)
        if decision is None:
            failures.append(
                (
                    "connector-unclassified",
                    f"connector {name!r} has no OCSF class and no recorded reason: its events take the 2001 "
                    "Security Finding default, which is category 2 and therefore always promoted, and nothing "
                    "says that was a decision",
                )
            )
            generic.append(name)
        elif decision["class_uid"] is None:
            generic.append(name)

    # PROMOTION. A class a connector is mapped to must be able to promote.
    for name, entry in sorted(connector_classes.items()):
        uid = entry["class_uid"]
        if uid is None or uid not in classes:
            continue
        if uid // 1000 == FINDINGS_CATEGORY:
            continue
        # A connector with its own profile carries that profile's ladder; one
        # on the canonical path carries the shared ladder.
        promotes = profiles[name]["severity_promotes"] if name in profiles else canonical_severity_promotes
        if not promotes:
            caption, _ = classes[uid]
            failures.append(
                (
                    "class-cannot-promote",
                    f"{name!r} maps to {uid} ({caption}), category {uid // 1000}, and the severity map it carries "
                    f"never reaches {PROMOTE_SEVERITY_FLOOR}: every one of its events would be archived to the lake "
                    "and never alert, silently",
                )
            )

    # A profile declaring a class the closed set does not know is the same
    # defect one layer over, and the profiles predate this table.
    for key, profile in sorted(profiles.items()):
        if profile["class_uid"] not in classes:
            failures.append(
                (
                    "profile-class-unknown",
                    f"profile {key!r} declares class {profile['class_uid']}, which is not in the closed set; "
                    "the gate cannot tell whether it can promote",
                )
            )
            continue
        # A profile carries the uid *and* the caption, written by hand and
        # side by side, which is how `microsoft_sentinel` came to declare uid
        # 2002 beside "Security Finding" — the caption of 2001. Both are
        # category 2, so promotion hid it, and every Sentinel event in the
        # lake disagreed with itself while a query filtering on 2002 pulled
        # incidents in among vulnerability findings.
        caption, _ = classes[profile["class_uid"]]
        if profile["class_name"] and profile["class_name"] != caption:
            failures.append(
                (
                    "profile-class-name-mismatch",
                    f"profile {key!r} declares class {profile['class_uid']} beside the name "
                    f"{profile['class_name']!r}; the schema calls that uid {caption!r}, so one of the two is "
                    "wrong and both travel onto every event",
                )
            )

    unclassified = sorted(n for n in generic if n not in connector_classes)
    stats = {
        "declared": len(declared),
        "with_class": sum(1 for e in connector_classes.values() if e["class_uid"] is not None and e["reason"] is None),
        "generic": len(generic),
        "generic_connectors": generic,
        "generic_with_reason": sorted(set(generic) - set(unclassified)),
        "unclassified": unclassified,
        "classes": len(classes),
    }

    if check_count and len(generic) > max_generic:
        failures.append(
            (
                "generic-count-grew",
                f"{len(generic)} connector types are on the generic mapping, above the committed ceiling of "
                f"{max_generic}. The ceiling is a debt balance, not a target: classify the new connector or "
                "record why it stays generic, rather than raising the number",
            )
        )
    return failures, stats


def load(root: Path) -> dict:
    classes_go = root / CLASSES_REL
    normalizer = root / NORMALIZER_REL
    connectors_dir = root / CONNECTORS_REL
    for path in (classes_go, normalizer, connectors_dir):
        if not path.exists():
            raise GateError(f"expected input does not exist: {path}")

    classes_src = classes_go.read_text(encoding="utf-8")
    normalizer_src = normalizer.read_text(encoding="utf-8")
    consts = parse_class_consts(classes_src)
    data = {
        "declared": parse_declared_connectors(connectors_dir),
        "classes": parse_classes(classes_src, consts),
        "connector_classes": parse_connector_classes(classes_src, consts),
        "profiles": parse_profile_classes(normalizer_src),
        "canonical_severity_promotes": parse_canonical_severity_promotes(normalizer_src),
    }
    # An empty parse means the format moved, not that the tree is clean.
    for name in ("declared", "classes", "connector_classes", "profiles"):
        if not data[name]:
            raise GateError(f"parsed zero {name} — refusing to report a clean tree from an empty read")
    if not data["canonical_severity_promotes"]:
        raise GateError(
            "_canonicalSeverityMap never reaches the promote floor — every canonical-envelope connector on a "
            "non-finding class would be unpromotable, so refusing to report on the mapping at all"
        )
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=repo_root())
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check", action="store_true", help="also fail when the generic-mapping count exceeds MAX_GENERIC")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects what it claims to")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test(args.repo_root.resolve())

    root = args.repo_root.resolve()
    try:
        data = load(root)
    except GateError as exc:
        print(f"check_ocsf_class_coverage: FAILED to read the tree: {exc}", file=sys.stderr)
        return 2

    failures, stats = evaluate(**data, max_generic=MAX_GENERIC, check_count=args.check)

    if args.json:
        print(
            json.dumps(
                {
                    "repo_root": str(root),
                    "max_generic": MAX_GENERIC,
                    **stats,
                    "failures": [{"code": c, "detail": d} for c, d in failures],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if failures else 0

    print(f"repo root        {root}")
    print(f"class table      {CLASSES_REL}  ({stats['classes']} OCSF classes, verified against schema.ocsf.io)")
    print(f"normalizer       {NORMALIZER_REL}  ({len(data['profiles'])} profiles)")
    print(f"connectors       {CONNECTORS_REL}  ({stats['declared']} declared connector ids)")
    print()
    print(f"class coverage   {stats['with_class']} with an OCSF class of their own")
    print(f"                 {stats['generic']} on the generic 2001 mapping (ceiling {MAX_GENERIC})")
    print(
        f"                   of those, {len(stats['generic_with_reason'])} with a recorded reason "
        f"and {len(stats['unclassified'])} with no decision at all"
    )
    if stats["generic_connectors"]:
        print(f"                 {', '.join(stats['generic_connectors'])}")
    print()
    if failures:
        print(f"FAIL — {len(failures)} finding(s):")
        for code, detail in failures:
            print(f"  [{code}] {detail}")
        return 1
    print("OK — every declared connector type names an OCSF class or records why it stays")
    print("     generic, every class can promote, and every uid matches its category.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def self_test(root: Path) -> int:
    """Inject each defect the gate claims to catch and require it to bite."""
    try:
        base = load(root)
    except GateError as exc:
        print(f"self-test: cannot read the tree: {exc}", file=sys.stderr)
        return 2

    clean, _ = evaluate(**base, max_generic=MAX_GENERIC, check_count=True)
    if clean:
        print("self-test: the unmodified tree already fails; fix that first", file=sys.stderr)
        for code, detail in clean:
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 1

    def mutate(**overrides) -> dict:
        data = {k: (v.copy() if hasattr(v, "copy") else v) for k, v in base.items()}
        for key, fn in overrides.items():
            fn(data[key])
        return data

    cases: list[tuple[str, str, dict, int]] = [
        (
            "PY -> GO: a declared connector with no class and no recorded reason",
            "connector-unclassified",
            mutate(declared=lambda s: s.add("acme_telemetry")),
            MAX_GENERIC,
        ),
        (
            "GO -> PY: a table entry naming a connector that does not exist",
            "class-names-nothing",
            mutate(connector_classes=lambda d: d.update({"acme_xdr_9000": {"class_uid": 4001, "reason": None}})),
            MAX_GENERIC,
        ),
        (
            "GO -> PY: an entry carrying both a class and a reason",
            "class-entry-ambiguous",
            mutate(connector_classes=lambda d: d.update({"okta": {"class_uid": 3002, "reason": "also stays generic somehow"}})),
            MAX_GENERIC,
        ),
        (
            "GO -> PY: an entry carrying neither",
            "class-entry-empty",
            mutate(connector_classes=lambda d: d.update({"okta": {"class_uid": None, "reason": None}})),
            MAX_GENERIC + 1,
        ),
        (
            "GO -> PY: a class uid outside the service's closed set",
            "class-uid-unknown",
            mutate(connector_classes=lambda d: d.update({"okta": {"class_uid": 9999, "reason": None}})),
            MAX_GENERIC,
        ),
        (
            "GO -> PY: a reason too thin to review",
            "class-reason-thin",
            mutate(connector_classes=lambda d: d.update({"splunk": {"class_uid": None, "reason": "noisy"}})),
            MAX_GENERIC + 1,
        ),
        (
            "SCHEMA: a class whose declared category disagrees with its uid",
            "class-category-mismatch",
            mutate(classes=lambda d: d.update({4003: ("DNS Activity", 6)})),
            MAX_GENERIC,
        ),
        (
            "PROMOTION: a non-finding class whose severity map cannot reach the floor",
            "class-cannot-promote",
            mutate(profiles=lambda d: d.update({"okta": {"class_uid": 3002, "class_name": "Authentication", "severity_promotes": False}})),
            MAX_GENERIC,
        ),
        (
            "PROMOTION: a profile declaring a class the closed set does not know",
            "profile-class-unknown",
            mutate(profiles=lambda d: d.update({"splunk": {"class_uid": 7777, "class_name": "Invented", "severity_promotes": True}})),
            MAX_GENERIC,
        ),
        (
            "SCHEMA: a profile whose class name contradicts its own class uid",
            "profile-class-name-mismatch",
            mutate(
                profiles=lambda d: d.update({"splunk": {"class_uid": 2002, "class_name": "Security Finding", "severity_promotes": True}})
            ),
            MAX_GENERIC,
        ),
        (
            "COUNT: the generic-mapping count rises above the committed ceiling",
            "generic-count-grew",
            mutate(declared=lambda s: s.add("acme_telemetry")),
            MAX_GENERIC,
        ),
    ]

    print(f"self-test against {root}")
    print(f"clean tree: 0 failures at MAX_GENERIC={MAX_GENERIC} (the baseline every case below perturbs)\n")
    ok = True
    for description, expected_code, data, ceiling in cases:
        found, _ = evaluate(**data, max_generic=ceiling, check_count=True)
        codes = {code for code, _ in found}
        caught = expected_code in codes
        ok &= caught
        print(f"  {'PASS' if caught else 'FAIL'}  {description}")
        print(f"        expected [{expected_code}]  got {sorted(codes) or 'nothing'}")

    # An empty tree must be refused, not reported clean.
    empty_refused = True
    try:
        load(Path("/nonexistent-tree-for-the-self-test"))
        empty_refused = False
    except GateError:
        pass
    ok &= empty_refused
    print(f"  {'PASS' if empty_refused else 'FAIL'}  TREE: a tree with no inputs is refused rather than reported clean")

    print()
    if not ok:
        print("self-test FAILED: the gate did not catch what it claims to catch")
        return 1
    print(f"self-test OK: {len(cases)} injected defects plus the empty-tree case, each caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
