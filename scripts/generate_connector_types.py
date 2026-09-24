#!/usr/bin/env python3
"""Generate the console's ``ConnectorType`` union from the connector registry.

Why this exists
---------------
``packages/types/src/connector.ts`` carried a hand-written union of
``connector_type`` values. Hand-maintenance is what let it drift: ten members
named nothing the platform could ingest, and ``ibm_qradar`` was the expensive
one — no connector declared it and no profile was keyed on it, so strict mode
rejected those events and lenient mode minted a vendor called "ibm_qradar", a
second alert source for the same QRadar deployment ``qradar`` already fed.

PR #811 corrected the members. It did not remove the mechanism, so this does:
the union is now derived from the registry that decides what the platform can
ingest, and ``--check`` fails when the committed file no longer matches.

What the union means
--------------------
"Every ``connector_type`` the ingest normalizer resolves", which is exactly
three sets, each read from its own source of truth:

  registry       ``_CONNECTOR_CLASSES`` in
                 ``services/connectors/app/connectors/__init__.py``, resolved
                 to ``cls.connector_id`` the same way ``_build_registry()``
                 does — through the class, never through the filename.
  profile        ``connectorProfiles`` keys in
                 ``services/ingest/internal/normalizer/normalizer.go``. Some
                 are longer legacy spellings a declared id reaches through
                 ``connectorTypeAliases`` (``crowdstrike`` ->
                 ``crowdstrike_falcon``); ``splunk_enterprise`` is reachable
                 only because the union carries it, which is why dropping it
                 would fail ``check_connector_profiles.py``.
  canonical-fold ``connectorTypeCanonical`` sources — alternate spellings the
                 normalizer folds onto a declared id before anything keys off
                 it. Generation must preserve these, not flatten them away:
                 the console still emits ``ibm_qradar`` and the fold is what
                 makes it arrive as ``qradar``.

That set is, by construction, the ``resolvable`` set
``scripts/check_connector_profiles.py`` computes, so the two gates now agree
on one definition instead of two.

Nothing here is positional
--------------------------
``scripts/generate_detections.py`` was not idempotent because it assigned
``det-{category}-{idx:03d}`` by position, so inserting anywhere but the end
moved every later id; it needed a committed lock file. This generator assigns
no identity at all. A member *is* its ``connector_id``, taken from the class,
and the output is a sorted set — so reordering the registry cannot change a
byte of the output and no lock file is required. ``tests/`` proves both
properties rather than asserting them here.

Identity comes from the class, not the filename
-----------------------------------------------
``scripts/generate_connector_docs.py`` derived a connector's identity from its
filename and produced thin duplicate pages for the six connectors whose files
are spelled with underscores, while the coverage gate reported 100%. Two
connectors in this tree would break the same way: ``jira_connector.py``
declares ``jira`` and ``tenable.py`` declares ``tenable_io``. This generator
reads ``connector_id`` off the class, which is what ``CONNECTOR_REGISTRY`` is
keyed by, and refuses a class with an empty or duplicate id exactly as
``_build_registry()`` does.

Usage
-----
    python3 scripts/generate_connector_types.py            # write outputs
    python3 scripts/generate_connector_types.py --check    # fail on drift
    python3 scripts/generate_connector_types.py --json
    python3 scripts/generate_connector_types.py --self-test

``--repo-root`` overrides the tree under inspection. The resolved root, every
file read and every count are printed before the verdict, and an empty parse
is a hard error rather than a quiet zero: a generator that reports a clean
tree it never opened is worse than no generator.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

REGISTRY_REL = Path("services/connectors/app/connectors/__init__.py")
CONNECTORS_REL = Path("services/connectors/app/connectors")
NORMALIZER_REL = Path("services/ingest/internal/normalizer/normalizer.go")
TS_OUT_REL = Path("packages/types/src/generated/connector-types.ts")
JSON_OUT_REL = Path("packages/types/src/generated/connector-types.json")
CONSUMER_REL = Path("packages/types/src/connector.ts")

#: Where each union member comes from, in the order a member is attributed to
#: the first source that claims it.
ORIGIN_REGISTRY = "registry"
ORIGIN_PROFILE = "profile"
ORIGIN_FOLD = "canonical-fold"


class GateError(RuntimeError):
    """An input could not be read. Never downgraded to a passing result."""


# --------------------------------------------------------------------------
# Registry (Python, via AST — no runtime import of the connectors package)
# --------------------------------------------------------------------------
def _registered_class_names(tree: ast.Module) -> list[str]:
    for node in tree.body:
        value = None
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == "_CONNECTOR_CLASSES":
            value = node.value
        elif isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "_CONNECTOR_CLASSES" for t in node.targets):
            value = node.value
        if isinstance(value, ast.Tuple):
            names = [e.id for e in value.elts if isinstance(e, ast.Name)]
            if len(names) != len(value.elts):
                raise GateError("_CONNECTOR_CLASSES contains an entry that is not a bare class name")
            return names
    raise GateError(f"could not find the _CONNECTOR_CLASSES tuple in {REGISTRY_REL}")


def _import_modules(tree: ast.Module) -> dict[str, str]:
    """Imported class name -> the module in app.connectors it comes from."""
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app.connectors."):
            for alias in node.names:
                out[alias.asname or alias.name] = node.module.split(".")[-1]
    return out


def _class_attribute(tree: ast.Module, class_name: str, attribute: str) -> str | None:
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == class_name):
        for stmt in cls.body:
            target = None
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = getattr(stmt.targets[0], "id", None)
            elif isinstance(stmt, ast.AnnAssign):
                target = getattr(stmt.target, "id", None)
            if target == attribute and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
                return stmt.value.value
    return None


def parse_registry(root: Path) -> dict[str, dict[str, str]]:
    """connector_id -> {class, module, name}, resolved as _build_registry() does."""
    registry_file = root / REGISTRY_REL
    connectors_dir = root / CONNECTORS_REL
    if not registry_file.exists():
        raise GateError(f"expected input does not exist: {registry_file}")

    init_tree = ast.parse(registry_file.read_text(encoding="utf-8"))
    modules = _import_modules(init_tree)
    out: dict[str, dict[str, str]] = {}
    for class_name in _registered_class_names(init_tree):
        module = modules.get(class_name)
        if module is None:
            raise GateError(f"{class_name} is in _CONNECTOR_CLASSES but is not imported from app.connectors.*")
        path = connectors_dir / f"{module}.py"
        if not path.exists():
            raise GateError(f"{class_name} is imported from app.connectors.{module}, which does not exist")
        tree = ast.parse(path.read_text(encoding="utf-8"))
        connector_id = _class_attribute(tree, class_name, "connector_id")
        # The same two refusals _build_registry() makes, for the same reasons.
        if not connector_id:
            raise GateError(f"connector class {class_name} has an empty connector_id; refusing to register")
        if connector_id in out:
            raise GateError(f"duplicate connector_id {connector_id!r} between {out[connector_id]['class']} and {class_name}")
        out[connector_id] = {
            "class": class_name,
            "module": f"{module}.py",
            "name": _class_attribute(tree, class_name, "connector_name") or "",
        }
    if not out:
        raise GateError("parsed zero connector ids — refusing to generate from an empty read")
    return out


# --------------------------------------------------------------------------
# Normalizer (Go, via brace-balanced literals)
# --------------------------------------------------------------------------
def _go_block(src: str, header: str) -> str:
    start = src.find(header)
    if start == -1:
        raise GateError(f"could not find `{header}` in {NORMALIZER_REL}")
    depth, i = 0, src.index("{", start)
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    raise GateError(f"unbalanced braces after `{header}` in {NORMALIZER_REL}")


def parse_normalizer(root: Path) -> tuple[set[str], dict[str, str], dict[str, str]]:
    """(profile keys, connectorTypeAliases, connectorTypeCanonical)."""
    path = root / NORMALIZER_REL
    if not path.exists():
        raise GateError(f"expected input does not exist: {path}")
    src = path.read_text(encoding="utf-8")

    profiles = set(re.findall(r'^\t"([^"]+)":\s*\{', _go_block(src, "var connectorProfiles = map[string]connectorProfile{"), re.MULTILINE))
    if not profiles:
        raise GateError("parsed zero connectorProfiles keys — refusing to generate from an empty read")

    def pairs(header: str) -> dict[str, str]:
        if header not in src:
            return {}
        return dict(re.findall(r'"([^"]+)":\s*"([^"]+)"', _go_block(src, header)))

    aliases = pairs("var connectorTypeAliases = map[string]string{")
    canonical = pairs("var connectorTypeCanonical = map[string]string{")
    return profiles, aliases, canonical


# --------------------------------------------------------------------------
# Payload
# --------------------------------------------------------------------------
def build_payload(registry: dict[str, dict[str, str]], profiles: set[str], aliases: dict[str, str], canonical: dict[str, str]) -> dict:
    """The union and its provenance. A pure function of the three inputs."""
    origins: dict[str, str] = {}
    for connector_id in registry:
        origins[connector_id] = ORIGIN_REGISTRY
    for key in sorted(profiles):
        origins.setdefault(key, ORIGIN_PROFILE)
    for alternate in sorted(canonical):
        origins.setdefault(alternate, ORIGIN_FOLD)

    members = sorted(origins)
    return {
        "members": members,
        "origins": {m: origins[m] for m in members},
        "canonical": dict(sorted(canonical.items())),
        "counts": {
            "total": len(members),
            ORIGIN_REGISTRY: sum(1 for m in members if origins[m] == ORIGIN_REGISTRY),
            ORIGIN_PROFILE: sum(1 for m in members if origins[m] == ORIGIN_PROFILE),
            ORIGIN_FOLD: sum(1 for m in members if origins[m] == ORIGIN_FOLD),
            "aliases": len(aliases),
        },
        "generatedFrom": [str(REGISTRY_REL), str(NORMALIZER_REL)],
        "regenerateWith": "python3 scripts/generate_connector_types.py",
    }


def render_json(payload: dict) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_typescript(payload: dict) -> str:
    members = payload["members"]
    origins = payload["origins"]
    canonical = payload["canonical"]
    counts = payload["counts"]

    lines: list[str] = [
        "// AUTO-GENERATED by scripts/generate_connector_types.py. Do not edit by hand.",
        "// Run `python3 scripts/generate_connector_types.py` and commit the result.",
        "//",
        "// Every `connector_type` the ingest normalizer resolves, derived from the",
        "// registry that decides what the platform can ingest:",
        "//",
        f"//   {counts[ORIGIN_REGISTRY]:>3}  connector ids declared in services/connectors (_CONNECTOR_CLASSES)",
        f"//   {counts[ORIGIN_PROFILE]:>3}  connectorProfiles keys no connector declares under that spelling",
        f"//   {counts[ORIGIN_FOLD]:>3}  alternate spellings connectorTypeCanonical folds onto a declared id",
        f"//   {counts['total']:>3}  total",
        "//",
        "// The union used to be written by hand, which is how ten members came to name",
        "// nothing: `ibm_qradar` reached no profile and no connector, so strict mode",
        '// rejected those events and lenient mode minted a vendor called "ibm_qradar" —',
        "// a second alert source for the QRadar deployment `qradar` already fed.",
        "",
        "/** Every `connector_type` value the ingest normalizer resolves. */",
        "export const CONNECTOR_TYPES = [",
    ]
    width = max(len(m) for m in members) + 2
    for member in members:
        literal = f'"{member}",'
        lines.append(f"  {literal:<{width + 1}} // {origins[member]}")
    lines += [
        "] as const;",
        "",
        "export type ConnectorType = (typeof CONNECTOR_TYPES)[number];",
        "",
        "/**",
        " * Alternate spellings the normalizer folds onto the id services/connectors",
        " * declares, before anything keys off it. Mirrors `connectorTypeCanonical` in",
        " * services/ingest/internal/normalizer/normalizer.go so the console can resolve",
        " * a stored value to one product name instead of two.",
        " */",
        "export const CONNECTOR_TYPE_CANONICAL: Readonly<Record<string, ConnectorType>> = {",
    ]
    for alternate, target in canonical.items():
        lines.append(f'  "{alternate}": "{target}",')
    lines += [
        "};",
        "",
        "/** Resolve an alternate spelling to the declared connector id. */",
        "export function canonicalConnectorType(connectorType: string): string {",
        "  return CONNECTOR_TYPE_CANONICAL[connectorType] ?? connectorType;",
        "}",
        "",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------
#: The consumer must re-export the generated union rather than redeclare it.
#: Without this rule the generated file can sit in the tree, current and
#: ignored, while a hand-written union three directories away is what
#: TypeScript actually resolves — the drift this change exists to end.
_REDECLARATION = re.compile(r"^\s*export\s+type\s+ConnectorType\s*=", re.MULTILINE)
_REEXPORT = re.compile(r"""export\s+type\s*\{[^}]*\bConnectorType\b[^}]*\}\s*from\s*["'][^"']*generated/connector-types["']""")


def evaluate(payload: dict, on_disk_ts: str | None, on_disk_json: str | None, consumer: str | None) -> list[tuple[str, str]]:
    failures: list[tuple[str, str]] = []

    if on_disk_ts is None:
        failures.append(("output-missing", f"{TS_OUT_REL} does not exist; run the generator"))
    elif on_disk_ts != render_typescript(payload):
        failures.append(("output-drifted", f"{TS_OUT_REL} is not what generation produces; run the generator and commit the result"))

    if on_disk_json is None:
        failures.append(("output-missing", f"{JSON_OUT_REL} does not exist; run the generator"))
    elif on_disk_json != render_json(payload):
        failures.append(("output-drifted", f"{JSON_OUT_REL} is not what generation produces; run the generator and commit the result"))

    if consumer is None:
        failures.append(("consumer-missing", f"{CONSUMER_REL} does not exist"))
    else:
        if _REDECLARATION.search(consumer):
            failures.append(
                (
                    "consumer-redeclares",
                    f"{CONSUMER_REL} declares its own ConnectorType union; the generated one would be ignored "
                    "and the hand-maintained list is the mechanism that drifted",
                )
            )
        if not _REEXPORT.search(consumer):
            failures.append(("consumer-not-reexporting", f"{CONSUMER_REL} does not re-export ConnectorType from {TS_OUT_REL.stem}"))

    # The folds are the part generation is most likely to flatten away, so
    # they are checked against the rendered output rather than the payload.
    rendered = on_disk_ts or ""
    for alternate, target in payload["canonical"].items():
        if alternate not in payload["members"]:
            failures.append(
                (
                    "fold-source-dropped",
                    f"{alternate!r} folds onto {target!r} but is not a union member; the console's spelling would not type-check",
                )
            )
        if target not in payload["members"]:
            failures.append(("fold-target-dropped", f"{alternate!r} folds onto {target!r}, which is not a union member"))
        if on_disk_ts is not None and f'"{alternate}": "{target}"' not in rendered:
            failures.append(("fold-not-emitted", f"the {alternate!r} -> {target!r} fold is missing from {TS_OUT_REL}"))
    return failures


def load(root: Path) -> dict:
    registry = parse_registry(root)
    profiles, aliases, canonical = parse_normalizer(root)
    return {"registry": registry, "profiles": profiles, "aliases": aliases, "canonical": canonical}


def _read(path: Path) -> str | None:
    return path.read_text(encoding="utf-8") if path.exists() else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--check", action="store_true", help="fail (exit 1) on drift instead of rewriting the outputs")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects injected drift in each direction")
    args = parser.parse_args(argv)

    root = args.repo_root.resolve()
    if args.self_test:
        return self_test(root)

    try:
        inputs = load(root)
    except GateError as exc:
        print(f"generate_connector_types: FAILED to read the tree: {exc}", file=sys.stderr)
        return 2

    payload = build_payload(**inputs)
    ts_path, json_path = root / TS_OUT_REL, root / JSON_OUT_REL

    if not args.check:
        ts_path.parent.mkdir(parents=True, exist_ok=True)
        ts_path.write_text(render_typescript(payload), encoding="utf-8")
        json_path.write_text(render_json(payload), encoding="utf-8")

    failures = evaluate(payload, _read(ts_path), _read(json_path), _read(root / CONSUMER_REL))

    if args.json:
        print(
            json.dumps(
                {"repo_root": str(root), **payload, "failures": [{"code": c, "detail": d} for c, d in failures]}, indent=2, sort_keys=True
            )
        )
        return 1 if failures else 0

    counts = payload["counts"]
    print(f"repo root        {root}")
    print(f"registry         {REGISTRY_REL}  ({len(inputs['registry'])} declared connector ids)")
    print(
        f"normalizer       {NORMALIZER_REL}  ({len(inputs['profiles'])} profiles, "
        f"{counts['aliases']} type aliases, {len(inputs['canonical'])} canonical folds)"
    )
    print(f"outputs          {TS_OUT_REL}")
    print(f"                 {JSON_OUT_REL}")
    print(f"consumer         {CONSUMER_REL}")
    print()
    print(
        f"union            {counts['total']} members = {counts[ORIGIN_REGISTRY]} registry "
        f"+ {counts[ORIGIN_PROFILE]} profile + {counts[ORIGIN_FOLD]} canonical-fold"
    )
    print(f"folds preserved  {', '.join(f'{a} -> {t}' for a, t in payload['canonical'].items())}")
    print()

    if failures:
        print(f"FAIL — {len(failures)} finding(s):")
        for code, detail in failures:
            print(f"  [{code}] {detail}")
        return 1
    print("OK — the committed union is what the registry, the profiles and the canonical")
    print("     folds generate, and the console re-exports it instead of redeclaring it.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def self_test(root: Path) -> int:
    """Inject drift in each direction and require --check to catch each one."""
    try:
        inputs = load(root)
    except GateError as exc:
        print(f"self-test: cannot read the tree: {exc}", file=sys.stderr)
        return 2

    payload = build_payload(**inputs)
    good_ts, good_json = render_typescript(payload), render_json(payload)
    consumer = _read(root / CONSUMER_REL) or ""

    clean = evaluate(payload, good_ts, good_json, consumer)
    if clean:
        print("self-test: the unmodified tree already fails; fix that first", file=sys.stderr)
        for code, detail in clean:
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 1

    def drop_member(name: str) -> dict:
        reduced = dict(payload.items())
        reduced["members"] = [m for m in payload["members"] if m != name]
        return reduced

    hand_edited_ts = good_ts.replace('  "qualys",', "", 1)
    a_connector, a_fold = next(iter(inputs["registry"])), next(iter(inputs["canonical"]))

    cases: list[tuple[str, str, tuple]] = [
        (
            "a hand edit removes a union member from the generated TypeScript",
            "output-drifted",
            (payload, hand_edited_ts, good_json, consumer),
        ),
        (
            "a hand edit changes the generated JSON",
            "output-drifted",
            (payload, good_ts, good_json.replace('"total"', '"totl"', 1), consumer),
        ),
        (
            "the generated TypeScript is deleted",
            "output-missing",
            (payload, None, good_json, consumer),
        ),
        (
            "the console goes back to declaring its own union",
            "consumer-redeclares",
            (payload, good_ts, good_json, consumer + '\nexport type ConnectorType = "a" | "b";\n'),
        ),
        (
            "the console stops re-exporting the generated union",
            "consumer-not-reexporting",
            (payload, good_ts, good_json, _REEXPORT.sub("", consumer)),
        ),
        (
            "a canonical fold is flattened out of the union",
            "fold-source-dropped",
            (drop_member(a_fold), good_ts, good_json, consumer),
        ),
        (
            "a fold's target leaves the registry",
            "fold-target-dropped",
            (drop_member(inputs["canonical"][a_fold]), good_ts, good_json, consumer),
        ),
        (
            "the fold map is dropped from the rendered TypeScript",
            "fold-not-emitted",
            (payload, re.sub(r'^\s+"[a-z_]+": "[a-z_]+",$', "", good_ts, flags=re.MULTILINE), good_json, consumer),
        ),
    ]

    print(f"self-test against {root}")
    print(f"clean tree: {payload['counts']['total']}-member union, 0 failures (the baseline every case below perturbs)")
    print(f"            a declared id is {a_connector!r}; a folded spelling is {a_fold!r}\n")
    ok = True
    for description, expected, call in cases:
        codes = {code for code, _ in evaluate(*call)}
        caught = expected in codes
        ok &= caught
        print(f"  {'PASS' if caught else 'FAIL'}  {description}")
        print(f"        expected [{expected}]  got {sorted(codes) or 'nothing'}")

    # The registry reader itself: identity must come from the class, because
    # two connectors are declared under an id their filename does not spell.
    by_filename = {info["module"][:-3] for info in inputs["registry"].values()}
    mismatched = sorted(cid for cid, info in inputs["registry"].items() if info["module"][:-3] != cid)
    filename_would_break = bool(mismatched) and set(inputs["registry"]) != by_filename
    print(f"  {'PASS' if filename_would_break else 'FAIL'}  IDENTITY: connector_id is read from the class, not the filename")
    print(f"        {len(mismatched)} connector(s) would be misnamed by a filename slug: {', '.join(mismatched) or 'none'}")
    ok &= filename_would_break

    print()
    if not ok:
        print("self-test FAILED: the gate did not catch drift it claims to catch")
        return 1
    print(f"self-test OK: {len(cases)} injected defects, each caught by its own code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
