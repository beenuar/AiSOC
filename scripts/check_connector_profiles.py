#!/usr/bin/env python3
"""Connector-type drift gate: names must resolve, in both directions.

Why this exists
---------------
``connectorProfiles`` in ``services/ingest/internal/normalizer/normalizer.go``
decides how a connector's events become OCSF, and it is keyed by
``connector_type``. The connectors service declares its own identifiers in
``services/connectors/app/connectors/``. Nothing compared the two, and they
drifted: the service declares ``crowdstrike`` and ``okta`` while the profiles
were keyed ``crowdstrike_falcon`` and ``okta_system_log``, so events arriving
under the names the product advertises missed the lookup entirely. The README's
own push example was one of them.

A missing profile is not cosmetic. In strict mode the normalizer rejects an
unknown connector type outright. In lenient mode it falls to the generic
profile, and before the identity aliases were wired into that path the
resulting alert carried no host, no user and no source IP — so entity
extraction, the Investigation Rail's pivots, the ``{tenant}:{entity}:{tactic}``
correlation key, the entity graph and UEBA all had nothing to work with. The
alert still appeared, which is what made it look like it had worked.

What it checks, in both directions
----------------------------------
The repository's dominant bug shape is a one-directional check: it compares A
against B, never B against A, so drift in the direction things actually change
slips through while the check prints OK. Every rule below is therefore stated
as a resolution requirement on a specific name, and both name spaces are
enumerated.

  GO -> PY   every ``connectorProfiles`` key and every ``connectorTypeAliases``
             entry must name something that exists.
  PY -> GO   every declared ``connector_id`` must reach a normalization path
             that survives strict mode: its own profile, an alias to one, or
             the canonical ``raw_event`` + ``source`` envelope.
  DOCS -> *  every ``connector_type`` in a documented example must resolve.
  MECHANISM  the identity aliases the generic path depends on must still be
             declared, and the Go tests that prove the behaviour must exist.
             Coverage without the behaviour behind it is the vacuous case.

Usage
-----
    python3 scripts/check_connector_profiles.py              # gate
    python3 scripts/check_connector_profiles.py --json
    python3 scripts/check_connector_profiles.py --self-test  # prove it bites

``--repo-root`` overrides the tree under inspection. The resolved root, every
file read and every count are printed before the verdict, and a missing or
empty input is a hard error rather than a quiet zero: a gate that resolves its
own location and reports OK about a tree it never opened is worse than no gate.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

NORMALIZER_REL = Path("services/ingest/internal/normalizer/normalizer.go")
NORMALIZER_TEST_REL = Path("services/ingest/internal/normalizer/normalizer_test.go")
CONNECTORS_REL = Path("services/connectors/app/connectors")
TEMPLATES_REL = Path("services/ingest/internal/normalizer/templates")

# Profile keys that are push-path template names rather than connector ids.
# Each must name a webhook template that exists, so this cannot become a
# dumping ground for keys nobody can account for.
PUSH_ONLY_PROFILES: dict[str, str] = {
    "ai_runtime": "ai-runtime.yaml",
    "ai_guardrail": "ai-finding.yaml",
}

# Legacy profile keys that the wider platform uses as a connector_type even
# though the connectors service spells the id differently. They stay because
# packages/types' ConnectorType union, the CLI default, the graph extractor and
# the actions credential resolver all key off them; the connectorTypeAliases
# map is what makes the declared id resolve to the same profile. Each entry
# must be reachable via an alias or still declared in the union, which is
# checked against those files rather than asserted here.
LEGACY_PROFILE_KEYS = {"crowdstrike_falcon", "okta_system_log", "splunk_enterprise"}

# packages/types' ConnectorType union is a third name space, and it predates
# the connectors registry. These members name no connector the service
# declares and no profile: they are the console's older vocabulary
# (``google_chronicle`` for ``chronicle``, ``ibm_qradar`` for ``qradar``) plus
# four generic transports that were never connectors at all. They are recorded
# rather than fixed here because the union is shared with the console.
#
# This is a ratchet: it may shrink, never grow. A new unresolvable union member
# fails the gate.
KNOWN_UNION_ONLY_TYPES = {
    "custom_webhook",
    "google_chronicle",
    "http_pull",
    "ibm_qradar",
    "kafka",
    "palo_alto_cortex",
    "slack",
    "syslog",
    "teams",
    "vectra_ai",
}

TS_TYPES_REL = Path("packages/types/src/connector.ts")

# Identity destinations the generic path depends on. Losing any one of these
# is the defect this gate exists for.
REQUIRED_IDENTITY_DESTINATIONS = ("actor.user.name", "device.name", "src_endpoint.ip")

# Behavioural proof. Coverage arithmetic alone would still pass if someone
# deleted the alias pass, so the gate requires the tests that exercise it.
REQUIRED_GO_TESTS = (
    "TestGenericProfileResolvesIdentityFields",
    "TestDeclaredConnectorIdResolvesToVendorProfile",
    "TestIdentityAliasResolutionIsDeterministic",
)

_GO_BLOCK = "var {name} = map[string]{vtype}{{"


class GateError(RuntimeError):
    """An input could not be read. Never downgraded to a passing result."""


# --------------------------------------------------------------------------
# Go side
# --------------------------------------------------------------------------
def _go_block(src: str, header: str, open_after: str | None = None) -> str:
    """The brace-balanced literal following `header`.

    `open_after` exists for a slice of anonymous structs, where the first brace
    after the header opens the type definition rather than the literal: the
    value starts at the `}{` that closes the struct and opens the composite.
    """
    start = src.find(header)
    if start == -1:
        raise GateError(f"could not find `{header}` in the normalizer")
    if open_after is not None:
        marker = src.find(open_after, start)
        if marker == -1:
            raise GateError(f"could not find `{open_after}` after `{header}`")
        start = marker
    depth, i = 0, src.index("{", start)
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    raise GateError(f"unbalanced braces after `{header}`")


def parse_profile_keys(src: str) -> set[str]:
    block = _go_block(src, "var connectorProfiles = map[string]connectorProfile{")
    # Top-level keys only: nested fieldMap entries are indented deeper.
    return set(re.findall(r'^\t"([^"]+)":\s*\{', block, re.MULTILINE))


def parse_type_aliases(src: str) -> dict[str, str]:
    # Absent is a valid state to report on, not a parse error: a tree with no
    # alias map is exactly the tree whose declared ids reach no profile, and
    # the gate should say so rather than abort before it gets there.
    if "var connectorTypeAliases = map[string]string{" not in src:
        return {}
    block = _go_block(src, "var connectorTypeAliases = map[string]string{")
    return dict(re.findall(r'"([^"]+)":\s*"([^"]+)"', block))


def parse_identity_destinations(src: str) -> dict[str, list[str]]:
    block = _go_block(src, "var _canonicalAliases = []struct {", open_after="}{")
    out: dict[str, list[str]] = {}
    for dst, sources in re.findall(r'\{"([^"]+)",\s*\[\]string\{([^}]*)\}\}', block):
        out[dst] = re.findall(r'"([^"]+)"', sources)
    return out


# --------------------------------------------------------------------------
# Python side
# --------------------------------------------------------------------------
def _class_connector_id(tree: ast.Module) -> str | None:
    for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
        for stmt in cls.body:
            if (
                isinstance(stmt, ast.Assign)
                and any(getattr(t, "id", None) == "connector_id" for t in stmt.targets)
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
                and stmt.value.value
            ):
                return stmt.value.value
            if (
                isinstance(stmt, ast.AnnAssign)
                and getattr(stmt.target, "id", None) == "connector_id"
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
                and stmt.value.value
            ):
                return stmt.value.value
    return None


def _emits_canonical_envelope(tree: ast.Module) -> bool:
    """Whether the connector's normalized event carries `raw_event` + `source`.

    Every string key contributed by a dict literal, a subscript assignment or
    an envelope helper inside the normalize path counts. Restricting this to
    keys of a directly-returned dict literal reported 13 connectors as
    non-canonical when a runtime probe of all 84 found 2 — eleven build the
    envelope through a helper or a spread, and a gate that fails eleven
    correct connectors gets switched off.
    """

    def in_normalize_path(name: str) -> bool:
        return name == "normalize" or name.startswith(("_envelope", "_normalize", "_to_", "_build"))

    keys: set[str] = set()
    functions = (ast.FunctionDef, ast.AsyncFunctionDef)
    for fn in (n for n in ast.walk(tree) if isinstance(n, functions) and in_normalize_path(n.name)):
        for node in ast.walk(fn):
            if isinstance(node, ast.Dict):
                keys.update(k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str))
            elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                keys.add(node.slice.value)
    return {"raw_event", "source"} <= keys


def parse_connectors(directory: Path) -> dict[str, bool]:
    """connector_id -> emits a canonical envelope."""
    out: dict[str, bool] = {}
    for path in sorted(directory.glob("*.py")):
        if path.name in {"__init__.py", "base.py"}:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        connector_id = _class_connector_id(tree)
        if connector_id:
            out[connector_id] = _emits_canonical_envelope(tree)
    return out


# --------------------------------------------------------------------------
# Docs side
# --------------------------------------------------------------------------
DOC_GLOBS = ("README.md", "docs/**/*.md", "apps/docs/docs/**/*.md", "apps/docs/docs/**/*.mdx")
DOC_PATTERN = re.compile(r"""["']?connector_type["']?\s*[:=]\s*["']([a-z0-9_]+)["']""")


def parse_doc_examples(root: Path) -> dict[str, list[str]]:
    """connector_type -> the documents that show it."""
    found: dict[str, list[str]] = {}
    for pattern in DOC_GLOBS:
        for path in sorted(root.glob(pattern)):
            if "node_modules" in path.parts or "plans" in path.parts:
                continue
            for name in DOC_PATTERN.findall(path.read_text(encoding="utf-8", errors="replace")):
                found.setdefault(name, []).append(str(path.relative_to(root)))
    return found


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------
def parse_union_types(path: Path) -> set[str]:
    """Members of packages/types' ConnectorType union."""
    src = path.read_text(encoding="utf-8")
    match = re.search(r"export type ConnectorType\s*=(.*?);", src, re.DOTALL)
    if not match:
        raise GateError(f"could not find the ConnectorType union in {path}")
    return set(re.findall(r'"([^"]+)"', match.group(1)))


def evaluate(
    profile_keys: set[str],
    type_aliases: dict[str, str],
    identity: dict[str, list[str]],
    connectors: dict[str, bool],
    doc_examples: dict[str, list[str]],
    go_tests: set[str],
    template_names: set[str],
    union_types: set[str],
) -> list[tuple[str, str]]:
    failures: list[tuple[str, str]] = []
    declared = set(connectors)
    # A name is resolvable if it is a declared connector, a profile key, or an
    # alias that leads to one.
    resolvable = declared | profile_keys | set(type_aliases)

    # GO -> PY. Every profile key must name something real.
    for key in sorted(profile_keys):
        if key in declared:
            continue
        if key in PUSH_ONLY_PROFILES:
            template = PUSH_ONLY_PROFILES[key]
            if template not in template_names:
                failures.append(
                    ("profile-template-missing", f"profile {key!r} is allowed as a push-only template key, but {template} does not exist")
                )
            continue
        if key in LEGACY_PROFILE_KEYS:
            if key not in set(type_aliases.values()) and key not in union_types:
                failures.append(
                    (
                        "legacy-profile-unreachable",
                        f"profile {key!r} is a legacy name: no connector declares it, no alias points at it, "
                        "and the ConnectorType union no longer carries it — nothing can reach this profile",
                    )
                )
            continue
        failures.append(("profile-names-nothing", f"profile {key!r} names a connector type that does not exist"))

    # GO -> PY. Aliases must start somewhere real and land somewhere real.
    for source, target in sorted(type_aliases.items()):
        if source not in declared:
            failures.append(("alias-source-undeclared", f"alias {source!r} -> {target!r}: no connector declares {source!r}"))
        if target not in profile_keys:
            failures.append(("alias-target-missing", f"alias {source!r} -> {target!r}: {target!r} is not a profile key"))
        if source in profile_keys:
            failures.append(("alias-shadowed", f"alias {source!r} is shadowed by its own profile entry and never fires"))

    # PY -> GO. Every declared connector must survive strict mode.
    for connector_id, canonical in sorted(connectors.items()):
        if connector_id in profile_keys or connector_id in type_aliases or canonical:
            continue
        failures.append(
            (
                "strict-mode-unreachable",
                f"connector {connector_id!r} has no profile, no alias and emits no canonical envelope: "
                "strict mode rejects it and lenient mode resolves only a title",
            )
        )

    # TS -> *. The console's union is the third name space, and drift here is
    # how `splunk_enterprise` came to exist on one side only. The ratchet may
    # shrink; a new unresolvable member fails.
    for name in sorted(union_types - resolvable - KNOWN_UNION_ONLY_TYPES):
        failures.append(("union-type-unresolvable", f"ConnectorType union member {name!r} names no connector, profile or alias"))
    for name in sorted(KNOWN_UNION_ONLY_TYPES & resolvable):
        failures.append(
            (
                "union-ratchet-stale",
                f"{name!r} now resolves; remove it from KNOWN_UNION_ONLY_TYPES so the ratchet keeps shrinking",
            )
        )

    # DOCS. A copied example that resolves to nothing is the defect that taught
    # us to write this gate.
    for name, where in sorted(doc_examples.items()):
        locations = ", ".join(sorted(set(where)))
        if name not in resolvable:
            failures.append(("doc-example-unresolvable", f"documented connector_type {name!r} resolves to nothing (in {locations})"))
            continue
        # Being a declared connector id is not enough for a documented example.
        # A reader pastes a flat payload, which carries no `raw_event`, so the
        # canonical branch never runs and only a profile or an alias can give
        # the event a vendor identity. This is the exact shape of the original
        # defect: the README said `crowdstrike`, the profile was keyed
        # `crowdstrike_falcon`, and the example a new user copied fell through
        # to the generic fallback while still producing an alert.
        if name not in profile_keys and name not in type_aliases:
            failures.append(
                (
                    "doc-example-no-profile",
                    f"documented connector_type {name!r} has no profile and no alias, so the flat payload "
                    f"shown in {locations} falls through to the generic fallback",
                )
            )

    # MECHANISM. The aliases the generic path leans on, and the tests that
    # prove it actually leans on them.
    for destination in REQUIRED_IDENTITY_DESTINATIONS:
        if not identity.get(destination):
            failures.append(
                ("identity-alias-missing", f"_canonicalAliases declares no sources for {destination!r}; the generic path cannot resolve it")
            )
    for test in REQUIRED_GO_TESTS:
        if test not in go_tests:
            failures.append(("behaviour-test-missing", f"{test} is gone; coverage arithmetic would still pass with the alias pass deleted"))
    return failures


def load(root: Path) -> dict:
    normalizer = root / NORMALIZER_REL
    normalizer_test = root / NORMALIZER_TEST_REL
    connectors_dir = root / CONNECTORS_REL
    templates_dir = root / TEMPLATES_REL
    ts_types = root / TS_TYPES_REL
    for path in (normalizer, normalizer_test, connectors_dir, templates_dir, ts_types):
        if not path.exists():
            raise GateError(f"expected input does not exist: {path}")

    src = normalizer.read_text(encoding="utf-8")
    data = {
        "profile_keys": parse_profile_keys(src),
        "type_aliases": parse_type_aliases(src),
        "identity": parse_identity_destinations(src),
        "connectors": parse_connectors(connectors_dir),
        "doc_examples": parse_doc_examples(root),
        "go_tests": set(re.findall(r"^func (Test\w+)\(", normalizer_test.read_text(encoding="utf-8"), re.MULTILINE)),
        "template_names": {p.name for p in templates_dir.glob("*.yaml")},
        "union_types": parse_union_types(ts_types),
    }
    # An empty parse means the format moved, not that the tree is clean.
    for name in ("profile_keys", "connectors", "identity", "go_tests", "template_names", "union_types"):
        if not data[name]:
            raise GateError(f"parsed zero {name} — refusing to report a clean tree from an empty read")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects injected drift in each direction")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test(args.repo_root.resolve())

    root = args.repo_root.resolve()
    try:
        data = load(root)
    except GateError as exc:
        print(f"check_connector_profiles: FAILED to read the tree: {exc}", file=sys.stderr)
        return 2

    failures = evaluate(**data)
    declared = data["connectors"]
    with_profile = sorted(c for c in declared if c in data["profile_keys"] or c in data["type_aliases"])
    canonical_only = sorted(c for c in declared if c not in with_profile and declared[c])
    generic_only = sorted(c for c in declared if c not in with_profile and not declared[c])

    if args.json:
        print(
            json.dumps(
                {
                    "repo_root": str(root),
                    "declared_connectors": len(declared),
                    "profile_keys": sorted(data["profile_keys"]),
                    "type_aliases": data["type_aliases"],
                    "with_profile": with_profile,
                    "canonical_envelope_only": canonical_only,
                    "generic_fallback_only": generic_only,
                    "doc_examples": data["doc_examples"],
                    "failures": [{"code": c, "detail": d} for c, d in failures],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 1 if failures else 0

    # Name the tree and the inputs before the verdict.
    print(f"repo root        {root}")
    print(f"normalizer       {NORMALIZER_REL}  ({len(data['profile_keys'])} profiles, {len(data['type_aliases'])} type aliases)")
    print(f"connectors       {CONNECTORS_REL}  ({len(declared)} declared connector ids)")
    print(f"templates        {TEMPLATES_REL}  ({len(data['template_names'])} webhook templates)")
    print(f"console types    {TS_TYPES_REL}  ({len(data['union_types'])} ConnectorType union members)")
    occurrences = sum(len(v) for v in data["doc_examples"].values())
    print(f"doc examples     {len(data['doc_examples'])} distinct connector_type values across {occurrences} occurrences")
    print()
    print(
        f"resolution path  {len(with_profile)} via profile/alias, "
        f"{len(canonical_only)} via canonical envelope, {len(generic_only)} generic-only"
    )
    if generic_only:
        print(f"                 generic-only: {', '.join(generic_only)}")
    print()
    if failures:
        print(f"FAIL — {len(failures)} connector-type name(s) do not resolve:")
        for code, detail in failures:
            print(f"  [{code}] {detail}")
        return 1
    print("OK — every profile key names a real connector type, every declared connector")
    print("     reaches a normalization path, and every documented example resolves.")
    return 0


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def self_test(root: Path) -> int:
    """Inject drift in each direction and require the gate to catch each one.

    A gate is only worth its runtime if it fails when it should. Each case
    mutates the real parsed inputs and asserts the specific code fires, so a
    refactor that quietly stops checking one direction fails here rather than
    printing OK forever.
    """
    try:
        base = load(root)
    except GateError as exc:
        print(f"self-test: cannot read the tree: {exc}", file=sys.stderr)
        return 2

    if evaluate(**base):
        print("self-test: the unmodified tree already fails; fix that first", file=sys.stderr)
        for code, detail in evaluate(**base):
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 1

    def mutate(**overrides) -> dict:
        data = {k: (v.copy() if hasattr(v, "copy") else v) for k, v in base.items()}
        for key, fn in overrides.items():
            fn(data[key])
        return data

    cases: list[tuple[str, str, dict]] = [
        (
            "GO -> PY: a profile key naming a connector that does not exist",
            "profile-names-nothing",
            mutate(profile_keys=lambda s: s.add("acme_xdr_9000")),
        ),
        (
            "PY -> GO: a declared connector with no profile and no canonical envelope",
            "strict-mode-unreachable",
            mutate(connectors=lambda d: d.update({"brand_new_connector": False})),
        ),
        (
            "DOCS: a documented example whose connector_type resolves to nothing",
            "doc-example-unresolvable",
            mutate(doc_examples=lambda d: d.update({"crowdstrik": ["README.md"]})),
        ),
        (
            "DOCS: a documented example naming a real connector with no profile behind it",
            "doc-example-no-profile",
            mutate(doc_examples=lambda d: d.update({"confluence_audit": ["README.md"]})),
        ),
        (
            "GO -> PY: an alias pointing at a profile that does not exist",
            "alias-target-missing",
            mutate(type_aliases=lambda d: d.update({"okta": "okta_nonexistent"})),
        ),
        (
            "GO -> PY: an alias starting from a connector nobody declares",
            "alias-source-undeclared",
            mutate(type_aliases=lambda d: d.update({"not_a_connector": "splunk"})),
        ),
        (
            "MECHANISM: the identity aliases the generic path depends on are removed",
            "identity-alias-missing",
            mutate(identity=lambda d: d.pop("actor.user.name", None)),
        ),
        (
            "MECHANISM: the Go test proving the behaviour is deleted",
            "behaviour-test-missing",
            mutate(go_tests=lambda s: s.discard("TestGenericProfileResolvesIdentityFields")),
        ),
        (
            "GO -> PY: a push-only profile key whose template is gone",
            "profile-template-missing",
            mutate(template_names=lambda s: s.discard("ai-runtime.yaml")),
        ),
        (
            "TS -> *: a union member naming no connector, profile or alias",
            "union-type-unresolvable",
            mutate(union_types=lambda s: s.add("acme_console_only")),
        ),
        (
            "TS -> *: the union ratchet left stale after a name starts resolving",
            "union-ratchet-stale",
            mutate(connectors=lambda d: d.update({"vectra_ai": True})),
        ),
        (
            "GO -> PY: the last route to a legacy profile key disappears",
            "legacy-profile-unreachable",
            mutate(union_types=lambda s: s.discard("splunk_enterprise")),
        ),
    ]

    print(f"self-test against {root}")
    print("clean tree: 0 failures (the baseline every case below perturbs)\n")
    ok = True
    for description, expected_code, data in cases:
        codes = {code for code, _ in evaluate(**data)}
        caught = expected_code in codes
        ok &= caught
        print(f"  {'PASS' if caught else 'FAIL'}  {description}")
        print(f"        expected [{expected_code}]  got {sorted(codes) or 'nothing'}")
    print()
    if not ok:
        print("self-test FAILED: the gate did not catch drift it claims to catch")
        return 1
    print(f"self-test OK: {len(cases)} injected defects, each caught by its own code")
    return 0


if __name__ == "__main__":
    sys.exit(main())
