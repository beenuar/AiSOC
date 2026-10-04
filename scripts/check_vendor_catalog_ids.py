#!/usr/bin/env python3
"""Every read executor's vendor id resolves to a connector a tenant can save.

The hole this closes
--------------------
``services/actions/app/live_actions/investigation_reads.py`` registers its
executors under a ``vendor`` id. ``services/api/app/services/agent_tools/vendor_reads.py``
decides which vendor tools to offer an investigation by looking that id up
against the tenant's saved connectors, keyed on ``connector_type``:

    by_type.get(vendor_id)

Three of the seven ids named nothing a tenant could ever have saved.
``defender``, ``entra`` and ``aws`` are not connector types; the catalog spells
them ``azure_defender``, ``azure_entra`` and ``aws_cloudtrail``. So the lookup
returned ``None``, the tool was never bound, and a model investigating a
Defender host, an Entra identity or a CloudTrail event was told the tenant had
no integration for it.

Nothing failed. The dictionary lookup that missed is the same expression as the
one that hits, and the three vendors were simply absent from a list nobody
counted. Three of the five vendors added in gap-closure 4.2 had never been
reachable.

What is asserted
----------------
For every vendor id registered by a read executor, at least one connector in
``services/connectors/app/connectors/__init__.py`` declares a matching
``connector_id`` -- either directly, or through an entry in the alias map that
``vendor_reads`` resolves with.

The direction that drifts is a new executor naming a vendor the way the vendor
names itself rather than the way the catalog does, so that is the direction
this runs in.

Run:  python3 scripts/check_vendor_catalog_ids.py [--self-test]
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

EXECUTORS = Path("services/actions/app/live_actions/investigation_reads.py")
REGISTRY = Path("services/connectors/app/connectors/__init__.py")
ALIASES = Path("services/api/app/services/agent_tools/vendor_aliases.py")


def _executor_vendor_ids(path: Path) -> set[str]:
    """Vendor ids registered by the read executors, from the AST.

    AST rather than a text scan so a vendor named in the prose explaining this
    defect is not counted as a registration.
    """
    found: set[str] = set()
    if not path.is_file():
        return found
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "vendor":
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                found.add(node.value.value)
    return found


def _catalog_connector_ids(path: Path) -> set[str]:
    """Every ``connector_id`` a tenant can save, read from the registry module.

    Resolved by importing the connectors package would be tidier and is not:
    the gate would then need that service's dependencies installed, and a gate
    that cannot run is a gate that gets deleted. The ids are class attributes
    assigned to string literals, which the AST can read.
    """
    found: set[str] = set()
    if not path.is_file():
        return found
    connectors_dir = path.parent
    for module in sorted(connectors_dir.glob("*.py")):
        try:
            tree = ast.parse(module.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for stmt in node.body:
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target] if isinstance(stmt, ast.AnnAssign) else []
                value = stmt.value if isinstance(stmt, ast.Assign | ast.AnnAssign) else None
                if not value or not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                    continue
                if any(isinstance(t, ast.Name) and t.id == "connector_id" for t in targets):
                    found.add(value.value)
    return found


def _alias_map(path: Path) -> dict[str, tuple[str, ...]]:
    """``vendor id -> catalog connector types`` from the alias module."""
    if not path.is_file():
        return {}
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if not any(isinstance(t, ast.Name) and t.id == "VENDOR_CONNECTOR_TYPES" for t in targets):
            continue
        value = node.value if isinstance(node, ast.Assign | ast.AnnAssign) else None
        if isinstance(value, ast.Dict):
            out: dict[str, tuple[str, ...]] = {}
            for key, val in zip(value.keys, value.values, strict=False):
                if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                    continue
                if isinstance(val, ast.Tuple | ast.List):
                    out[key.value] = tuple(e.value for e in val.elts if isinstance(e, ast.Constant) and isinstance(e.value, str))
                elif isinstance(val, ast.Constant) and isinstance(val.value, str):
                    out[key.value] = (val.value,)
            return out
    return {}


def check(root: Path | None = None) -> tuple[list[str], dict[str, int]]:
    root = root or repo_root()
    vendors = _executor_vendor_ids(root / EXECUTORS)
    catalog = _catalog_connector_ids(root / REGISTRY)
    aliases = _alias_map(root / ALIASES)
    counts = {"vendors": len(vendors), "catalog": len(catalog), "aliases": len(aliases)}
    findings: list[str] = []

    if not vendors:
        findings.append(
            f"{EXECUTORS} declared no read executor at all. A clean result over an empty scan is the failure this gate exists to prevent."
        )
        return findings, counts
    if not catalog:
        findings.append(f"{REGISTRY} yielded no connector ids, so nothing could be resolved against it.")
        return findings, counts

    for vendor in sorted(vendors):
        if vendor in catalog:
            continue
        mapped = aliases.get(vendor, ())
        if not mapped:
            findings.append(
                f"read executor vendor {vendor!r} is not a connector type a tenant can save, and no alias "
                f"maps it to one. `by_type.get({vendor!r})` returns None on every tenant, so the tool is "
                "never offered and the model is told there is no integration."
            )
            continue
        unknown = [t for t in mapped if t not in catalog]
        if unknown:
            findings.append(
                f"vendor {vendor!r} is aliased to {', '.join(unknown)}, which no connector declares. "
                "An alias to a type nobody can save resolves to nothing, exactly like no alias at all."
            )

    for vendor in sorted(aliases):
        if vendor not in vendors:
            findings.append(
                f"the alias map names vendor {vendor!r} and no read executor registers it. "
                "Remove the row, so an alias covering nothing is not mistaken for one that is load-bearing."
            )

    return findings, counts


def _self_test_cases() -> list[tuple[str, bool]]:
    """Prove the gate detects the drift it exists to catch.

    Mutations are applied to a copy of the real tree rather than to a fixture,
    because a gate proven against a fixture is proven against the fixture.
    """
    import shutil
    import tempfile

    root = repo_root()
    cases: list[tuple[str, bool]] = []
    clean, counts = check(root)
    cases.append(("the real tree passes", not clean))
    cases.append(("the real tree has read executors to judge", counts["vendors"] > 0))
    cases.append(("the real tree has a catalog to resolve against", counts["catalog"] > 0))

    read = (EXECUTORS, REGISTRY, ALIASES)
    mutations = [
        (
            "an executor naming a vendor the catalog does not have is reported",
            EXECUTORS,
            'vendor="okta"',
            'vendor="okta_identity"',
        ),
        (
            "an alias pointing at a type nobody can save is reported",
            ALIASES,
            '"azure_defender"',
            '"microsoft_defender_atp"',
        ),
        (
            "an alias for a vendor no executor registers is reported",
            ALIASES,
            '"defender": ',
            '"defender_gone_away": ',
        ),
    ]

    for description, target, old, new in mutations:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            for rel in read:
                source = root / rel
                destination = tree / rel
                destination.parent.mkdir(parents=True, exist_ok=True)
                if source.is_file():
                    shutil.copy2(source, destination)
            # The registry resolver reads every sibling module, so the whole
            # directory comes along.
            shutil.copytree(
                root / REGISTRY.parent, tree / REGISTRY.parent, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__")
            )
            patched = tree / target
            text = patched.read_text(encoding="utf-8")
            if old not in text:
                cases.append((f"{description} (self-test anchor missing; case did not run)", False))
                continue
            patched.write_text(text.replace(old, new, 1), encoding="utf-8")
            problems, _ = check(tree)
            cases.append((description, bool(problems)))

    return cases


def main(argv: list[str] | None = None) -> int:
    if SELF_TEST_FLAG in (argv if argv is not None else sys.argv[1:]):
        return self_test_main(Path(__file__).name, extra=_self_test_cases())

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="render the verdict (default)")
    parser.parse_args(argv)

    findings, counts = check()
    print(
        f"check_vendor_catalog_ids: {counts['vendors']} read executor vendor(s) against "
        f"{counts['catalog']} saveable connector type(s), with {counts['aliases']} alias(es)"
    )
    if counts["vendors"] == 0 or counts["catalog"] == 0:
        print(
            "\nFAIL: the executor list or the connector catalog read as empty. A clean result over "
            "nothing is indistinguishable from a wrong root or a renamed module.",
            file=sys.stderr,
        )
        return 2
    if findings:
        print(f"\nFAIL: {len(findings)} vendor id(s) resolve to no connector a tenant can save.", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        return 1
    print("OK: every read executor's vendor id resolves to a connector type a tenant can save.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
