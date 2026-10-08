#!/usr/bin/env python3
"""Every event type in a connector's fixtures is classified, or excused.

Why this exists
---------------
`schemas/event_catalog/<source>.yaml` says what a vendor's event types mean:
a normalized action, a sensitivity on the platform's five-tier ladder, and an
optional ATT&CK hint. Ingest reads it at boot and stamps the answer onto every
event, so the lake, the detection matcher and triage share one classification
rather than each re-deriving a meaning from an event name.

A catalogue that only grows when somebody remembers is a catalogue that stops
growing. So this gate extracts every event type that appears in the fixtures
each catalogue declares, and fails when one is neither classified nor listed
under ``unclassified`` with a reason. Adding a connector fixture carrying a
new event type therefore fails CI until somebody decides what it means.

Three things it refuses that a simpler version of itself would not
------------------------------------------------------------------
**A source whose fixtures yield no event types.** That is a gate passing for
the wrong reason — the shape this repository keeps finding, where the clean
result and the broken glob print the same word. Two of the ten sources here
had no vendor-payload fixture at all before this catalogue was written, and
a gate that shrugged at that would have certified them forever.

**A vendored copy that has drifted.** `go:embed` cannot reach above its own
package, so the binary carries a copy under
``services/ingest/internal/eventcatalog/catalog/``. Reading the directory
from disk at run time instead is a failure this service has already shipped:
the webhook templates were read from a path the Dockerfile never populated.
The two directories are held byte-identical in both directions, so neither
can gain, lose or alter a file alone.

**A classification outside the ladder.** Severity is five tiers everywhere in
this platform. A sixth would be invisible until a query filtered on it and
found nothing.

Usage
-----
    python3 scripts/check_event_catalog.py
    python3 scripts/check_event_catalog.py --json
    python3 scripts/check_event_catalog.py --self-test

``--repo-root`` overrides the tree. Every input is named before the verdict
and an empty read is a hard error, never a quiet pass.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml
from gate_toolkit import repo_root

CATALOG_REL = Path("schemas/event_catalog")
VENDORED_REL = Path("services/ingest/internal/eventcatalog/catalog")
LOADER_REL = Path("services/ingest/internal/eventcatalog/catalog.go")
CONNECTORS_REL = Path("services/connectors/app/connectors")

#: The five tiers, lowest first. Identical to `eventcatalog.Sensitivities` in
#: the Go, which this gate reads back out of the loader so the two cannot
#: diverge without failing here.
SENSITIVITIES = ("info", "low", "medium", "high", "critical")

#: An ATT&CK technique or sub-technique id. Nothing resolves these against
#: the corpus here — `scripts/` already owns that check for detection content
#: — but a malformed id is cheap to catch and travels onto every event.
ATTACK_ID = re.compile(r"^T\d{4}(\.\d{3})?$")


class GateError(RuntimeError):
    """An input could not be read. Never downgraded to a passing result."""


# --------------------------------------------------------------------------
# Catalogue
# --------------------------------------------------------------------------
def load_catalogs(directory: Path) -> dict[str, dict]:
    """source -> parsed catalogue, keyed by the `source:` field, not the name."""
    out: dict[str, dict] = {}
    for path in sorted(directory.glob("*.yaml")):
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            raise GateError(f"{path} does not parse to a mapping")
        source = parsed.get("source")
        if not source:
            raise GateError(f"{path} declares no `source`")
        if source in out:
            raise GateError(f"two catalogue files declare source {source!r}")
        parsed["__file__"] = path.name
        out[source] = parsed
    return out


# --------------------------------------------------------------------------
# Fixture corpus
# --------------------------------------------------------------------------
def _records_from_json(path: Path):
    data = json.loads(path.read_text(encoding="utf-8"))
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            yield item
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _records_from_python(path: Path):
    """Every dict literal in a Python test file, as a plain dict.

    Only constant keys and values survive; a nested dict or list becomes a
    real nested structure so a declared path like ``operationName.value`` or
    ``events[].name`` resolves the same way it does at run time. Anything
    built by a call or a comprehension is skipped rather than guessed at.
    """

    def literal(node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Dict):
            out = {}
            for key, value in zip(node.keys, node.values, strict=False):
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    out[key.value] = literal(value)
            return out
        if isinstance(node, (ast.List, ast.Tuple)):
            return [literal(item) for item in node.elts]
        return None

    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            value = literal(node)
            if value:
                yield value


def extract_at_path(record: dict, declared_path: str) -> str | None:
    """Read the event type out of one record, using the declared path.

    One list hop (``events[].name``) is supported, which is the only shape
    any source here needs. Mirrors ``eventcatalog.EventType`` in the Go; the
    two are small enough that a shared implementation would cost more than
    it saves, and the fixtures exercise both.
    """
    # Annotated rather than inferred: it starts as the record but walks into
    # whatever each segment finds, so `dict` -- what mypy takes from the first
    # assignment -- is wrong from the second one onward.
    cur: Any = record
    for segment in declared_path.split("."):
        list_hop = segment.endswith("[]")
        key = segment[:-2] if list_hop else segment
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
        if list_hop:
            if not isinstance(cur, list) or not cur:
                return None
            cur = cur[0]
    if isinstance(cur, str) and cur.strip():
        return cur.strip()
    return None


def event_types_in_fixtures(root: Path, catalog: dict) -> tuple[set[str], list[str]]:
    """(event types found, files that could not be read)."""
    declared_path = catalog["event_type_path"]
    requires = catalog.get("fixture_requires") or []
    found: set[str] = set()
    missing: list[str] = []

    for relative in catalog.get("fixture_files") or []:
        path = root / relative
        if not path.exists():
            missing.append(relative)
            continue
        records = _records_from_json(path) if path.suffix == ".json" else _records_from_python(path)
        for record in records:
            if not isinstance(record, dict):
                continue
            # A discriminator, where the source declares one. `action`
            # appears on records from several sources and in unrelated test
            # dictionaries, so without this the GitHub catalogue would be
            # asked to classify a VPC flow log's `ACCEPT`.
            if requires and not all(key in record for key in requires):
                continue
            value = extract_at_path(record, declared_path)
            if value:
                found.add(value)
    return found, missing


# --------------------------------------------------------------------------
# Go side
# --------------------------------------------------------------------------
def parse_go_sensitivities(src: str) -> list[str]:
    match = re.search(r"var Sensitivities = \[\]Sensitivity\{(.*?)\}", src, re.DOTALL)
    if not match:
        raise GateError("could not find the Sensitivities slice in the loader")
    by_const = dict(re.findall(r'^\tSensitivity(\w+)\s+Sensitivity = "(\w+)"$', src, re.MULTILINE))
    return [by_const[name] for name in re.findall(r"Sensitivity(\w+)", match.group(1)) if name in by_const]


def parse_declared_connectors(directory: Path) -> set[str]:
    out: set[str] = set()
    for path in sorted(directory.glob("*.py")):
        if path.name in {"__init__.py", "base.py"}:
            continue
        for match in re.finditer(r'(?m)^\s*connector_id(?:\s*:\s*\w+)?\s*=\s*"([^"]+)"', path.read_text(encoding="utf-8")):
            out.add(match.group(1))
    return out


# --------------------------------------------------------------------------
# Gate
# --------------------------------------------------------------------------
def evaluate(
    catalogs: dict[str, dict],
    fixture_types: dict[str, set[str]],
    missing_fixtures: dict[str, list[str]],
    vendored_bytes: dict[str, bytes],
    source_bytes: dict[str, bytes],
    go_sensitivities: list[str],
    declared_connectors: set[str],
) -> tuple[list[tuple[str, str]], dict]:
    failures: list[tuple[str, str]] = []

    # LADDER. The Go's closed set and this gate's must be the same five.
    if list(go_sensitivities) != list(SENSITIVITIES):
        failures.append(
            (
                "ladder-mismatch",
                f"the loader declares the sensitivity ladder as {go_sensitivities}, and this gate checks "
                f"against {list(SENSITIVITIES)}; a value the gate accepts and the loader rejects fails at boot",
            )
        )

    # VENDORED COPY. Both directions: neither directory may gain, lose or
    # alter a file alone.
    for name in sorted(set(source_bytes) | set(vendored_bytes)):
        if name not in vendored_bytes:
            failures.append(("vendored-missing", f"{name} is in {CATALOG_REL} and not in {VENDORED_REL}; the binary would not carry it"))
        elif name not in source_bytes:
            failures.append(
                ("vendored-orphan", f"{name} is in {VENDORED_REL} and not in {CATALOG_REL}; the binary carries a file nobody edits")
            )
        elif source_bytes[name] != vendored_bytes[name]:
            failures.append(
                (
                    "vendored-drift",
                    f"{name} differs between {CATALOG_REL} and {VENDORED_REL}; the file a reviewer edits is not the one the binary loads",
                )
            )

    for source, catalog in sorted(catalogs.items()):
        file_name = catalog["__file__"]

        # The source must be a connector type that exists.
        if source not in declared_connectors:
            failures.append(("source-names-nothing", f"{file_name} declares source {source!r}, which no connector declares"))

        # Declared fixtures must exist, or the corpus is a promise.
        for relative in missing_fixtures.get(source, []):
            failures.append(("fixture-missing", f"{file_name} declares the fixture {relative}, which does not exist"))

        events = catalog.get("events") or {}
        unclassified = catalog.get("unclassified") or {}

        for event_type, classification in sorted(events.items()):
            if not isinstance(classification, dict):
                failures.append(("entry-malformed", f"{file_name}: {event_type!r} is not a mapping"))
                continue
            if not classification.get("action"):
                failures.append(("action-missing", f"{file_name}: {event_type!r} declares no normalized action"))
            sensitivity = classification.get("sensitivity")
            if sensitivity not in SENSITIVITIES:
                failures.append(
                    (
                        "sensitivity-invalid",
                        f"{file_name}: {event_type!r} declares sensitivity {sensitivity!r}, which is not one of {', '.join(SENSITIVITIES)}",
                    )
                )
            for technique in classification.get("attack") or []:
                if not ATTACK_ID.match(str(technique)):
                    failures.append(("attack-malformed", f"{file_name}: {event_type!r} hints at {technique!r}, which is not an ATT&CK id"))

        for event_type, reason in sorted(unclassified.items()):
            if event_type in events:
                failures.append(
                    (
                        "entry-both",
                        f"{file_name}: {event_type!r} is both classified and listed as deliberately unclassified",
                    )
                )
            if not isinstance(reason, str) or len(reason) < 15:
                failures.append(
                    (
                        "excuse-thin",
                        f"{file_name}: {event_type!r} is excused with {reason!r}, which does not say enough for a "
                        "reviewer to disagree with it",
                    )
                )

        # The corpus itself. An empty one is a pass for the wrong reason.
        found = fixture_types.get(source, set())
        if not found:
            failures.append(
                (
                    "fixture-corpus-empty",
                    f"{file_name} declares {len(catalog.get('fixture_files') or [])} fixture file(s) and no event "
                    f"type was found at {catalog['event_type_path']!r} in any of them. This gate would pass over "
                    "this source forever without checking anything",
                )
            )
            continue

        for event_type in sorted(found - set(events) - set(unclassified)):
            failures.append(
                (
                    "event-type-unclassified",
                    f"{source}: the event type {event_type!r} appears in the fixtures and is neither classified "
                    f"nor listed as deliberately unclassified in {file_name}",
                )
            )

    stats = {
        "sources": sorted(catalogs),
        "classified": sum(len(c.get("events") or {}) for c in catalogs.values()),
        "excused": sum(len(c.get("unclassified") or {}) for c in catalogs.values()),
        "fixture_types": {source: sorted(types) for source, types in sorted(fixture_types.items())},
        "by_sensitivity": {
            tier: sum(
                1
                for c in catalogs.values()
                for e in (c.get("events") or {}).values()
                if isinstance(e, dict) and e.get("sensitivity") == tier
            )
            for tier in SENSITIVITIES
        },
    }
    return failures, stats


def load(root: Path) -> dict:
    catalog_dir = root / CATALOG_REL
    vendored_dir = root / VENDORED_REL
    loader = root / LOADER_REL
    connectors = root / CONNECTORS_REL
    for path in (catalog_dir, vendored_dir, loader, connectors):
        if not path.exists():
            raise GateError(f"expected input does not exist: {path}")

    catalogs = load_catalogs(catalog_dir)
    fixture_types: dict[str, set[str]] = {}
    missing_fixtures: dict[str, list[str]] = {}
    for source, catalog in catalogs.items():
        found, missing = event_types_in_fixtures(root, catalog)
        fixture_types[source] = found
        missing_fixtures[source] = missing

    data = {
        "catalogs": catalogs,
        "fixture_types": fixture_types,
        "missing_fixtures": missing_fixtures,
        "source_bytes": {p.name: p.read_bytes() for p in sorted(catalog_dir.glob("*.yaml"))},
        "vendored_bytes": {p.name: p.read_bytes() for p in sorted(vendored_dir.glob("*.yaml"))},
        "go_sensitivities": parse_go_sensitivities(loader.read_text(encoding="utf-8")),
        "declared_connectors": parse_declared_connectors(connectors),
    }
    for name in ("catalogs", "source_bytes", "vendored_bytes", "go_sensitivities", "declared_connectors"):
        if not data[name]:
            raise GateError(f"parsed zero {name} — refusing to report a clean tree from an empty read")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=repo_root())
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--self-test", action="store_true", help="prove the gate detects what it claims to")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test(args.repo_root.resolve())

    root = args.repo_root.resolve()
    try:
        data = load(root)
    except GateError as exc:
        print(f"check_event_catalog: FAILED to read the tree: {exc}", file=sys.stderr)
        return 2

    failures, stats = evaluate(**data)

    if args.json:
        report = {"repo_root": str(root), **stats, "failures": [{"code": c, "detail": d} for c, d in failures]}
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if failures else 0

    print(f"repo root        {root}")
    print(f"catalogue        {CATALOG_REL}  ({len(stats['sources'])} sources, {stats['classified']} event types)")
    print(f"vendored copy    {VENDORED_REL}  ({len(data['vendored_bytes'])} files, byte-compared both ways)")
    print(f"loader           {LOADER_REL}  (ladder: {', '.join(data['go_sensitivities'])})")
    print()
    for source in stats["sources"]:
        found = stats["fixture_types"][source]
        catalog = data["catalogs"][source]
        print(f"  {source:18s} {len(catalog.get('events') or {}):>3} classified   {len(found):>3} in fixtures")
    print()
    tiers = "  ".join(f"{tier}={count}" for tier, count in stats["by_sensitivity"].items())
    print(f"by sensitivity   {tiers}")
    print()
    if failures:
        print(f"FAIL — {len(failures)} finding(s):")
        for code, detail in failures:
            print(f"  [{code}] {detail}")
        return 1
    print("OK — every event type in every declared fixture is classified or excused,")
    print("     every sensitivity is on the ladder, and the vendored copy matches.")
    return 0


def self_test(root: Path) -> int:
    """Inject each defect the gate claims to catch and require it to bite."""
    try:
        base = load(root)
    except GateError as exc:
        print(f"self-test: cannot read the tree: {exc}", file=sys.stderr)
        return 2

    clean, _ = evaluate(**base)
    if clean:
        print("self-test: the unmodified tree already fails; fix that first", file=sys.stderr)
        for code, detail in clean:
            print(f"  [{code}] {detail}", file=sys.stderr)
        return 1

    def mutate(**overrides) -> dict:
        import copy

        data = copy.deepcopy(base)
        for key, fn in overrides.items():
            fn(data[key])
        return data

    any_source = sorted(base["catalogs"])[0]
    any_file = sorted(base["source_bytes"])[0]

    cases = [
        (
            "CORPUS: a fixture event type that is neither classified nor excused",
            "event-type-unclassified",
            mutate(fixture_types=lambda d: d[any_source].add("SomethingNobodyClassified")),
        ),
        (
            "CORPUS: a source whose fixtures yield nothing, so the gate would check nothing",
            "fixture-corpus-empty",
            mutate(fixture_types=lambda d: d.__setitem__(any_source, set())),
        ),
        (
            "CORPUS: a declared fixture file that does not exist",
            "fixture-missing",
            mutate(missing_fixtures=lambda d: d.__setitem__(any_source, ["services/connectors/tests/not_there.py"])),
        ),
        (
            "LADDER: a sensitivity outside the five tiers",
            "sensitivity-invalid",
            mutate(catalogs=lambda d: d[any_source]["events"].__setitem__("X", {"action": "x", "sensitivity": "severe"})),
        ),
        (
            "LADDER: the loader and the gate disagreeing about the ladder",
            "ladder-mismatch",
            mutate(go_sensitivities=lambda lst: lst.append("catastrophic")),
        ),
        (
            "ENTRY: a classification with no normalized action",
            "action-missing",
            mutate(catalogs=lambda d: d[any_source]["events"].__setitem__("Y", {"sensitivity": "low"})),
        ),
        (
            "ENTRY: a malformed ATT&CK hint",
            "attack-malformed",
            mutate(
                catalogs=lambda d: d[any_source]["events"].__setitem__("Z", {"action": "z", "sensitivity": "low", "attack": ["TA0001"]})
            ),
        ),
        (
            "ENTRY: an excuse too thin to review",
            "excuse-thin",
            mutate(catalogs=lambda d: d[any_source].__setitem__("unclassified", {"Q": "noisy"})),
        ),
        (
            "ENTRY: an event type both classified and excused",
            "entry-both",
            mutate(
                catalogs=lambda d: d[any_source].__setitem__(
                    "unclassified", {next(iter(d[any_source]["events"])): "a reason long enough to pass the length check"}
                )
            ),
        ),
        (
            "SOURCE: a catalogue for a connector that does not exist",
            "source-names-nothing",
            mutate(catalogs=lambda d: d.__setitem__("acme_xdr_9000", {**d[any_source], "__file__": "acme.yaml"})),
        ),
        (
            "VENDORED: the embedded copy differs from the file a reviewer edits",
            "vendored-drift",
            mutate(vendored_bytes=lambda d: d.__setitem__(any_file, b"# drifted\n")),
        ),
        (
            "VENDORED: a catalogue file the binary does not carry",
            "vendored-missing",
            mutate(source_bytes=lambda d: d.__setitem__("new_source.yaml", b"source: x\n")),
        ),
        (
            "VENDORED: an embedded file nobody edits",
            "vendored-orphan",
            mutate(vendored_bytes=lambda d: d.__setitem__("orphan.yaml", b"source: x\n")),
        ),
    ]

    print(f"self-test against {root}")
    print("clean tree: 0 failures (the baseline every case below perturbs)\n")
    ok = True
    for description, expected_code, data in cases:
        found, _ = evaluate(**data)
        codes = {code for code, _ in found}
        caught = expected_code in codes
        ok &= caught
        print(f"  {'PASS' if caught else 'FAIL'}  {description}")
        print(f"        expected [{expected_code}]  got {sorted(codes) or 'nothing'}")

    empty_refused = True
    try:
        load(Path("/nonexistent-tree-for-the-self-test"))
        empty_refused = False
    except GateError:
        # Refusing an empty tree is the behaviour under test, so the
        # exception is the pass and there is nothing to handle.
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
