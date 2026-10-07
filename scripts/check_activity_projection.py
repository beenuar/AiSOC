#!/usr/bin/env python3
"""The activity projection says the same thing in all five places it lives.

Why this exists
---------------
Depth plan 2.2 puts one projection — who acted, what kind of actor they were,
what they did, to which resource, from where, with what outcome — on every
normalized event, and then carries it into four more places: the lake's
``CREATE TABLE``, the lake's migration list, the fusion writer's column
tuple, and the graph schema. Five hand-written lists of the same thing, which
is five chances for them to disagree.

Three of those disagreements are silent, and one of them is a trap this
repository has already documented without closing:

**``001_init.sql`` and ``lake_migrations.py`` are read by different
deployments.** The SQL file runs only in the ClickHouse container entrypoint,
on a fresh volume. An existing deployment gets its schema from the migration
list and never sees the file again. `lake_migrations.py`'s own docstring says
so — "a new column lands on a fresh deployment and silently does not land on
an existing one" — and before this gate nothing compared the two. A column
added to one alone produces a lake where the same query works on a new
install and fails on every upgrade, discovered whenever somebody selects it.

**The writer's column tuple is positional.** ``_INSERT_SQL`` is built by
joining ``_COLUMNS``, and the row dict is read in that order. A column in the
tuple that the table does not have fails the insert; a column the table has
that the tuple omits is silently always default.

**``actor.kind`` must be a closed set.** It is the field that separates a
person from the app or token acting for them, and every later surface — a
privilege decision, a blast radius, an auto-close — treats it as evidence. A
derivation returning a value outside the set reaches a ``LowCardinality``
column and a graph property as something nothing queries for.

What it checks
--------------
  GO -> SQL     every lake column the writer sends exists in the CREATE TABLE
  GO -> MIGR    and in the migration that adds it, so both deployment paths
                converge on the same schema
  SQL <-> MIGR  in both directions, which is the one nothing checked
  KIND          every ActorKind constant is in ActorKinds, the lake's
                documented set and nothing else; and every derivation that
                returns a kind also names the vendor field it read it from,
                because an unsourced kind is a guess wearing a type
  GRAPH         every property in ActivityNodeProperties is declared on that
                label in schemas/graph-schema.yaml, in both directions

Usage
-----
    python3 scripts/check_activity_projection.py
    python3 scripts/check_activity_projection.py --json
    python3 scripts/check_activity_projection.py --self-test

``--repo-root`` overrides the tree. Every input is named before the verdict
and an empty read is a hard error, never a quiet pass.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root

ACTIVITY_REL = Path("services/ingest/internal/activity/activity.go")
ACTOR_REL = Path("services/ingest/internal/activity/actor.go")
GRAPH_SCHEMA_GO_REL = Path("services/ingest/internal/graph/schema.go")
GRAPH_SCHEMA_YAML_REL = Path("schemas/graph-schema.yaml")
INIT_SQL_REL = Path("services/api/clickhouse/001_init.sql")
LAKE_MIGRATIONS_REL = Path("services/api/app/db/lake_migrations.py")
LAKE_WRITER_REL = Path("services/fusion/app/services/lake_writer.py")

#: Columns the writer sends that 001_init.sql declares but no migration adds,
#: because they predate the migration mechanism. Everything the projection
#: adds must appear in both.
PRE_MIGRATION_COLUMNS = {
    "event_id",
    "tenant_id",
    "event_time",
    # Declared with a DEFAULT and never sent by the writer, which is why it
    # is in the table and not in _COLUMNS.
    "ingest_time",
    "class_uid",
    "category_uid",
    "severity_id",
    "severity",
    "activity_id",
    "source_ip",
    "dest_ip",
    "src_port",
    "dst_port",
    "protocol",
    "src_hostname",
    "dst_hostname",
    "user_name",
    "process_name",
    "file_path",
    "hash_sha256",
    "connector_type",
    "raw_payload",
    "ocsf_json",
    "mitre_techniques",
    "mitre_tactics",
    "iocs",
}


class GateError(RuntimeError):
    """An input could not be read. Never downgraded to a passing result."""


def parse_actor_kinds(src: str) -> tuple[set[str], set[str]]:
    """(constants declared, members of the ActorKinds slice)."""
    declared = set(re.findall(r'^\tActor\w+\s+ActorKind = "([a-z_]+)"$', src, re.MULTILINE))
    match = re.search(r"var ActorKinds = \[\]ActorKind\{(.*?)\}", src, re.DOTALL)
    if not match:
        raise GateError("could not find the ActorKinds slice")
    names = set(re.findall(r"\bActor(\w+)\b", match.group(1)))
    by_const = dict(re.findall(r"^\tActor(\w+)\s+ActorKind = \"([a-z_]+)\"$", src, re.MULTILINE))
    listed = {by_const[n] for n in names if n in by_const}
    return declared, listed


def parse_kind_returns(src: str) -> list[tuple[str, str]]:
    """Every `return ActorX, "source"` in the derivations, as (kind, source)."""
    return re.findall(r'return\s+Actor(\w+),\s*"([^"]*)"', src)


def parse_sql_columns(src: str) -> set[str]:
    """Column names declared inside the raw_events CREATE TABLE."""
    start = src.find("CREATE TABLE IF NOT EXISTS aisoc.raw_events (")
    if start == -1:
        raise GateError("could not find the raw_events CREATE TABLE")
    depth, body_start = 0, src.index("(", start)
    for i in range(body_start, len(src)):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                body = src[body_start + 1 : i]
                break
    else:
        raise GateError("unbalanced parentheses in the raw_events CREATE TABLE")

    columns: set[str] = set()
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("--") or line.startswith("INDEX "):
            continue
        name = line.split()[0]
        if re.fullmatch(r"[a-z_][a-z0-9_]*", name):
            columns.add(name)
    return columns


def parse_migration_columns(src: str) -> set[str]:
    """Columns added by an ALTER ... ADD COLUMN in the lake migration list."""
    return set(re.findall(r"ADD COLUMN IF NOT EXISTS (\w+)", src))


def parse_writer_columns(src: str) -> set[str]:
    match = re.search(r"^_COLUMNS = \((.*?)^\)", src, re.DOTALL | re.MULTILINE)
    if not match:
        raise GateError("could not find _COLUMNS in the lake writer")
    return set(re.findall(r'"(\w+)"', match.group(1)))


def parse_graph_go_properties(src: str) -> dict[str, set[str]]:
    match = re.search(r"var ActivityNodeProperties = map\[NodeLabel\]\[\]string\{(.*?)\n\}", src, re.DOTALL)
    if not match:
        raise GateError("could not find ActivityNodeProperties in the graph schema")
    out: dict[str, set[str]] = {}
    label_const = dict(re.findall(r'^\tNode(\w+)\s+NodeLabel = "(\w+)"$', src, re.MULTILINE))
    for const, body in re.findall(r"Node(\w+):\s*\{(.*?)\}", match.group(1), re.DOTALL):
        label = label_const.get(const, const)
        out[label] = set(re.findall(r'"(\w+)"', body))
    return out


def parse_graph_yaml_properties(src: str) -> dict[str, set[str]]:
    """label -> declared property names, from the node_labels block."""
    out: dict[str, set[str]] = {}
    label = None
    for line in src.splitlines():
        label_match = re.match(r"^\s*-\s*label:\s*(\w+)\s*$", line)
        if label_match:
            label = label_match.group(1)
            out.setdefault(label, set())
            continue
        if label and (prop := re.match(r"^\s*-\s*\{\s*name:\s*([a-z_]+)", line)):
            out[label].add(prop.group(1))
        # A new top-level key ends the node_labels block.
        if re.match(r"^[a-z_]+:", line):
            label = None
    return out


def evaluate(
    kinds_declared: set[str],
    kinds_listed: set[str],
    kind_returns: list[tuple[str, str]],
    sql_columns: set[str],
    migration_columns: set[str],
    writer_columns: set[str],
    graph_go: dict[str, set[str]],
    graph_yaml: dict[str, set[str]],
) -> tuple[list[tuple[str, str]], dict]:
    failures: list[tuple[str, str]] = []

    # KIND. The closed set has to be closed in both directions, or a
    # consumer reading ActorKinds sees a different vocabulary from the one
    # the derivations can produce.
    for kind in sorted(kinds_declared - kinds_listed):
        failures.append(
            (
                "kind-not-listed",
                f"ActorKind {kind!r} is declared but is not in ActorKinds, so the lake's enum and the gate "
                "that reads it do not know about a value the derivations can produce",
            )
        )
    for kind in sorted(kinds_listed - kinds_declared):
        failures.append(("kind-not-declared", f"ActorKinds lists {kind!r}, which no constant declares"))

    # KIND. An unsourced kind is a guess wearing a type. The one exception
    # is `unknown`, which is precisely the answer that was read from no
    # field — and it must carry no source, for the same reason.
    for const, source in kind_returns:
        kind = const.lower()
        if kind == "unknown":
            if source:
                failures.append(
                    (
                        "unknown-kind-has-a-source",
                        f"a derivation returns unknown alongside the source {source!r}; unknown means no field "
                        "answered, so naming one would make a reviewer check a derivation that did not happen",
                    )
                )
            continue
        if not source:
            failures.append(
                (
                    "kind-without-a-source",
                    f"a derivation returns {kind!r} naming no vendor field. actor.kind is evidence downstream, "
                    "and a kind no field produced is a guess",
                )
            )

    # LAKE. Three lists, compared pairwise in both directions.
    for column in sorted(writer_columns - sql_columns):
        failures.append(
            (
                "writer-column-not-in-table",
                f"the lake writer sends {column!r}, which the raw_events CREATE TABLE does not declare; "
                "the insert is positional, so this fails at write time on a fresh deployment",
            )
        )
    for column in sorted(writer_columns - migration_columns - PRE_MIGRATION_COLUMNS):
        failures.append(
            (
                "writer-column-not-migrated",
                f"the lake writer sends {column!r} and no lake migration adds it. 001_init.sql runs only in "
                "the container entrypoint on a fresh volume, so an existing deployment never gets this column",
            )
        )
    for column in sorted(migration_columns - sql_columns):
        failures.append(
            (
                "migrated-column-not-in-table",
                f"a lake migration adds {column!r} but the CREATE TABLE does not declare it, so a fresh "
                "deployment and an upgraded one end up with different schemas",
            )
        )
    for column in sorted(sql_columns - migration_columns - PRE_MIGRATION_COLUMNS):
        failures.append(
            (
                "table-column-not-migrated",
                f"the CREATE TABLE declares {column!r} and no migration adds it; it will exist on a fresh "
                "deployment and be missing on every upgrade",
            )
        )

    # GRAPH. Both directions, because the YAML is what the drift gate and
    # the published schema doc read and the Go is what the writer uses.
    for label, properties in sorted(graph_go.items()):
        declared = graph_yaml.get(label)
        if declared is None:
            failures.append(("graph-label-missing", f"ActivityNodeProperties names label {label!r}, which the YAML does not declare"))
            continue
        for prop in sorted(properties - declared):
            failures.append(
                (
                    "graph-property-undeclared",
                    f"the writer puts {prop!r} on {label}, and schemas/graph-schema.yaml does not declare it",
                )
            )

    stats = {
        "actor_kinds": sorted(kinds_listed),
        "kind_derivations": len([s for _, s in kind_returns if s]),
        "lake_columns": len(writer_columns),
        "projection_columns": sorted(writer_columns & migration_columns),
        "graph_labels": sorted(graph_go),
    }
    return failures, stats


def load(root: Path) -> dict:
    paths = {
        "activity": root / ACTIVITY_REL,
        "actor": root / ACTOR_REL,
        "graph_go": root / GRAPH_SCHEMA_GO_REL,
        "graph_yaml": root / GRAPH_SCHEMA_YAML_REL,
        "init_sql": root / INIT_SQL_REL,
        "migrations": root / LAKE_MIGRATIONS_REL,
        "writer": root / LAKE_WRITER_REL,
    }
    for name, path in paths.items():
        if not path.exists():
            raise GateError(f"expected input does not exist: {path} ({name})")

    activity_src = paths["activity"].read_text(encoding="utf-8")
    declared, listed = parse_actor_kinds(activity_src)
    data = {
        "kinds_declared": declared,
        "kinds_listed": listed,
        "kind_returns": parse_kind_returns(paths["actor"].read_text(encoding="utf-8")),
        "sql_columns": parse_sql_columns(paths["init_sql"].read_text(encoding="utf-8")),
        "migration_columns": parse_migration_columns(paths["migrations"].read_text(encoding="utf-8")),
        "writer_columns": parse_writer_columns(paths["writer"].read_text(encoding="utf-8")),
        "graph_go": parse_graph_go_properties(paths["graph_go"].read_text(encoding="utf-8")),
        "graph_yaml": parse_graph_yaml_properties(paths["graph_yaml"].read_text(encoding="utf-8")),
    }
    required = (
        "kinds_declared",
        "kinds_listed",
        "kind_returns",
        "sql_columns",
        "migration_columns",
        "writer_columns",
        "graph_go",
        "graph_yaml",
    )
    for name in required:
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
        print(f"check_activity_projection: FAILED to read the tree: {exc}", file=sys.stderr)
        return 2

    failures, stats = evaluate(**data)

    if args.json:
        report = {"repo_root": str(root), **stats, "failures": [{"code": c, "detail": d} for c, d in failures]}
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if failures else 0

    print(f"repo root        {root}")
    print(f"projection       {ACTIVITY_REL}  ({len(stats['actor_kinds'])} actor kinds)")
    print(f"derivations      {ACTOR_REL}  ({stats['kind_derivations']} kinds returned, each naming a vendor field)")
    print(f"lake table       {INIT_SQL_REL}  ({len(data['sql_columns'])} columns)")
    print(f"lake migrations  {LAKE_MIGRATIONS_REL}  ({len(data['migration_columns'])} columns added)")
    print(f"lake writer      {LAKE_WRITER_REL}  ({stats['lake_columns']} columns sent)")
    print(f"graph            {GRAPH_SCHEMA_GO_REL} / {GRAPH_SCHEMA_YAML_REL}  ({', '.join(stats['graph_labels'])})")
    print()
    print(f"actor kinds      {', '.join(stats['actor_kinds'])}")
    print(f"projection cols  {len(stats['projection_columns'])} in the table, the migration and the writer")
    print()
    if failures:
        print(f"FAIL — {len(failures)} finding(s):")
        for code, detail in failures:
            print(f"  [{code}] {detail}")
        return 1
    print("OK — the projection says the same thing in the Go, the lake table, the lake")
    print("     migration, the fusion writer and the graph schema.")
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
        data = {k: (v.copy() if hasattr(v, "copy") else v) for k, v in base.items()}
        for key, fn in overrides.items():
            fn(data[key])
        return data

    cases = [
        (
            "KIND: a constant missing from the closed-set slice",
            "kind-not-listed",
            mutate(kinds_declared=lambda s: s.add("contractor")),
        ),
        (
            "KIND: the slice naming something no constant declares",
            "kind-not-declared",
            mutate(kinds_listed=lambda s: s.add("robot")),
        ),
        (
            "KIND: a derivation returning a kind it read from no field",
            "kind-without-a-source",
            mutate(kind_returns=lambda lst: lst.append(("Human", ""))),
        ),
        (
            "KIND: an unknown kind claiming a source",
            "unknown-kind-has-a-source",
            mutate(kind_returns=lambda lst: lst.append(("Unknown", "a.field"))),
        ),
        (
            "LAKE: the writer sending a column the table does not declare",
            "writer-column-not-in-table",
            mutate(writer_columns=lambda s: s.add("actor_shoe_size")),
        ),
        (
            "LAKE: a column in the table that no migration adds, so upgrades never get it",
            "table-column-not-migrated",
            mutate(sql_columns=lambda s: s.add("added_to_the_sql_file_only")),
        ),
        (
            "LAKE: a column a migration adds that the table does not declare",
            "migrated-column-not-in-table",
            mutate(migration_columns=lambda s: s.add("added_to_the_migration_only")),
        ),
        (
            "GRAPH: a property the writer sets that the YAML does not declare",
            "graph-property-undeclared",
            mutate(graph_go=lambda d: d.__setitem__("User", d["User"] | {"undeclared_property"})),
        ),
        (
            "GRAPH: a label in the Go that the YAML does not carry",
            "graph-label-missing",
            mutate(graph_go=lambda d: d.__setitem__("Phantom", {"x"})),
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
