#!/usr/bin/env python3
"""Export, validate, and regenerate the AiSOC security knowledge graph schema.

This script is the drift gate that keeps three representations of the schema
in lockstep:

1. ``schemas/graph-schema.yaml`` — the source of truth checked into the repo.
2. ``services/ingest/internal/graph/schema.go`` — the Go enums consumed by
   the ingest writer (may not exist yet — T1.1 is concurrent).
3. The live Neo4j database materialised by ingest (when reachable).

Modes
-----

Default (no flags)
    Connect to Neo4j (env: ``AISOC_NEO4J_URI`` / ``AISOC_NEO4J_USER`` /
    ``AISOC_NEO4J_PASSWORD``, falling back to ``NEO4J_URI`` etc.) and write
    the materialised schema to ``schemas/graph-schema-current.yaml``. When
    Neo4j is unreachable, fall back to parsing the Go enums and dumping
    those.

``--check``
    Parse the on-disk YAML, parse the Go enums (when present), and the live
    database (when reachable), and fail non-zero on any drift. CI calls this.

``--from-go``
    Regenerate ``schemas/graph-schema.yaml`` from the Go enums. One-shot
    helper for the rare case where Go is the authoritative change. Refuses
    to run when the Go source file is missing.

Exit codes
----------
0
    All checked artefacts agree.
1
    Drift detected (in ``--check`` mode).
2
    Operational failure: missing input file, unreadable YAML, missing Go
    source in ``--from-go`` mode.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_YAML = REPO_ROOT / "schemas" / "graph-schema.yaml"
DEFAULT_CURRENT_YAML = REPO_ROOT / "schemas" / "graph-schema-current.yaml"
DEFAULT_GO_SOURCE = REPO_ROOT / "services" / "ingest" / "internal" / "graph" / "schema.go"

SCHEMA_VERSION = "v1.0"

# Required event-edge property set. Every relationship marked
# ``event_edge: true`` must declare all three.
EVENT_EDGE_REQUIRED = {"ts", "source_event_id", "snapshot_id"}


# ---------------------------------------------------------------------------
# YAML parsing
# ---------------------------------------------------------------------------


def _require_yaml():
    """Import PyYAML lazily so the module can be imported in environments
    without PyYAML (e.g. for ``--help``)."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:  # pragma: no cover - import guard
        sys.stderr.write(f"PyYAML is required: pip install pyyaml\n  (original error: {exc})\n")
        sys.exit(2)
    return yaml


@dataclass
class Schema:
    """In-memory representation of the schema."""

    version: str
    node_labels: list[str] = field(default_factory=list)
    relationships: list[str] = field(default_factory=list)
    label_properties: dict[str, set[str]] = field(default_factory=dict)
    relationship_properties: dict[str, set[str]] = field(default_factory=dict)
    event_edges: set[str] = field(default_factory=set)

    def summary(self) -> str:
        return (
            f"version={self.version} "
            f"labels={len(self.node_labels)} "
            f"relationships={len(self.relationships)} "
            f"event_edges={len(self.event_edges)}"
        )


def load_yaml_schema(path: Path) -> Schema:
    yaml = _require_yaml()
    if not path.exists():
        sys.stderr.write(f"schema yaml not found at {path}\n")
        sys.exit(2)
    with path.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}

    version = str(data.get("version", "")).strip()
    if not version:
        sys.stderr.write(f"{path}: missing top-level `version`\n")
        sys.exit(2)

    schema = Schema(version=version)
    for label_entry in data.get("node_labels", []) or []:
        if not isinstance(label_entry, dict):
            continue
        name = label_entry.get("label")
        if not name:
            continue
        schema.node_labels.append(name)
        props = {p["name"] for p in (label_entry.get("properties") or []) if isinstance(p, dict) and p.get("name")}
        schema.label_properties[name] = props

    for rel_entry in data.get("relationships", []) or []:
        if not isinstance(rel_entry, dict):
            continue
        name = rel_entry.get("name")
        if not name:
            continue
        schema.relationships.append(name)
        props = {p["name"] for p in (rel_entry.get("properties") or []) if isinstance(p, dict) and p.get("name")}
        schema.relationship_properties[name] = props
        if rel_entry.get("event_edge"):
            schema.event_edges.add(name)

    return schema


# ---------------------------------------------------------------------------
# Go source parsing
# ---------------------------------------------------------------------------


# Heuristic regex: match string literals on the right-hand side of a Go
# constant or variable assignment. We deliberately do not try to fully parse
# Go — the T1.1 file may declare these as ``const ( Label = "..." )``,
# ``var Label = "..."``, or as map keys. We collect every quoted string and
# bucket it by simple shape conventions:
#   * CamelCase tokens (``Identity``, ``ServiceAccount``)  → node label
#   * UPPER_SNAKE_CASE tokens (``HAS_PERMISSION``)         → relationship
# Anything else is ignored.
_STRING_LITERAL_RE = re.compile(r'"([A-Za-z][A-Za-z0-9_]*)"')


def parse_go_source(path: Path) -> tuple[set[str], set[str]] | None:
    """Extract candidate node labels and relationship names from a Go file.

    Returns ``None`` when the file does not exist (T1.1 not yet landed).
    """
    if not path.exists():
        return None
    content = path.read_text(encoding="utf-8")
    labels: set[str] = set()
    rels: set[str] = set()
    for match in _STRING_LITERAL_RE.finditer(content):
        token = match.group(1)
        # Heuristic: any lowercase letter → CamelCase label; otherwise an
        # ALL_CAPS (or ALLCAPS) token → relationship name. This handles
        # both ``HAS_PERMISSION`` and single-word relationships like
        # ``ACCESSES`` or ``OWNS`` without misclassifying ``SaaSApp``.
        if re.search(r"[a-z]", token):
            if re.fullmatch(r"[A-Z][a-zA-Z0-9]*", token):
                labels.add(token)
        elif re.fullmatch(r"[A-Z][A-Z0-9_]*", token):
            rels.add(token)
    return labels, rels


# ---------------------------------------------------------------------------
# Neo4j parsing
# ---------------------------------------------------------------------------


def _neo4j_credentials() -> tuple[str, str, str] | None:
    uri = os.environ.get("AISOC_NEO4J_URI") or os.environ.get("NEO4J_URI")
    user = os.environ.get("AISOC_NEO4J_USER") or os.environ.get("NEO4J_USER")
    password = os.environ.get("AISOC_NEO4J_PASSWORD") or os.environ.get("NEO4J_PASSWORD")
    if not uri or not user or password is None:
        return None
    return uri, user, password


def parse_live_neo4j() -> tuple[set[str], set[str]] | None:
    """Connect to Neo4j and dump labels + relationship types.

    Returns ``None`` when the ``neo4j`` driver is missing, when no credentials
    are configured, or when the connection fails — every one of these is a
    soft fall-through, not an error. Callers should treat ``None`` as "skip
    the live check".
    """
    creds = _neo4j_credentials()
    if creds is None:
        return None
    try:
        from neo4j import GraphDatabase  # type: ignore[import-untyped]
    except ImportError:
        return None

    uri, user, password = creds
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
    except Exception:
        return None

    try:
        with driver.session() as session:
            labels = {record["label"] for record in session.run("CALL db.labels() YIELD label")}
            rels = {record["relationshipType"] for record in session.run("CALL db.relationshipTypes() YIELD relationshipType")}
    except Exception:
        return None
    finally:
        try:
            driver.close()
        except Exception:
            # Closing the driver is strictly best-effort cleanup —
            # we're already on the error path. If the underlying
            # connection is already torn down (or never opened),
            # surfacing that here would just shadow the real failure
            # from the calling block above.
            pass

    return labels, rels


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _format_set(items: Iterable[str]) -> str:
    return ", ".join(sorted(items)) if items else "<none>"


def validate_yaml_internal(schema: Schema) -> list[str]:
    """Internal-consistency checks on the YAML itself."""
    errors: list[str] = []

    if schema.version != SCHEMA_VERSION:
        errors.append(
            f"schema version mismatch: YAML declares {schema.version!r}, "
            f"script expects {SCHEMA_VERSION!r}. Bump SCHEMA_VERSION in "
            f"scripts/export_graph_schema.py if this is intentional."
        )

    duplicates = [name for name in schema.node_labels if schema.node_labels.count(name) > 1]
    if duplicates:
        errors.append(f"duplicate node labels: {_format_set(set(duplicates))}")

    rel_duplicates = [name for name in schema.relationships if schema.relationships.count(name) > 1]
    if rel_duplicates:
        errors.append(f"duplicate relationships: {_format_set(set(rel_duplicates))}")

    for rel_name in schema.event_edges:
        props = schema.relationship_properties.get(rel_name, set())
        missing = EVENT_EDGE_REQUIRED - props
        if missing:
            errors.append(f"event-edge `{rel_name}` is missing required properties: {_format_set(missing)}")

    return errors


def compare_against_go(schema: Schema, go_parsed: tuple[set[str], set[str]]) -> list[str]:
    """Compare the YAML against parsed Go enums.

    The comparison is intentionally lenient on the Go side: Go may declare
    labels we already cover in the YAML (no error). Drift fires when:

    * A YAML node label is not present anywhere in Go (Go forgot to declare
      it).
    * A YAML relationship is not present anywhere in Go.
    """
    errors: list[str] = []
    go_labels, go_rels = go_parsed

    yaml_labels = set(schema.node_labels)
    yaml_rels = set(schema.relationships)

    missing_in_go_labels = yaml_labels - go_labels
    if missing_in_go_labels:
        errors.append(f"node labels declared in YAML but missing from Go source: {_format_set(missing_in_go_labels)}")

    missing_in_go_rels = yaml_rels - go_rels
    if missing_in_go_rels:
        errors.append(f"relationships declared in YAML but missing from Go source: {_format_set(missing_in_go_rels)}")

    return errors


def compare_against_live(schema: Schema, live_parsed: tuple[set[str], set[str]]) -> list[str]:
    """Compare the YAML against the live database.

    The live DB may contain labels not yet documented (drift in the other
    direction — Neo4j running ahead of the schema). Both directions are
    reported.
    """
    errors: list[str] = []
    live_labels, live_rels = live_parsed

    yaml_labels = set(schema.node_labels)
    yaml_rels = set(schema.relationships)

    in_db_not_yaml_labels = live_labels - yaml_labels
    if in_db_not_yaml_labels:
        errors.append(f"node labels materialised in Neo4j but not in YAML: {_format_set(in_db_not_yaml_labels)}")

    in_yaml_not_db_labels = yaml_labels - live_labels
    if in_yaml_not_db_labels:
        errors.append(
            "node labels declared in YAML but not yet materialised in Neo4j: "
            f"{_format_set(in_yaml_not_db_labels)} "
            "(non-fatal on a fresh DB — the writer materialises lazily)"
        )

    in_db_not_yaml_rels = live_rels - yaml_rels
    if in_db_not_yaml_rels:
        errors.append(f"relationships materialised in Neo4j but not in YAML: {_format_set(in_db_not_yaml_rels)}")

    return errors


# ---------------------------------------------------------------------------
# YAML writers
# ---------------------------------------------------------------------------


def dump_runtime_yaml(
    out_path: Path,
    *,
    source: str,
    labels: set[str],
    relationships: set[str],
    schema_version: str = SCHEMA_VERSION,
) -> None:
    """Dump the currently-materialised schema in a stable shape.

    The output is intentionally minimal: it captures what is *running*, not
    a re-spec of the source-of-truth YAML. The ``--check`` mode compares
    label/relationship *sets*, so a thin dump is enough.
    """
    yaml = _require_yaml()
    payload = {
        "version": schema_version,
        "generated_from": source,
        "node_labels": sorted(labels),
        "relationships": sorted(relationships),
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        fh.write("# Auto-generated by scripts/export_graph_schema.py — do not edit.\n")
        yaml.safe_dump(payload, fh, sort_keys=False)


def regenerate_yaml_from_go(go_parsed: tuple[set[str], set[str]], out_path: Path) -> None:
    """Regenerate the source-of-truth YAML from Go enums.

    Property declarations come from the existing on-disk YAML when the label
    or relationship is already known; brand-new entries get a stub
    ``properties: []`` that the author is expected to fill in. The point of
    ``--from-go`` is to get a fresh skeleton, not to replace human curation.
    """
    yaml = _require_yaml()
    labels, rels = go_parsed
    existing = load_yaml_schema(out_path) if out_path.exists() else Schema(version=SCHEMA_VERSION)

    existing_label_props: dict[str, list[dict]] = {}
    existing_rel_props: dict[str, list[dict]] = {}
    if out_path.exists():
        raw = yaml.safe_load(out_path.read_text(encoding="utf-8")) or {}
        for entry in raw.get("node_labels", []) or []:
            if isinstance(entry, dict) and entry.get("label"):
                existing_label_props[entry["label"]] = entry.get("properties", []) or []
        for entry in raw.get("relationships", []) or []:
            if isinstance(entry, dict) and entry.get("name"):
                existing_rel_props[entry["name"]] = entry.get("properties", []) or []

    out = {
        "version": existing.version or SCHEMA_VERSION,
        "node_labels": [
            {
                "label": label,
                "description": f"TODO: describe {label}",
                "properties": existing_label_props.get(label, []),
            }
            for label in sorted(labels)
        ],
        "relationships": [
            {
                "name": rel,
                "source_label": "TODO",
                "target_label": "TODO",
                "event_edge": False,
                "description": f"TODO: describe {rel}",
                "properties": existing_rel_props.get(rel, []),
            }
            for rel in sorted(rels)
        ],
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(
            "# Regenerated from services/ingest/internal/graph/schema.go.\n"
            "# Fill in TODOs by hand — the script can extract names, not intent.\n"
        )
        yaml.safe_dump(out, fh, sort_keys=False)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Export, validate, and regenerate the AiSOC graph schema. "
            "Default mode: dump the currently materialised schema to "
            "schemas/graph-schema-current.yaml."
        ),
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare YAML, Go source, and (if reachable) live Neo4j. Exit non-zero on drift.",
    )
    parser.add_argument(
        "--from-go",
        action="store_true",
        help="Regenerate schemas/graph-schema.yaml from the Go enums in services/ingest/internal/graph/schema.go.",
    )
    parser.add_argument(
        "--yaml-path",
        default=str(DEFAULT_YAML),
        help="Path to schemas/graph-schema.yaml (default: %(default)s).",
    )
    parser.add_argument(
        "--go-path",
        default=str(DEFAULT_GO_SOURCE),
        help="Path to the Go schema source (default: %(default)s).",
    )
    parser.add_argument(
        "--out-path",
        default=str(DEFAULT_CURRENT_YAML),
        help="Where to write the materialised-schema dump (default: %(default)s).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON summary on stdout.",
    )
    return parser.parse_args(argv)


def _emit_human(args: argparse.Namespace, lines: list[str]) -> None:
    if args.json:
        return
    for line in lines:
        print(line)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    yaml_path = Path(args.yaml_path)
    go_path = Path(args.go_path)
    out_path = Path(args.out_path)

    if args.check and args.from_go:
        sys.stderr.write("--check and --from-go are mutually exclusive\n")
        return 2

    # --from-go mode ---------------------------------------------------------
    if args.from_go:
        go_parsed = parse_go_source(go_path)
        if go_parsed is None:
            sys.stderr.write(f"--from-go requires {go_path} to exist (T1.1 not landed yet?)\n")
            return 2
        regenerate_yaml_from_go(go_parsed, yaml_path)
        _emit_human(
            args,
            [
                f"regenerated {yaml_path} from {go_path}",
                f"  labels: {len(go_parsed[0])}",
                f"  relationships: {len(go_parsed[1])}",
            ],
        )
        if args.json:
            json.dump(
                {
                    "mode": "from-go",
                    "yaml_path": str(yaml_path),
                    "labels": sorted(go_parsed[0]),
                    "relationships": sorted(go_parsed[1]),
                },
                sys.stdout,
                indent=2,
            )
            print()
        return 0

    # Both --check and default mode want the YAML loaded.
    schema = load_yaml_schema(yaml_path)
    internal_errors = validate_yaml_internal(schema)

    go_parsed = parse_go_source(go_path)
    live_parsed = parse_live_neo4j()

    # --check mode -----------------------------------------------------------
    if args.check:
        errors = list(internal_errors)
        if go_parsed is not None:
            errors.extend(compare_against_go(schema, go_parsed))
        if live_parsed is not None:
            errors.extend(compare_against_live(schema, live_parsed))

        result = {
            "mode": "check",
            "schema_summary": schema.summary(),
            "go_source_present": go_parsed is not None,
            "neo4j_reachable": live_parsed is not None,
            "errors": errors,
        }
        if args.json:
            json.dump(result, sys.stdout, indent=2)
            print()
        else:
            print(f"schema: {schema.summary()}")
            print(
                "go source: "
                + (
                    f"present ({len(go_parsed[0])} labels, {len(go_parsed[1])} rels)"
                    if go_parsed is not None
                    else f"missing — skipping (expected {go_path})"
                )
            )
            print(
                "live db: "
                + (
                    f"reachable ({len(live_parsed[0])} labels, {len(live_parsed[1])} rels)"
                    if live_parsed is not None
                    else "unreachable — skipping"
                )
            )
            if errors:
                print()
                print("DRIFT DETECTED:")
                for err in errors:
                    print(f"  - {err}")
            else:
                print()
                print("OK: schema is consistent across all available representations.")

        return 1 if errors else 0

    # Default mode -----------------------------------------------------------
    if live_parsed is not None:
        labels, rels = live_parsed
        source = "neo4j"
    elif go_parsed is not None:
        labels, rels = go_parsed
        source = "go"
    else:
        # Last-resort fallback: dump what's in the YAML so we always produce
        # an output file. This is the bootstrap case where neither T1.1 nor
        # the database is up yet.
        labels = set(schema.node_labels)
        rels = set(schema.relationships)
        source = "yaml"

    dump_runtime_yaml(
        out_path,
        source=source,
        labels=labels,
        relationships=rels,
    )

    summary = {
        "mode": "dump",
        "source": source,
        "out_path": str(out_path),
        "labels": sorted(labels),
        "relationships": sorted(rels),
    }
    if args.json:
        json.dump(summary, sys.stdout, indent=2)
        print()
    else:
        print(f"wrote {out_path} (source={source})")
        print(f"  labels: {len(labels)}")
        print(f"  relationships: {len(rels)}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
