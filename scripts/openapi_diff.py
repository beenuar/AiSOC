#!/usr/bin/env python3
"""OpenAPI breaking-change detector (Phase 11 — API/SDK/release engineering).

`check-openapi.yml` proves the committed spec matches the code (drift), but has
**no breaking-change semantics** — the reality audit's `NO GATE` row. A PR could
delete an endpoint, remove a response field, tighten a request, or drop an enum
value and every check stays green while every generated SDK client silently
breaks.

This is a dependency-light (pyyaml only) diff that classifies the changes
between two OpenAPI specs as **breaking** or non-breaking, from the perspective
of an existing generated client. Breaking classes:

* a path or operation (method) was removed,
* a component schema was removed,
* a property was removed from a schema (a response consumer relying on it breaks),
* a property's type signature changed,
* a property went optional → required, or a new required property was added to a
  *request*-shaped schema (an existing caller's payload is now rejected),
* an enum value was removed (a client with exhaustive handling breaks),
* a new required parameter was added to an existing operation.

`--old`/`--new` take spec files; exit 1 if any breaking change is found. The CI
job (`openapi-breaking.yml`) diffs the PR spec against the base branch's spec,
so a breaking change blocks the PR until it is deliberate.

Shipping one deliberately goes through `--allow-breaking`, which the gate passes
only when a maintainer has applied the `breaking-change-approved` label to the
pull request. The flag is not a silent bypass: it *requires* `--changelog` and
`--changelog-base`, refuses the approval unless this change added a `### BREAKING`
note under `## [Unreleased]`, and prints every break it is permitting — so the
record says what was approved rather than merely that something was.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import self_test_if_requested

self_test_if_requested(__file__)

# Schema-name suffixes that indicate a request body (tightening these breaks
# callers). Response-shaped schemas don't break a caller when a new optional
# field appears, so a *new* required field only counts as breaking here.
_REQUEST_SUFFIXES = ("Request", "Create", "Update", "In", "Input", "Payload", "Body")


@dataclass(frozen=True)
class Change:
    breaking: bool
    kind: str
    detail: str


def _type_signature(prop: dict[str, Any]) -> str:
    """A comparable signature for a property's type. $ref, type, array item."""
    if not isinstance(prop, dict):
        return "any"
    if "$ref" in prop:
        return f"ref:{prop['$ref']}"
    if "anyOf" in prop or "oneOf" in prop:
        variants = prop.get("anyOf") or prop.get("oneOf") or []
        return "union:" + ",".join(sorted(_type_signature(v) for v in variants))
    t = prop.get("type")
    if t == "array":
        return f"array<{_type_signature(prop.get('items', {}))}>"
    if t is not None:
        return str(t)
    return "any"


def _schemas(spec: dict[str, Any]) -> dict[str, Any]:
    return (spec.get("components") or {}).get("schemas") or {}


def _op_params(op: dict[str, Any]) -> dict[str, bool]:
    """name → required, for an operation's parameters."""
    out: dict[str, bool] = {}
    for p in op.get("parameters") or []:
        if isinstance(p, dict) and "name" in p:
            out[str(p["name"])] = bool(p.get("required", False))
    return out


def _is_request_schema(name: str) -> bool:
    return any(name.endswith(sfx) for sfx in _REQUEST_SUFFIXES)


def diff(old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
    changes: list[Change] = []

    # ── paths + operations ──────────────────────────────────────────────────
    old_paths = old.get("paths") or {}
    new_paths = new.get("paths") or {}
    _METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
    for path, old_item in old_paths.items():
        if path not in new_paths:
            changes.append(Change(True, "path_removed", f"path '{path}' was removed"))
            continue
        new_item = new_paths[path]
        for method in _METHODS:
            if method in (old_item or {}):
                if method not in (new_item or {}):
                    changes.append(Change(True, "operation_removed", f"{method.upper()} {path} was removed"))
                    continue
                old_params = _op_params(old_item[method])
                new_params = _op_params(new_item[method])
                for name, required in new_params.items():
                    if required and name not in old_params:
                        changes.append(Change(True, "required_param_added", f"{method.upper()} {path}: new required parameter '{name}'"))
                for name in old_params:
                    if not old_params[name] and new_params.get(name) is True:
                        changes.append(Change(True, "param_now_required", f"{method.upper()} {path}: parameter '{name}' became required"))

    # ── component schemas ──────────────────────────────────────────────────
    old_schemas = _schemas(old)
    new_schemas = _schemas(new)
    for name, old_schema in old_schemas.items():
        if name not in new_schemas:
            changes.append(Change(True, "schema_removed", f"schema '{name}' was removed"))
            continue
        new_schema = new_schemas[name]
        old_props = old_schema.get("properties") or {}
        new_props = new_schema.get("properties") or {}
        old_required = set(old_schema.get("required") or [])
        new_required = set(new_schema.get("required") or [])

        for prop_name, old_prop in old_props.items():
            if prop_name not in new_props:
                changes.append(Change(True, "property_removed", f"{name}.{prop_name} was removed"))
                continue
            old_sig = _type_signature(old_prop)
            new_sig = _type_signature(new_props[prop_name])
            if old_sig != new_sig:
                changes.append(Change(True, "property_type_changed", f"{name}.{prop_name}: {old_sig} → {new_sig}"))
            # optional → required
            if prop_name in new_required and prop_name not in old_required:
                changes.append(Change(True, "property_now_required", f"{name}.{prop_name} became required"))

        # new required property on a request-shaped schema tightens callers
        if _is_request_schema(name):
            for prop_name in new_required - old_required:
                if prop_name not in old_props:
                    changes.append(Change(True, "required_property_added", f"{name}.{prop_name} is a new required request field"))

        # enum narrowing (per property)
        for prop_name, old_prop in old_props.items():
            if prop_name not in new_props:
                continue
            old_enum = set(old_prop.get("enum") or []) if isinstance(old_prop, dict) else set()
            new_enum = set(new_props[prop_name].get("enum") or []) if isinstance(new_props[prop_name], dict) else set()
            if old_enum and (removed := old_enum - new_enum):
                changes.append(Change(True, "enum_value_removed", f"{name}.{prop_name}: enum values removed {sorted(map(str, removed))}"))

    return changes


def load_spec(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


# ── CHANGELOG evidence for an approved break ────────────────────────────────
#
# The approval label says a maintainer authorised the break. The CHANGELOG note
# is what says *what* was broken, and it is the half that outlives CI logs.

_H2 = re.compile(r"^##\s+")
_H3 = re.compile(r"^###\s+")
_UNRELEASED = re.compile(r"^##\s+\[Unreleased\]", re.IGNORECASE)
_BREAKING_HEADING = re.compile(r"^###\s+BREAKING\b", re.IGNORECASE)


def changelog_breaking_notes(text: str) -> list[str]:
    """Non-blank lines under `### BREAKING` inside the `## [Unreleased]` section.

    Scoped to Unreleased on purpose: a BREAKING heading in an already-shipped
    release section describes a past break and must not stand in for this one.
    """
    lines = text.splitlines()
    start = next((n for n, line in enumerate(lines) if _UNRELEASED.match(line)), None)
    if start is None:
        return []
    notes: list[str] = []
    in_breaking = False
    for line in lines[start + 1 :]:
        if _H2.match(line):  # the next release section — Unreleased has ended
            break
        if _H3.match(line):
            in_breaking = bool(_BREAKING_HEADING.match(line))
            continue
        if in_breaking and line.strip():
            notes.append(line.strip())
    return notes


def changelog_evidence(old_text: str, new_text: str) -> tuple[list[str], str | None]:
    """Notes this change added, or a reason the approval cannot be honoured.

    Checked in both directions. "A BREAKING section exists" alone would let the
    first such note in a release cycle excuse every later break in that cycle,
    so the note must also differ from the base branch's.
    """
    new_notes = changelog_breaking_notes(new_text)
    if not new_notes:
        return [], "the CHANGELOG has no '### BREAKING' section with content under '## [Unreleased]'"
    old_notes = set(changelog_breaking_notes(old_text))
    added = [note for note in new_notes if note not in old_notes]
    if not added:
        return [], (
            "the '### BREAKING' section under '## [Unreleased]' is byte-identical to the "
            "base branch's, so it documents an earlier break and not this one"
        )
    return added, None


def approval_record(breaking: list[Change], notes: list[str], approved_by: str) -> str:
    """The audit line: who permitted it, and exactly what they permitted."""
    lines = [
        "## Breaking OpenAPI changes PERMITTED",
        "",
        f"Authorised by: {approved_by or 'not resolved — see the pull request timeline'}",
        "",
        f"The detector ran and found {len(breaking)} breaking change(s). All are permitted:",
        "",
    ]
    lines += [f"- `{c.kind}` — {c.detail}" for c in breaking]
    lines += ["", "CHANGELOG `### BREAKING` note added by this change:", ""]
    lines += [f"> {note}" for note in notes]
    return "\n".join(lines)


def _write_step_summary(record: str) -> None:
    """Mirror the record onto the check-run page, not just into the job log."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(record + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--old", required=True, type=Path, help="baseline spec (e.g. base branch / last release)")
    parser.add_argument("--new", required=True, type=Path, help="candidate spec (e.g. this PR)")
    parser.add_argument(
        "--allow-breaking",
        action="store_true",
        help="permit breaking changes; requires --changelog/--changelog-base as evidence",
    )
    parser.add_argument("--changelog", type=Path, help="candidate CHANGELOG.md (required with --allow-breaking)")
    parser.add_argument("--changelog-base", type=Path, help="baseline CHANGELOG.md (required with --allow-breaking)")
    parser.add_argument("--approved-by", default="", help="who authorised the break; recorded in the audit line")
    args = parser.parse_args(argv)

    # A bypass that can be taken on trust is not auditable. Requiring the
    # evidence as arguments means --allow-breaking cannot be wired up later
    # without also wiring up the thing that records what was approved.
    if args.allow_breaking and not (args.changelog and args.changelog_base):
        parser.error("--allow-breaking requires --changelog and --changelog-base (the CHANGELOG BREAKING note is the evidence)")

    old = load_spec(args.old)
    new = load_spec(args.new)
    changes = diff(old, new)
    breaking = [c for c in changes if c.breaking]

    if not breaking:
        print(f"OK: no breaking OpenAPI changes ({len(changes)} total change(s))")
        return 0

    # The detector runs and names every break whether or not it is approved.
    print(f"Found {len(breaking)} BREAKING OpenAPI change(s):", file=sys.stderr)
    for c in breaking:
        print(f"  - [{c.kind}] {c.detail}", file=sys.stderr)

    if not args.allow_breaking:
        print(
            "\nBreaking API changes break every generated SDK client. Either avoid the "
            "break, or ship it deliberately: add a '### BREAKING' note under "
            "'## [Unreleased]' in CHANGELOG.md saying what moved and why it could not "
            "be preserved, then have a maintainer apply the 'breaking-change-approved' "
            "label to the pull request.",
            file=sys.stderr,
        )
        return 1

    notes, problem = changelog_evidence(
        args.changelog_base.read_text(encoding="utf-8"),
        args.changelog.read_text(encoding="utf-8"),
    )
    if problem:
        print(
            f"\nApproval REFUSED: {problem}. The label authorises a break; the CHANGELOG "
            "note is what records which break, and it has to outlive this job log.",
            file=sys.stderr,
        )
        return 1

    record = approval_record(breaking, notes, args.approved_by)
    print(record)
    _write_step_summary(record)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
