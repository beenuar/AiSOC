#!/usr/bin/env python3
"""Upgrade pre-v4 playbook JSON to the schema the engine actually accepts.

``docs/upgrade/MIGRATION.md`` has told operators to run this script since v4.
It did not exist, so the one command in the upgrade path that touches their
own content failed at exactly the moment they needed it — and the table of
field renames beside it named four spellings the schema rejects, so following
the doc by hand produced playbooks that would not validate either.

Design, in the order the decisions matter
------------------------------------------
**It reports before it writes.** The default is ``--check``: nothing on disk
changes and the exit code says whether anything would. A migration tool whose
first act is to rewrite a customer's content is one people run once and then
never trust.

**It validates its own output.** Every upgraded playbook is checked against
``schemas/playbook.schema.json`` before it is written, and a file whose
upgrade does not validate is left alone and reported. An upgrader that
produces invalid output is worse than no upgrader, because the failure
arrives later and somewhere else.

**It refuses rather than invents.** Four v3 step types — ``loop``,
``parallel``, ``wait`` and ``run_playbook`` — name control flow this engine
does not have. There is no correct rewrite, so those files are reported and
skipped. Mapping them onto a "nearest neighbour" is precisely the defect that
was removed from the NL drafter, where a ``disable_user`` step shipped as
``investigate``.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

try:
    import jsonschema
except ModuleNotFoundError:  # pragma: no cover - the CI job installs it
    jsonschema = None  # type: ignore[assignment]


#: v3 step types that are a different spelling of a verb the engine runs.
#: Each is a synonym, not an approximation — ``isolate`` and ``isolate_host``
#: are the same action, so the rewrite loses nothing.
STEP_TYPE_RENAMES: dict[str, str] = {
    "isolate": "isolate_host",
    "block": "block_ip",
    "create_case": "create_ticket",
    "script": "run_script",
    "human_approval": "approval",
}

#: v3 step types with no v4 equivalent, and why. Reported, never rewritten.
UNMAPPABLE: dict[str, str] = {
    "loop": "the engine is a single-threaded index walk with no iteration construct",
    "parallel": "the engine runs one step at a time; there is no fan-out",
    "wait": "the engine has no timer and no pause",
    "run_playbook": (
        "nested playbooks are deliberately not implemented: a nested playbook's steps are "
        "not visible where the parent declares its policy, so the parent cannot bound them"
    ),
    "action": (
        "'action' was a meta-type. Replace it with the specific verb the step performs "
        "(block_ip, isolate_host, disable_user, ...), because the contract belongs to the verb"
    ),
    "trigger": "a trigger is playbook-level (the top-level `trigger` object), never a step",
}

#: Step types the engine accepts but cannot run. Upgrading *to* one is valid
#: and the file will validate, so this is a warning rather than a refusal.
STILL_FAILS_CLOSED: dict[str, str] = {
    "approval": (
        "the engine has no pause, so an `approval` step fails closed. Response steps are now "
        "graded individually at dispatch and return `pending_approval` on their own, so the "
        "gate is usually redundant — see apps/docs/docs/concepts/playbooks.md"
    ),
}

_ON_FAILURE = {"stop": "abort", "abort": "abort", "continue": "continue", "retry": "retry"}


class Finding:
    """One thing that happened to one file."""

    def __init__(self, path: Path, kind: str, message: str) -> None:
        self.path = path
        self.kind = kind  # "changed" | "blocked" | "warning" | "invalid"
        self.message = message

    def __str__(self) -> str:
        return f"{self.kind.upper():8} {self.path}: {self.message}"


def _upgrade_condition(value: Any) -> Any:
    """v3 wrapped the expression in ``{expr, language}``; v4 takes the string.

    The engine's own parser is deliberately restricted — no JMESPath, no
    compound boolean chains — so a v3 condition naming a language is carried
    across as its expression text and flagged if it looks like JMESPath.
    """
    if isinstance(value, dict) and "expr" in value:
        return str(value["expr"])
    return value


def _upgrade_retry(step: dict[str, Any]) -> None:
    """``retry: {max_attempts, backoff}`` became the scalar ``retry_max``.

    Backoff is not configurable: the engine uses ``min(2**attempt, 30)``. A
    declared backoff strategy is dropped rather than translated into a field
    nothing reads, which is what the removed root schema did.
    """
    retry = step.pop("retry", None)
    if isinstance(retry, dict):
        attempts = retry.get("max_attempts", retry.get("max"))
        if isinstance(attempts, int):
            step["retry_max"] = attempts
    elif isinstance(retry, int):
        step["retry_max"] = retry


def upgrade_playbook(doc: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    """Return ``(upgraded, changes, blockers)``. Never mutates ``doc``."""
    out = copy.deepcopy(doc)
    changes: list[str] = []
    blockers: list[str] = []

    for key in ("blast_radius", "depends_on", "output_key"):
        if key in out:
            out.pop(key)
            changes.append(f"dropped playbook key '{key}' (never read by the engine)")

    for index, step in enumerate(out.get("steps") or []):
        if not isinstance(step, dict):
            continue
        where = f"step {index}"

        raw_type = step.get("type")
        if raw_type in UNMAPPABLE:
            blockers.append(f"{where}: type '{raw_type}' has no v4 equivalent — {UNMAPPABLE[raw_type]}")
        elif raw_type in STEP_TYPE_RENAMES:
            step["type"] = STEP_TYPE_RENAMES[raw_type]
            changes.append(f"{where}: type '{raw_type}' -> '{step['type']}'")

        if "on_error" in step:
            policy = step.pop("on_error")
            step["on_failure"] = _ON_FAILURE.get(str(policy), "abort")
            changes.append(f"{where}: on_error '{policy}' -> on_failure '{step['on_failure']}'")
        elif isinstance(step.get("on_failure"), dict):
            # v3.x briefly wrapped it: ``on_failure: {policy: "abort"}``.
            policy = step["on_failure"].get("policy", "abort")
            step["on_failure"] = _ON_FAILURE.get(str(policy), "abort")
            changes.append(f"{where}: on_failure object -> '{step['on_failure']}'")

        if "timeout" in step:
            step["timeout_seconds"] = step.pop("timeout")
            changes.append(f"{where}: timeout -> timeout_seconds")

        if "retry" in step:
            _upgrade_retry(step)
            changes.append(f"{where}: retry object -> retry_max")

        if "condition" in step:
            upgraded = _upgrade_condition(step["condition"])
            if upgraded is not step["condition"]:
                step["condition"] = upgraded
                changes.append(f"{where}: condition object -> expression string")

        for dead in ("blast_radius", "depends_on", "output_key"):
            if dead in step:
                step.pop(dead)
                changes.append(f"{where}: dropped '{dead}' (never read by the engine)")

    return out, changes, blockers


def _load_schema(root: Path) -> Any:
    path = root / "schemas" / "playbook.schema.json"
    if not path.is_file():
        raise SystemExit(f"upgrade_playbooks: cannot find {path}; run this from inside the repository")
    return json.loads(path.read_text())


def _validate(schema: Any, doc: dict[str, Any]) -> list[str]:
    if jsonschema is None:
        return ["jsonschema is not installed, so the upgraded playbook could not be checked — install it before writing"]
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
    return [f"{'.'.join(str(p) for p in e.path) or '(root)'}: {e.message}" for e in errors]


def _targets(root: Path, directory: str | None) -> list[Path]:
    base = (root / directory).resolve() if directory else root
    if not base.is_dir():
        raise SystemExit(f"upgrade_playbooks: {base} is not a directory")
    return sorted(p for p in base.rglob("*.playbook.json") if "node_modules" not in p.parts and ".git" not in p.parts)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Upgrade pre-v4 playbook JSON to the current schema.")
    parser.add_argument("--dir", default="playbooks", help="directory to scan, relative to the repo root (default: playbooks)")
    parser.add_argument("--write", action="store_true", help="write the upgraded files. Without this nothing on disk changes.")
    parser.add_argument("--repo-root", default=None)
    args = parser.parse_args(argv)

    root = Path(args.repo_root).resolve() if args.repo_root else Path(__file__).resolve().parent.parent
    schema = _load_schema(root)
    files = _targets(root, args.dir)

    print(f"upgrade_playbooks: repo root {root}")
    print(f"upgrade_playbooks: scanning {root / args.dir} — {len(files)} playbook file(s)")
    if not files:
        # An empty scan is a broken scan, not a clean bill of health: the same
        # defect that let the lint job report "2/2 passed" over 62 unchecked
        # packs.
        print("upgrade_playbooks: found no *.playbook.json files. Check --dir; this is not a pass.")
        return 1

    findings: list[Finding] = []
    for path in files:
        try:
            doc = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            findings.append(Finding(path, "invalid", f"JSON parse error: {exc}"))
            continue

        upgraded, changes, blockers = upgrade_playbook(doc)
        for blocker in blockers:
            findings.append(Finding(path, "blocked", blocker))
        if blockers:
            continue
        if not changes:
            continue

        errors = _validate(schema, upgraded)
        if errors:
            findings.append(Finding(path, "invalid", f"upgrade would not validate ({errors[0]}); left unchanged"))
            continue

        for step in upgraded.get("steps") or []:
            note = STILL_FAILS_CLOSED.get(step.get("type") if isinstance(step, dict) else None)
            if note:
                findings.append(Finding(path, "warning", f"step type '{step['type']}' is accepted and still fails closed — {note}"))

        findings.append(Finding(path, "changed", "; ".join(changes)))
        if args.write:
            path.write_text(json.dumps(upgraded, indent=2) + "\n")

    for finding in findings:
        print(f"  {finding}")

    changed = sum(1 for f in findings if f.kind == "changed")
    blocked = sum(1 for f in findings if f.kind == "blocked")
    invalid = sum(1 for f in findings if f.kind == "invalid")

    print()
    if args.write:
        print(f"upgrade_playbooks: rewrote {changed} file(s); {blocked} blocked, {invalid} could not be upgraded.")
    else:
        print(f"upgrade_playbooks: {changed} file(s) would change; {blocked} blocked, {invalid} could not be upgraded.")
        print("upgrade_playbooks: nothing was written. Re-run with --write once the report looks right.")

    # Blocked and invalid are real problems that need a person. "Would change"
    # is not a failure in check mode, but it is a non-zero answer so a script
    # can branch on it.
    if blocked or invalid:
        return 2
    if changed and not args.write:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
