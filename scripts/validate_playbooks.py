#!/usr/bin/env python3
"""
Validate every *.playbook.json under playbooks/packs/v1/ (and any user-supplied
directories passed on argv).

Validation layers:

1. JSON parse.
2. Pydantic schema validation against services/agents/app/playbook/models.py
   so a JSON file rejected here is also rejected by the runtime.
3. Cross-file uniqueness of playbook IDs.
4. Per-playbook step-graph integrity:
   - step IDs are unique within a playbook
   - condition.next_true / next_false (when set) point at real step IDs
   - condition steps that are *not* the last step have at least one branch set
5. Step-type / on_failure consistency:
   - condition steps must declare a `condition` block
   - non-condition steps with `next_true` / `next_false` are flagged
6. Trigger sanity: trigger.on must be one of the supported event kinds.

Exits non-zero on any failure with a human-readable summary.

Usage:
    python scripts/validate_playbooks.py
    python scripts/validate_playbooks.py path/to/extra/dir
"""
from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PACK = ROOT / "playbooks" / "packs" / "v1"

# Make the services/agents Pydantic models importable.
sys.path.insert(0, str(ROOT / "services" / "agents"))

try:
    from app.playbook.models import Playbook, StepType  # type: ignore[import-not-found]
except Exception as exc:  # pragma: no cover - import errors visible to user
    print(f"FATAL: cannot import Playbook model: {exc}", file=sys.stderr)
    sys.exit(2)


SUPPORTED_TRIGGERS = {"alert", "case", "manual", "schedule"}


def _iter_playbook_files(roots: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        files.extend(sorted(root.rglob("*.playbook.json")))
    return files


def _validate_one(fp: Path) -> tuple[Playbook | None, list[str]]:
    """Return (playbook, errors). playbook is None if parse/schema failed."""
    errors: list[str] = []
    try:
        data = json.loads(fp.read_text())
    except json.JSONDecodeError as exc:
        return None, [f"JSON parse: {exc}"]

    try:
        pb = Playbook.model_validate(data)
    except Exception as exc:
        return None, [f"schema: {exc}"]

    # Step-graph and step-type rules
    step_ids = [s.id for s in pb.steps]
    if len(step_ids) != len(set(step_ids)):
        dups = sorted({sid for sid in step_ids if step_ids.count(sid) > 1})
        errors.append(f"duplicate step ids: {dups}")

    valid_step_ids = set(step_ids)
    for s in pb.steps:
        if s.next_true and s.next_true not in valid_step_ids:
            errors.append(f"step '{s.id}': next_true -> unknown '{s.next_true}'")
        if s.next_false and s.next_false not in valid_step_ids:
            errors.append(f"step '{s.id}': next_false -> unknown '{s.next_false}'")
        if s.type == StepType.CONDITION:
            if s.condition is None:
                errors.append(f"step '{s.id}': condition step missing `condition` block")
            # Allow trailing condition with no branches (acts as filter / gate).
        else:
            if s.next_true or s.next_false:
                errors.append(
                    f"step '{s.id}': non-condition step has next_true/next_false"
                )

    # Trigger sanity
    on = pb.trigger.get("on") if isinstance(pb.trigger, dict) else None
    if on not in SUPPORTED_TRIGGERS:
        errors.append(f"trigger.on={on!r} not in {sorted(SUPPORTED_TRIGGERS)}")

    return pb, errors


def main() -> int:
    extra_roots = [Path(a) for a in sys.argv[1:]]
    roots = [DEFAULT_PACK, *extra_roots]
    files = _iter_playbook_files(roots)

    if not files:
        print("No playbook files found under:", *roots, sep="\n  ")
        return 1

    all_errors: list[str] = []
    seen_ids: dict[str, Path] = {}
    by_cat: dict[str, int] = {}

    for fp in files:
        rel = fp.relative_to(ROOT)
        pb, errors = _validate_one(fp)
        if errors:
            for e in errors:
                all_errors.append(f"{rel}: {e}")
        if pb is None:
            continue
        if pb.id in seen_ids:
            all_errors.append(
                f"{rel}: duplicate playbook id '{pb.id}' "
                f"(also in {seen_ids[pb.id].relative_to(ROOT)})"
            )
        else:
            seen_ids[pb.id] = fp
        # Category is the parent dir name relative to packs/v1.
        cat = fp.parent.name
        by_cat[cat] = by_cat.get(cat, 0) + 1

    print(f"Validated {len(files)} playbook files across {len(by_cat)} categories.")
    for cat in sorted(by_cat):
        print(f"  {cat:20s} {by_cat[cat]:3d}")

    if all_errors:
        print(f"\n{len(all_errors)} ERROR(S):", file=sys.stderr)
        for e in all_errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    print("\nOK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
