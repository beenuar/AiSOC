#!/usr/bin/env python3
"""CI gate: no detection YAML on disk that no spec generates.

`detections/*.yaml` is generated output. `scripts/generate_detections.py`
writes one file per spec and allocates its id from
`detections/rule-ids.lock.json`, but it has never *deleted* a file whose spec
went away — so a renamed or removed spec leaves its YAML behind, with an id
the lock no longer holds.

That is quiet until the lock hands the same number to a new rule, and then it
is not quiet at all. `scripts/detection_truth_table.py` classifies a file as
executable by asking whether its `id` is in the engine's id set, so two files
sharing one id are counted twice: the published executable total rises by one
for a rule that does not exist. Forty orphans from an earlier generation run
were sitting on `det-cloud-191` through `det-endpoint-304` when the depth 2
wave 2 scenario families were allocated ids, and four of them collided
immediately — the truth table published 2,617 against an engine that loads
2,613.

Two independent checks, because each catches the other's blind spot:

* **Orphan.** A `det-*` id on disk that the lock does not hold. The file was
  generated once and nothing generates it now.
* **Duplicate.** Two files carrying one id, whatever the lock says. This is
  the condition that actually corrupts the count, and an orphan is only one
  way to reach it.

Usage:
    python3 scripts/check_detection_yaml_orphans.py
    python3 scripts/check_detection_yaml_orphans.py --list
    python3 scripts/check_detection_yaml_orphans.py --self-test
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main

ROOT = repo_root()
DETECTIONS = ROOT / "detections"
LOCK = DETECTIONS / "rule-ids.lock.json"

#: Subdirectories holding YAML that is not a detection rule. Kept equal to
#: `detection_truth_table.py`'s `SKIP_DIRS` and `project_stats.py`'s
#: `_NON_RULE_DIRS`: three walkers over one tree disagreeing about what a
#: detection is is how 25 response playbooks were once counted as rules.
SKIP_DIRS = frozenset({"fixtures", "playbooks"})

_ID_RE = re.compile(r"^id:\s*(\S+)", re.MULTILINE)


def locked_ids() -> set[str]:
    if not LOCK.is_file():
        return set()
    data = json.loads(LOCK.read_text(encoding="utf-8"))
    ids = data.get("ids", data) if isinstance(data, dict) else {}
    return {str(v) for v in ids.values()}


def ids_on_disk() -> dict[str, list[Path]]:
    """Every `id:` under `detections/`, and the files carrying it."""
    found: dict[str, list[Path]] = defaultdict(list)
    if not DETECTIONS.is_dir():
        return found
    for path in sorted(DETECTIONS.rglob("*.yaml")):
        relative = path.relative_to(DETECTIONS)
        if SKIP_DIRS & set(relative.parts):
            continue
        match = _ID_RE.search(path.read_text(encoding="utf-8"))
        if match:
            found[match.group(1)].append(path)
    return found


def check() -> list[str]:
    locked = locked_ids()
    if not locked:
        # An empty lock would make every file an orphan and every message
        # wrong. Refuse rather than emit a thousand confident falsehoods.
        return [f"{LOCK.relative_to(ROOT)} holds no ids — the gate cannot tell an orphan from a rule"]

    problems: list[str] = []
    on_disk = ids_on_disk()
    if not on_disk:
        return ["no detection YAML found — the gate would have passed over an empty tree"]

    for rule_id, paths in sorted(on_disk.items()):
        if len(paths) > 1:
            names = ", ".join(str(p.relative_to(ROOT)) for p in paths)
            problems.append(f"{rule_id} is carried by {len(paths)} files, so the truth table counts it {len(paths)} times: {names}")
        # Imported Sigma rules keep their upstream id and are not in the lock.
        if rule_id.startswith("det-") and rule_id not in locked:
            for path in paths:
                problems.append(f"{path.relative_to(ROOT)} carries {rule_id}, which no spec owns — stale output from an earlier generation run; delete it")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="name every orphan without failing")
    parser.add_argument("--self-test", action="store_true", help="run the gate's own tests")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test_main(Path(__file__).name)

    problems = check()
    if args.list:
        for problem in problems:
            print(f"  {problem}")
        return 0
    if problems:
        print("detection yaml orphans: FAILED\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(
            "\nDelete the stale file, then re-run scripts/generate_detections.py,\n"
            "scripts/export_detection_ruleset.py and scripts/detection_truth_table.py.\n",
            file=sys.stderr,
        )
        return 1
    total = sum(len(p) for p in ids_on_disk().values())
    print(f"detection yaml orphans: OK — {total} rule files, every id owned by one file")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
