#!/usr/bin/env python3
"""Ship the v1 playbook pack inside the agents package, and keep it identical.

Why this exists
---------------
`playbooks/packs/v1/` holds 62 production playbooks. `PlaybookStore`
resolves them by walking up from its own file looking for an ancestor
that contains `playbooks/packs` — which works in a checkout and **finds
nothing in the container**, because `services/agents/Dockerfile` has a
build context of `services/agents` and copies only `app/`.

So the shipped agents image contained **zero** pack playbooks. The store
logged nothing about it: the loader's pack branch is guarded by
`if self._pack_root.exists()`, so an absent pack is silently the same as
an empty one, and a deployment's playbook library was 62 entries shorter
than the repository's with no error anywhere.

A build context cannot reach outside itself, so the fix is the pattern
this repository already uses for `services/fusion`'s 2,603-rule
`detection_ruleset.json`: commit the data *inside* the package, where the
existing `COPY app/ ./app/` picks it up.

Two copies of anything drift, so `--check` is a CI gate.

Direction
---------
`playbooks/packs/v1/` is the source of truth and the vendored copy is
derived. The check compares in **both** directions — a file added to the
vendored copy and not to the source fails too, because a one-directional
gate passes while drift accumulates in the direction things actually
change.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

REPO = repo_root()
SOURCE = REPO / "playbooks" / "packs" / "v1"
VENDORED = REPO / "services" / "agents" / "app" / "playbook" / "packs" / "v1"
SUFFIX = "*.playbook.json"


def _digests(root: Path) -> dict[str, str]:
    """Relative path to content hash, for every playbook under ``root``."""
    if not root.is_dir():
        return {}
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(root.rglob(SUFFIX))}


def check() -> int:
    source, vendored = _digests(SOURCE), _digests(VENDORED)

    if not source:
        print(
            f"sync_vendored_playbook_packs: {SOURCE} holds no {SUFFIX} files. Finding "
            "nothing and comparing nothing print the same word, so this refuses rather "
            "than reporting the copies in sync.",
            file=sys.stderr,
        )
        return 1

    missing = sorted(set(source) - set(vendored))
    extra = sorted(set(vendored) - set(source))
    changed = sorted(p for p in set(source) & set(vendored) if source[p] != vendored[p])

    if not (missing or extra or changed):
        print(f"sync_vendored_playbook_packs: OK — {len(source)} playbooks, byte-identical.")
        return 0

    print("sync_vendored_playbook_packs: the vendored pack has drifted:", file=sys.stderr)
    for path in missing:
        print(f"  missing from the image: {path}", file=sys.stderr)
    for path in extra:
        print(f"  in the image and not in the source: {path}", file=sys.stderr)
    for path in changed:
        print(f"  differs: {path}", file=sys.stderr)
    print(
        "\nRun `python3 scripts/sync_vendored_playbook_packs.py` to re-copy. The agents "
        "image cannot COPY outside its build context, so a playbook that is not vendored "
        "is a playbook no deployment has.",
        file=sys.stderr,
    )
    return 1


def sync() -> int:
    if not SOURCE.is_dir():
        print(f"sync_vendored_playbook_packs: {SOURCE} does not exist", file=sys.stderr)
        return 1
    if VENDORED.exists():
        shutil.rmtree(VENDORED)
    shutil.copytree(SOURCE, VENDORED, ignore=shutil.ignore_patterns("__pycache__"))
    print(f"sync_vendored_playbook_packs: copied {len(_digests(VENDORED))} playbooks into the package.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the copies differ")
    args = parser.parse_args()
    return check() if args.check else sync()


if __name__ == "__main__":
    sys.exit(main())
