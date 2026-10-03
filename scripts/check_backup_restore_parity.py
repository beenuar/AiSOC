#!/usr/bin/env python3
"""Every store with a backup path has a restore path.

Gap-closure wave 15.

`backup.sh` backed up five stores. `restore.sh` restored two. Neo4j,
Qdrant and Redis each had a backup that nobody had ever proven they
could use, and the first time anyone would find out is during the
recovery.

Nothing failed, which is why it survived. Both scripts ran, both
reported success, and the asymmetry was only visible by reading the
two files side by side and comparing the lists.

This gate runs in the direction that drifts — a store gains a backup
long before it gains a restore, because the backup is the part that
feels urgent.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

ROOT = repo_root()
BACKUP = ROOT / "scripts" / "backup.sh"
RESTORE = ROOT / "scripts" / "restore.sh"

_BACKUP_FN = re.compile(r"^backup_([a-z0-9_]+)\(\)", re.MULTILINE)
_RESTORE_FN = re.compile(r"^restore_([a-z0-9_]+)\(\)", re.MULTILINE)

#: Stores whose backup deliberately has no restore, each with the
#: reason. Empty, and that is the point: when it was not empty nobody
#: had written the reasons down because nobody had noticed.
EXEMPT: dict[str, str] = {}


def main() -> int:
    if not BACKUP.is_file() or not RESTORE.is_file():
        print("check_backup_restore_parity: backup.sh or restore.sh is missing", file=sys.stderr)
        return 2

    backed_up = set(_BACKUP_FN.findall(BACKUP.read_text(encoding="utf-8")))
    restorable = set(_RESTORE_FN.findall(RESTORE.read_text(encoding="utf-8")))

    if not backed_up:
        print("check_backup_restore_parity: found no backup functions — this gate would pass anything", file=sys.stderr)
        return 2

    missing = sorted(backed_up - restorable - set(EXEMPT))
    stale_exemptions = sorted(set(EXEMPT) - backed_up)

    for store in missing:
        print(
            f"FAIL [no-restore] `backup_{store}` exists and `restore_{store}` does not. "
            "A backup nobody can restore is a backup nobody has proven they can use, and "
            "the first time anyone finds out is during the recovery."
        )
    for store in stale_exemptions:
        print(f"FAIL [stale-exemption] {store!r} is exempted ({EXEMPT[store]}) and is no longer backed up")

    if missing or stale_exemptions:
        return 1

    print(f"check_backup_restore_parity: OK — {len(backed_up)} store(s) backed up, all restorable ({', '.join(sorted(backed_up))})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
