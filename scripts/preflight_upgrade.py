#!/usr/bin/env python3
"""Refuse an upgrade that a restore could not undo.

Why this exists
---------------
Two failures that are invisible until recovery, and both of them look fine
right up to the moment they matter.

**The credential key is not in the backup.** ``scripts/backup.sh`` covers six
stores with AES-256-GCM and a SHA-256 manifest and never captured
``AISOC_CREDENTIAL_KEY``. A complete, verified, restorable Postgres dump is
useless for connector credentials without it: every ``vault:v1:`` token fails
its integrity check against a different key and ``CredentialVault`` raises
``ciphertext failed integrity check (key rotated without re-encrypt?)``. The
restore reports success and every connector is dead. ``backup.sh`` now
captures it; this refuses to upgrade a deployment where there is nothing to
capture.

**``ensure_env.py`` mints one.** It is a good citizen about an existing
``.env`` and never overwrites a secret that already has a value, but when
``.env`` is *absent* it copies the example and generates a brand-new Fernet
key. On an existing deployment that orphans every stored credential in one
step, as a side effect of a command whose job is to be helpful — and a
missing ``.env`` is exactly the state in which an operator reaches for it.
So this runs **before** anything that could call it, which is why
``make upgrade`` does not depend on the ``env`` target.

What it refuses, and what it deliberately does not
--------------------------------------------------
Four conditions, each meaning "a restore would not bring this deployment
back":

1. ``.env`` is absent;
2. ``AISOC_CREDENTIAL_KEY`` is unset or empty;
3. it is set but is not a readable Fernet key;
4. no usable recent backup exists.

It does not check that the backup *restores* — that is
``scripts/restore.sh``'s job and the backup→destroy→restore gate's. It checks
that one exists, is recent, and is not empty, because a ``pg_dump | gzip``
into a full disk exits 0 and leaves a file.

Nothing here imports anything outside the standard library. It runs before
any ``pip install`` on a host that may have only the interpreter, and a
preflight that cannot run is a preflight that gets skipped.
"""

from __future__ import annotations

import argparse
import base64
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested  # noqa: E402

self_test_if_requested(__file__)

#: How old a pre-upgrade dump may be and still count. A dump from the
#: previous upgrade restores the deployment to the previous upgrade, which is
#: not the protection the operator believes they have.
DEFAULT_MAX_AGE_HOURS = 24

#: `cryptography.fernet` wants 32 bytes, urlsafe-base64 encoded — the same
#: shape `ensure_env.py` generates with
#: `base64.urlsafe_b64encode(os.urandom(32))`.
FERNET_KEY_BYTES = 32


def tree_under_test() -> Path:
    override = os.environ.get("AISOC_REPO_ROOT")
    if override:
        return Path(override)
    cwd = Path.cwd()
    if (cwd / ".git").exists():
        return cwd
    return repo_root()


def parse_env_value(text: str, key: str) -> str | None:
    """The last assignment of ``key``, or None.

    Last rather than first: that is how a shell sourcing the file and how
    compose's own interpolation both resolve a duplicate, and reading the
    first would disagree with the thing actually being configured.
    """
    found: str | None = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        name, sep, value = line.partition("=")
        if sep and name.strip() == key:
            found = value.strip().strip("'\"")
    return found


def is_readable_fernet_key(value: str) -> bool:
    """True when `cryptography.fernet.Fernet(value)` would accept it.

    Decoded here rather than by constructing a `Fernet`, so the preflight
    keeps working on a host with no `cryptography` installed. The library's
    own check is exactly this: urlsafe-base64 decoding to 32 bytes.
    """
    try:
        return len(base64.urlsafe_b64decode(value.encode("ascii"))) == FERNET_KEY_BYTES
    except Exception:
        return False


def recent_backups(backup_dir: Path, max_age_hours: float) -> list[Path]:
    """Non-empty dumps modified within the window, newest first."""
    if not backup_dir.is_dir():
        return []
    cutoff = time.time() - max_age_hours * 3600
    found = [p for p in backup_dir.glob("*.sql.gz") if p.is_file() and p.stat().st_size > 0 and p.stat().st_mtime >= cutoff]
    return sorted(found, key=lambda p: p.stat().st_mtime, reverse=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refuse an upgrade a restore could not undo.")
    parser.add_argument(
        "--skip-backup-check",
        action="store_true",
        help="check the credential key only. `make upgrade` uses this for the phase that runs before the backup is taken.",
    )
    parser.add_argument("--backup-dir", type=Path, default=None, help="default: <repo>/backups")
    parser.add_argument(
        "--max-age-hours",
        type=float,
        default=float(os.environ.get("AISOC_UPGRADE_BACKUP_MAX_AGE_HOURS", DEFAULT_MAX_AGE_HOURS)),
    )
    args = parser.parse_args(argv)

    root = tree_under_test()
    env_path = root / ".env"
    problems: list[str] = []

    # ── 1 + 2 + 3: the credential key ────────────────────────────────────
    #
    # Read from .env first and the process environment second, because
    # compose interpolates both and a key exported by the operator is a real
    # deployment rather than a broken one.
    key: str | None = None
    if env_path.is_file():
        key = parse_env_value(env_path.read_text(encoding="utf-8", errors="replace"), "AISOC_CREDENTIAL_KEY")
    else:
        problems.append(
            f"{env_path} does not exist.\n"
            "    On an existing deployment this is the dangerous state, not a harmless one:\n"
            "    scripts/ensure_env.py copies the example and generates a BRAND-NEW Fernet\n"
            "    key when .env is absent, and every stored connector credential is encrypted\n"
            "    under the old one. They would all fail their integrity check afterwards.\n"
            "    Restore the .env this deployment was running with before upgrading.\n"
            "    If this host genuinely has no connectors configured, `make env` is safe."
        )

    if not key:
        key = os.environ.get("AISOC_CREDENTIAL_KEY") or None

    if env_path.is_file() and not key:
        problems.append(
            "AISOC_CREDENTIAL_KEY is unset or empty.\n"
            "    The connector credential vault has no key, so either this deployment has\n"
            "    never stored a credential, or it has and they cannot be decrypted.\n"
            "    Generate one with `make env` only if you are certain it is the former."
        )
    elif key and not is_readable_fernet_key(key):
        problems.append(
            "AISOC_CREDENTIAL_KEY is set but is not a readable Fernet key.\n"
            "    It must be 32 bytes, urlsafe-base64 encoded. A value that is set and wrong\n"
            "    is worse than one that is missing: the API starts, and the failure arrives\n"
            "    at the first connector poll rather than at boot."
        )

    # ── 4: a backup that could actually be used ──────────────────────────
    backup_dir = args.backup_dir or root / "backups"
    if not args.skip_backup_check:
        usable = recent_backups(backup_dir, args.max_age_hours)
        if not usable:
            problems.append(
                f"no usable backup in {backup_dir} from the last {args.max_age_hours:g}h.\n"
                "    A migration has no undo. `make upgrade` takes this dump for you; if you\n"
                "    are running this command directly, take one first:\n"
                "        make upgrade            (backs up, migrates, then starts)\n"
                "    Empty files do not count — pg_dump into a full disk exits 0 and leaves one.\n"
                "    Off-host disaster recovery is scripts/backup.sh, which is a different\n"
                "    thing from this and covers all six stores."
            )

    if problems:
        print("preflight_upgrade: REFUSING to upgrade.\n")
        for n, problem in enumerate(problems, 1):
            print(f"  {n}. {problem}\n")
        print("  Nothing has been changed.")
        return 1

    # Never prints the key itself. A preflight that echoes the secret into CI
    # logs and terminal scrollback has made a second copy of it in the worst
    # place available.
    print("preflight_upgrade: OK")
    print("  credential key: present and readable")
    if args.skip_backup_check:
        print("  backup:         not checked yet (this phase runs before the dump is taken)")
    else:
        newest = recent_backups(backup_dir, args.max_age_hours)[0]
        age_h = (time.time() - newest.stat().st_mtime) / 3600
        print(f"  backup:         {newest.name} ({newest.stat().st_size} bytes, {age_h:.1f}h old)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
