#!/usr/bin/env python3
"""Nothing in the ``.env`` namespace is tracked except the published template.

Why this exists
---------------
GHSA-57rw-w33m-cp5v. Two backups of a working ``.env`` were committed and
removed a few commits later — ``.env.bak-202610021531`` and
``.env.bak.1790944801``, added in ``9a59f24b`` and deleted in ``240ecbf4``,
both ancestors of ``main``. A deletion is not a redaction: every clone and
every fork still carries the blobs, and between them they hold a generated
``SECRET_KEY``, the Fernet ``AISOC_CREDENTIAL_KEY`` that unlocks the connector
vault, and the Postgres, Redis and ClickHouse passwords.

``.gitignore`` named ``.env``, ``.env.local`` and ``.env.*.local`` and nothing
else, so a backup written beside the real file was simply not ignored, and
``git add -A`` took it. That has been changed to a namespace deny with the
template as the one exception, which closes the next spelling as well as the
two that happened.

Why the ignore rule is not the whole fix
----------------------------------------
``.gitignore`` has no effect on a file that is **already** tracked, and
``git add -f`` overrides it. So this gate asks the question the ignore rule
cannot: *is one tracked right now?* It also asks the ignore rule's own
question back at it — would these names be ignored if they appeared — so the
two halves cannot drift apart the way the detector and ``.env.example`` once
did in ``check_env_placeholders.py``.

Both directions, deliberately. The dominant failure shape in this repository
is a check that compares A against B and never B against A: an allowlist entry
that stops being needed must fail the build rather than sit there, so a name
listed as permitted and not present is an error too.

What it does not do
-------------------
It does not scan history. The two blobs above are reachable from ``main`` and
no gate can un-publish them; rewriting history is a maintainer decision with a
cost to every clone, fork and release tag. The honest remedy for what is
already out is rotation, recorded in the advisory. This gate exists so there
is never a third.

It also does not look at file *contents*. A secret scanner already does that
(``gitleaks``, wired in ``security.yml``), and it reads the working directory
rather than history — which is why it never saw these two. The property here
is structural: a path in this namespace does not belong in the index at all,
whatever happens to be inside it today.

Usage::

    python3 scripts/check_env_backup_files.py
    python3 scripts/check_env_backup_files.py --print
    python3 scripts/check_env_backup_files.py --self-test
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

ROOT = repo_root()

#: ``.env`` itself, and anything suffixed onto it. Matched on the *basename*,
#: so a nested ``services/api/.env.bak`` is caught as readily as a root one.
#:
#: ``.envrc`` is deliberately outside the pattern. It is direnv's file, it is
#: not in this namespace, and a gate that refused it would be refusing a file
#: this repository has never had an opinion about — the kind of over-reach
#: that gets a check switched off rather than fixed.
_ENV_NAMESPACE = re.compile(r"^\.env(\..+)?$")

#: The published template, and the only member of the namespace that belongs
#: in the index. It holds names and empty values; that is its whole job.
#:
#: Shrink-only by intent. Adding a second entry here is adding a file whose
#: every future value a reader can see, so it should be hard and visible.
ALLOWED = frozenset({".env.example"})

#: Names the ignore rules must actually catch. These are not hypotheticals:
#: the first two are the files that were committed, verbatim.
_MUST_BE_IGNORED = (
    ".env.bak-202610021531",
    ".env.bak.1790944801",
    ".env",
    ".env.bak",
    ".env.backup",
    ".env.local",
    ".env.production",
    ".env.save",
    "services/api/.env.bak-1",
)


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [line for line in out.splitlines() if line.strip()]


def _is_ignored(path: str) -> bool:
    """Whether ``git`` would refuse to add ``path``.

    ``check-ignore`` answers for a path that need not exist, which is what
    lets this ask about the two committed names without recreating them.
    """
    return (
        subprocess.run(
            ["git", "-C", str(ROOT), "check-ignore", "-q", "--no-index", path],
            capture_output=True,
        ).returncode
        == 0
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print", dest="print_only", action="store_true", help="list what was found")
    parser.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    tracked = _tracked()
    # Scanned nothing and found nothing print the same word, so refuse the
    # first. A broken root or a tree that is not there would otherwise be
    # certified clean, which is the whole subject of check_gate_contract.py.
    if not tracked:
        print(
            "ERROR: no tracked files at all — this gate scanned nothing and will not report OK.",
            file=sys.stderr,
        )
        return 1

    in_namespace = sorted(p for p in tracked if _ENV_NAMESPACE.match(Path(p).name))
    offenders = [p for p in in_namespace if p not in ALLOWED]
    stale = sorted(name for name in ALLOWED if name not in in_namespace)
    unignored = [name for name in _MUST_BE_IGNORED if not _is_ignored(name)]

    if args.print_only:
        print(f"tracked files: {len(tracked)} | in the .env namespace: {len(in_namespace)}")
        for path in in_namespace:
            print(f"  {path:<40} {'allowed' if path in ALLOWED else 'NOT ALLOWED'}")

    errors: list[str] = []
    for path in offenders:
        errors.append(
            f"{path} is tracked. Nothing in the .env namespace belongs in the index "
            f"except {sorted(ALLOWED)}; this is how GHSA-57rw-w33m-cp5v happened. "
            f"Remove it with `git rm --cached {path}`, and rotate anything it held."
        )
    for name in stale:
        errors.append(
            f"{name} is listed as an allowed .env file but is not tracked. "
            "Either restore it or drop the entry — an allowlist that outlives what "
            "it permits is a rule nobody is checking."
        )
    for name in unignored:
        errors.append(
            f".gitignore does not ignore {name!r}, so `git add -A` beside a real .env "
            "would take it. Add a namespace rule rather than this one spelling."
        )

    if errors:
        print("ERROR: .env namespace gate failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(
        f"OK: {len(tracked)} tracked file(s); the .env namespace holds only "
        f"{sorted(ALLOWED)[0]}, and {len(_MUST_BE_IGNORED)} backup spellings are ignored"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
