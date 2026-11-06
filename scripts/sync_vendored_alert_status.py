#!/usr/bin/env python3
"""Keep fusion's terminal-status list identical to the canonical vocabulary.

`services/api/app/services/alert_status.py` owns the answer to "is this alert
still someone's problem". Fusion needs exactly one fact out of it — which
statuses mean *finished* — because `AlertSink` reopens an alert whose
detection has fired again (GHSA-qp9f-459j-w89c), and the predicate that
decides whether to reopen is `status = ANY(terminal)`.

Why a rendered copy rather than a byte-identical one
----------------------------------------------------
The 16 other `sync_vendored_*` scripts mostly `shutil.copy2` the source. That
is the right default and it is wrong here: the canonical module imports
`sqlalchemy` for `unresolved_filter`/`resolved_filter`, and fusion writes raw
asyncpg SQL and imports SQLAlchemy nowhere. Copying it byte-for-byte would put
an ORM import on the alert hot path to obtain a five-element tuple.

So this follows `sync_vendored_tenant_scope.py` instead, which renders rather
than copies: the generated module carries the vocabulary and nothing else, and
`--check` compares the *rendered* text against what is committed. Drift is
caught the same way a byte comparison catches it — change the canonical tuple
and the render no longer matches the file on disk — without the dependency.

Fail-closed extraction
----------------------
The extractor refuses anything it cannot read with certainty: the assignment
must be a module-level tuple of string literals with at least one member. A
canonical module that moved to a computed expression would make this script
exit non-zero rather than quietly render an empty list, which would silently
disable the reopen for every terminal status at once.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
SOURCE_FILE = REPO_ROOT / "services" / "api" / "app" / "services" / "alert_status.py"
TARGET_FILE = REPO_ROOT / "services" / "fusion" / "app" / "services" / "alert_status.py"

#: The constant fusion needs. Named here rather than inferred so that renaming
#: it in the canonical module is a loud failure instead of an empty render.
CONSTANT = "RESOLVED_STATUSES"

_HEADER = '''"""The statuses that mean an alert is finished — generated, do not edit.

Rendered from `services/api/app/services/alert_status.py` by
`scripts/sync_vendored_alert_status.py`. Edit the canonical module and re-run
that script; a CI gate fails when this file and the canonical tuple disagree.

Fusion needs this because `AlertSink` reopens an alert whose detection has
fired again after the alert was closed (GHSA-qp9f-459j-w89c). The reopen is
one conditional UPDATE whose `status = ANY(terminal)` predicate is also the
control that leaves an *open* alert alone, so a list that drifted from the
console's idea of "closed" would either miss a recurrence or churn an alert
an analyst is working.

Only the vocabulary is vendored. The canonical module's `unresolved_filter`
and `resolved_filter` build SQLAlchemy expressions, and fusion writes raw
asyncpg SQL -- vendoring them would put an ORM import on the alert path for
no caller.
"""

from __future__ import annotations

from typing import Final

#: Finished. The canonical module enumerates these by hand on purpose: this is
#: the only list whose membership *removes* work from an analyst's queue.
RESOLVED_STATUSES: Final[tuple[str, ...]] = (
'''

_FOOTER = ''')


def is_resolved(status: str | None) -> bool:
    """True only for a status that explicitly means finished.

    The mirror of the canonical module's function of the same name, including
    its treatment of NULL: an alert with no status is not finished.
    """
    if status is None:
        return False
    return status.strip().lower() in RESOLVED_STATUSES


__all__ = ["RESOLVED_STATUSES", "is_resolved"]
'''


def _extract(source: str) -> tuple[str, ...]:
    """The canonical terminal statuses, or a hard failure."""
    tree = ast.parse(source)
    for node in tree.body:
        # Both forms, kept apart so the narrowing is real rather than a cast:
        # the canonical module writes `NAME: Final[...] = (...)`, which is an
        # AnnAssign, and a future edit dropping the annotation would make it
        # an Assign. Reading `.value` off the common `ast.stmt` would be an
        # attribute mypy cannot prove exists.
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
            value: ast.expr | None = node.value
        elif isinstance(node, ast.AnnAssign):
            # `.value` is optional: `NAME: tuple[str, ...]` with no assignment
            # is a declaration, and rendering an empty vocabulary from one
            # would disable the reopen for every terminal status at once.
            targets = [node.target]
            value = node.value
        else:
            continue
        if not any(isinstance(t, ast.Name) and t.id == CONSTANT for t in targets):
            continue
        if not isinstance(value, ast.Tuple):
            raise SystemExit(f"FAIL: {CONSTANT} in {SOURCE_FILE.name} is not a literal tuple; this script cannot render it safely.")
        members: list[str] = []
        for element in value.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, str):
                raise SystemExit(f"FAIL: {CONSTANT} contains a non-literal member; refusing to render a partial vocabulary.")
            members.append(element.value)
        if not members:
            raise SystemExit(f"FAIL: {CONSTANT} is empty; rendering that would disable the reopen for every terminal status.")
        return tuple(members)
    raise SystemExit(f"FAIL: no module-level {CONSTANT} assignment found in {SOURCE_FILE}.")


def _render(statuses: tuple[str, ...]) -> str:
    body = "".join(f'    "{status}",\n' for status in statuses)
    return _HEADER + body + _FOOTER


def _rendered_from_source() -> str:
    if not SOURCE_FILE.is_file():
        raise SystemExit(f"FAIL: source file missing: {SOURCE_FILE}")
    return _render(_extract(SOURCE_FILE.read_text(encoding="utf-8")))


def _check() -> int:
    want = _rendered_from_source()
    if not TARGET_FILE.is_file():
        print(f"FAIL: vendored copy missing: {TARGET_FILE.relative_to(REPO_ROOT)}", file=sys.stderr)
        return 1
    if TARGET_FILE.read_text(encoding="utf-8") != want:
        print(
            f"FAIL: {TARGET_FILE.relative_to(REPO_ROOT)} is out of sync with "
            f"{SOURCE_FILE.relative_to(REPO_ROOT)}.\n"
            "      Re-run: python scripts/sync_vendored_alert_status.py",
            file=sys.stderr,
        )
        return 1
    count = len(_extract(SOURCE_FILE.read_text(encoding="utf-8")))
    print(f"OK: fusion's vendored terminal-status list matches the canonical vocabulary ({count} statuses).")
    return 0


def _sync() -> int:
    want = _rendered_from_source()
    TARGET_FILE.parent.mkdir(parents=True, exist_ok=True)
    TARGET_FILE.write_text(want, encoding="utf-8")
    print(f"wrote {TARGET_FILE.relative_to(REPO_ROOT)} from {SOURCE_FILE.relative_to(REPO_ROOT)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify the vendored copy matches; do not write.")
    args = parser.parse_args()
    return _check() if args.check else _sync()


if __name__ == "__main__":
    raise SystemExit(main())
