#!/usr/bin/env python3
"""Gate: no tracked file carries an unresolved merge conflict marker.

Why this exists
---------------
Three documents reached `main` carrying `<<<<<<< HEAD`, `=======` and
`>>>>>>> <sha>`. Two of them were prose nobody parses, so they sat there
looking like text. The third was `apps/docs/docs/compliance/evidence-pack.md`,
which Docusaurus compiles as MDX, and the docs site stopped building.

Nothing caught it, and the reason is worth stating because it is the general
case rather than one bad afternoon. Every gate that read those files was
looking for something else: the claim-matrix ratchet parses table rows and a
marker is not one, `readme_gates.py` looks for a figure and found the first of
the two duplicated lines, and the markdown link checker resolves links. A
marker is invisible to all of them, and the only check that would have seen it
is one that looks for markers.

The programme this repository runs makes that likely rather than unlikely: a
long-lived branch is rebased on `main` several times a day, tracking documents
are edited by every branch at once, and conflicts in them are resolved by hand
under time pressure. A resolution that drops a marker line is one keystroke
away from one that does not.

What counts
-----------
The three markers git writes, each at the start of a line: `<<<<<<< ` and
`>>>>>>> ` with a trailing space and a label, and a bare `=======`. The
trailing-space requirement matters: `=======` is also a valid setext heading
underline and a horizontal rule, so a bare seven-equals line is only a finding
when it sits between the other two.

`>>>>>>>` is likewise matched only with a following space, because a Markdown
blockquote nested seven deep is legal and this gate should not be the reason
somebody cannot write one.

Run:  python3 scripts/check_merge_markers.py
      python3 scripts/check_merge_markers.py --self-test
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

REPO_ROOT = repo_root()

_START = re.compile(r"^<{7} \S")
_END = re.compile(r"^>{7} \S")
_MIDDLE = re.compile(r"^={7}$")

#: This gate's own docstring and self-test quote the markers, and so does the
#: git documentation vendored under `plans/`. Paths are matched as prefixes.
EXEMPT_PREFIXES: tuple[str, ...] = (
    "scripts/check_merge_markers.py",
    "scripts/tests/test_merge_markers_gate.py",
    "plans/",
)

#: Binary and generated trees nobody hand-resolves.
SKIP_SUFFIXES: tuple[str, ...] = (".png", ".jpg", ".jpeg", ".gif", ".pdf", ".woff", ".woff2", ".ico", ".mp4", ".zip", ".gz")


def tracked_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [p for p in result.stdout.splitlines() if p]


def scan(root: Path) -> tuple[list[str], int, int]:
    """Return ``(findings, files_read, subject_files_read)``.

    The second count is every readable tracked text file. The third is the
    subset that is neither this gate's own toolkit nor empty, and it is the
    one a verdict rests on: ``gate_toolkit``'s scratch tree copies
    ``scripts/`` in so the gate is runnable and creates the content
    directories holding a single empty ``.gitkeep`` each, so a gate counting
    only the first would read 161 real files, find nothing, and report a tree
    with no content as clean.
    """
    findings: list[str] = []
    read = 0
    subject = 0
    for rel in tracked_files(root):
        if rel.startswith(EXEMPT_PREFIXES) or rel.endswith(SKIP_SUFFIXES):
            continue
        path = root / rel
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        read += 1
        if text.strip() and not rel.startswith("scripts/"):
            subject += 1
        # A bare `=======` is a setext underline as often as it is a marker,
        # so it only counts inside a region opened by `<<<<<<< `.
        inside = False
        for number, line in enumerate(text.splitlines(), start=1):
            if _START.match(line):
                inside = True
                findings.append(f"{rel}:{number}: conflict start marker")
            elif _END.match(line):
                inside = False
                findings.append(f"{rel}:{number}: conflict end marker")
            elif inside and _MIDDLE.match(line):
                findings.append(f"{rel}:{number}: conflict separator")
    return findings, read, subject


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    findings, read, subject = scan(REPO_ROOT)

    # `subject`, not `read`. A tree holding only this gate's own toolkit, or
    # one whose content directories hold a single empty placeholder each, is
    # not a repository this gate can render a verdict about, and reporting it
    # clean would be a verdict about `scripts/` wearing the whole
    # repository's name.
    if subject == 0:
        print(
            f"merge-markers: FAILED. {read} file(s) read and none of them carries content outside scripts/, so this "
            "is the gate's own toolkit rather than a repository. A clean verdict here would describe nothing.",
            file=sys.stderr,
        )
        return 1

    if findings:
        print("MERGE MARKER GATE FAILED:", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding}", file=sys.stderr)
        print(
            "\nA conflict resolved by hand left its markers behind. Two of the three markers are prose "
            "to every other gate in this tree, and the one that is not broke the docs build.",
            file=sys.stderr,
        )
        return 1

    if args.verbose:
        print(f"merge-markers: scanned {read} tracked text file(s), {subject} of them outside scripts/")
    print(f"merge-markers: OK. {read} tracked text files carry no unresolved conflict marker.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
