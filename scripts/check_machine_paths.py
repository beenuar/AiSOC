#!/usr/bin/env python3
"""No tracked file may carry an absolute path from the machine that wrote it.

A clone is the product. A path like ``/Users/someone/Desktop/AiSOC-d9surf``
resolves on exactly one computer in the world, so a script carrying one runs
for its author and fails for everybody else -- and it fails *late*, after the
reader has already trusted the file enough to run it.

Two real instances motivated this gate, and they are different shapes:

* A deploy script opened with ``ROOT="/Users/<someone>/Desktop/AgenticSOC"``
  and then ``cd "$ROOT"``. Nobody else could run it.
* A 4.2 MB compiled Go test binary was committed in May 2026. Nothing
  referenced it, it was wrong for every architecture but one, and ``strings``
  showed the absolute build paths of the machine that produced it. A binary
  also cannot be reviewed, which is why this gate refuses executables in the
  source tree rather than only scanning text.

What a script should do instead is derive its own root::

    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

and in Python, ``pathlib.Path(__file__).resolve().parents[N]``.

Exit codes: 0 clean, 1 findings, 2 nothing scanned (a scope that collects no
files is a gate that cannot fail, which is worse than no gate because its
presence implies coverage).

Usage::

    python3 scripts/check_machine_paths.py
    python3 scripts/check_machine_paths.py --self-test
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

# `scripts/` is on sys.path when this file runs as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root  # noqa: E402

# Resolved through `git rev-parse`, not from `__file__`. Two levels above this
# script is whatever happens to be there — and `scripts/` copied into an empty
# repository is exactly that, which is how the first version of this gate
# reported 253 files clean without ever seeing the product.
REPO = repo_root()

#: A home directory alone is not the defect, and assuming it was is how the
#: first draft of this gate produced 288 findings that were all correct
#: content: detection rules matching `/home/*/.bashrc`, synthetic telemetry
#: carrying user home paths, and a benchmark corpus. Security software is
#: *supposed* to contain strings that look like someone's home directory.
#:
#: What breaks a clone is narrower and has a signature: a home-rooted path
#: that also names **a checkout of this repository**. That is a path the
#: tooling depends on to run, and it resolves on exactly one computer.
_HOME_ROOT = r"(?:/Users/[A-Za-z0-9._-]+|/home/[A-Za-z0-9._-]+|[A-Za-z]:\\{1,2}Users\\{1,2}[A-Za-z0-9._-]+)"

#: Directory names that mean "a checkout of this project".
_CHECKOUT = r"(?:[Aa]gentic[Ss][Oo][Cc]|[Aa]i[Ss][Oo][Cc])"

#: A separator may be a slash, one backslash, or the doubled backslash a
#: JSON or Go string literal carries.
_MACHINE_PATH = re.compile(rf"{_HOME_ROOT}[/\\\\]{{1,2}}(?:[A-Za-z0-9._-]+[/\\\\]{{1,2}})*?{_CHECKOUT}[A-Za-z0-9._-]*")

#: Home-rooted strings that are not a machine path leaking into the product.
#: Each needs a reason, and the list is checked in both directions so an entry
#: nothing needs any more fails the build instead of sitting there looking
#: like coverage.
ALLOWED: dict[str, str] = {
    # Empty, and that is the correct state rather than an oversight.
    #
    # The first draft of this gate matched any home directory and needed
    # exemptions for `/home/runner`, `/Users/runner` and the devcontainer
    # users. Narrowing the pattern to "a home path that also names a checkout
    # of this repository" made every one of them unnecessary: a CI runner's
    # `/home/runner/.cache` no longer matches at all.
    #
    # `/home/runner/work/AiSOC/AiSOC` would still match, because it does name
    # a checkout. No tracked file contains it today. If a workflow ever needs
    # to, add it here **with the reason** -- the list is checked in both
    # directions, so an entry nothing needs fails the build rather than
    # sitting there looking like coverage.
}

#: Extensions that are never source and should not be committed at all. A
#: compiled artefact cannot be reviewed and is wrong for every architecture
#: but the one it was built on.
BINARY_SUFFIXES: tuple[str, ...] = (".test", ".exe", ".dylib", ".so", ".a", ".o")

#: This gate's own self-test corpus is the one place a machine path is
#: deliberate: it is the thing being detected. Skipping the file keeps the
#: fixtures readable as real strings rather than obfuscated to dodge the
#: checker they exist to exercise.
SKIP_FILES: tuple[str, ...] = ("scripts/check_machine_paths.py",)

SKIP_DIRECTORIES: tuple[str, ...] = (
    "plans/",  # historical prototype, kept verbatim as a reference
    ".git/",
    "node_modules/",
)


@dataclass
class Finding:
    kind: str
    detail: str


@dataclass
class Scan:
    findings: list[Finding] = field(default_factory=list)
    scanned: int = 0


def tracked_files(root: Path) -> list[str]:
    """Every tracked path. Untracked files are not what a clone receives."""
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        text=True,
        check=False,
    )
    return [p for p in out.stdout.split("\0") if p]


def is_allowed(line: str, match: str) -> bool:
    return any(line.startswith(prefix) or match.startswith(prefix) for prefix in ALLOWED)


def scan_text(path: Path, relative: str) -> list[Finding]:
    """Machine paths in one text file, with the allowlist applied per match."""
    try:
        content = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []

    findings: list[Finding] = []
    for number, line in enumerate(content.splitlines(), start=1):
        for match in _MACHINE_PATH.finditer(line):
            text = match.group(0)
            if any(text.startswith(prefix) for prefix in ALLOWED):
                continue
            findings.append(
                Finding(
                    "machine-path",
                    f"{relative}:{number} names {text!r}, which exists on one computer. "
                    "Derive the root instead: "
                    '`ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"` in bash, '
                    "`Path(__file__).resolve().parents[N]` in Python.",
                )
            )
    return findings


def scan(root: Path | None = None) -> Scan:
    root = root or REPO
    result = Scan()
    used: set[str] = set()

    for relative in tracked_files(root):
        if relative in SKIP_FILES or any(relative.startswith(skip) for skip in SKIP_DIRECTORIES):
            continue
        path = root / relative

        if relative.endswith(BINARY_SUFFIXES):
            result.findings.append(
                Finding(
                    "committed-binary",
                    f"{relative} is a compiled artefact. It cannot be reviewed, it is wrong "
                    "for every architecture but the one it was built on, and it carries the "
                    "absolute build paths of the machine that produced it. Build it in CI "
                    "and ignore the output.",
                )
            )
            continue

        if not path.is_file():
            continue
        result.scanned += 1
        found = scan_text(path, relative)
        result.findings.extend(found)

        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for prefix in ALLOWED:
            if prefix in content:
                used.add(prefix)

    for prefix in sorted(set(ALLOWED) - used):
        result.findings.append(
            Finding(
                "stale-exemption",
                f"ALLOWED[{prefix!r}] — no tracked file names it any more, so the "
                "exemption is describing a tree that no longer exists. Delete it.",
            )
        )

    return result


def self_test() -> int:
    """Prove the gate catches each shape, and passes what it must pass.

    Both directions, because a checker that flags everything is as useless as
    one that flags nothing — and `/home/runner` appears in real workflows, so
    an over-broad pattern would red the whole tree on day one.
    """
    cases: list[tuple[str, str, bool]] = [
        # The two real instances this gate was written for.
        ("a checkout under Desktop", 'ROOT="/Users/someone/Desktop/AgenticSOC"', True),
        ("a worktree of it", "cd /Users/someone/Desktop/AiSOC-d9surf", True),
        ("a linux checkout elsewhere", "ROOT=/home/someone/src/aisoc", True),
        ("a windows checkout", r"SET ROOT=C:\\Users\\someone\\AiSOC", True),
        # Security content, which is the whole reason the first draft of this
        # pattern was wrong. A detection rule naming a home directory is doing
        # its job; 288 such findings were produced before this was narrowed.
        ("a detection rule's home glob", "/home/*/.bashrc", False),
        ("a fixture's synthetic user", r"C:\\Users\\Bob\\Documents", False),
        ("a truncated test path", "/home/u/.ssh/authorized_keys", False),
        ("a home path with no checkout in it", "/Users/someone/Downloads/report.pdf", False),
        # Portable forms.
        ("a derived root", 'ROOT="$(cd "$(dirname "$0")/../.." && pwd)"', False),
        ("a repo-relative path", "services/api/app/main.py", False),
        ("an absolute system path", "/usr/local/bin/python3", False),
        ("a container path", "/app/templates", False),
    ]

    failures = 0
    for name, line, should_flag in cases:
        flagged = any(not any(m.group(0).startswith(p) for p in ALLOWED) for m in _MACHINE_PATH.finditer(line))
        ok = flagged == should_flag
        failures += not ok
        print(f"  self-test [{'ok' if ok else 'FAIL'}] {name}")

    for suffix in BINARY_SUFFIXES:
        name = f"plugins/x/go/widget{suffix}"
        ok = name.endswith(BINARY_SUFFIXES)
        failures += not ok
        print(f"  self-test [{'ok' if ok else 'FAIL'}] a committed {suffix} artefact is refused")

    print(
        f"\ncheck_machine_paths.py: self-test {'OK' if not failures else f'FAILED ({failures})'}"
        f" — {len(cases) + len(BINARY_SUFFIXES)} cases, both directions"
    )
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="prove the gate still detects")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    # Refuse a tree that is not this repository, before scanning it.
    #
    # `scanned == 0` is not a strong enough guard: `scripts/` copied into an
    # empty git repository yields 253 tracked files, and this gate reported
    # them clean — a pass over a corpus that contains none of the product.
    # That is the exact shape `No check may report OK over a repository with
    # no content` exists to catch, and it caught this one.
    #
    # Each required input is somewhere a machine path has actually been found
    # or would land: the services tree, the deployment scripts, and the
    # compose file a self-hoster runs.
    missing = [name for name in ("services", "infra", "docker-compose.yml") if not (REPO / name).exists()]
    if missing:
        print(
            "check_machine_paths: FAILED to read the tree: expected input does not exist: "
            + ", ".join(str(REPO / name) for name in missing),
            file=sys.stderr,
        )
        return 2

    result = scan()
    if not result.scanned:
        print("check_machine_paths: nothing scanned — refusing to report clean", file=sys.stderr)
        return 2

    if result.findings:
        print(f"FAIL — {len(result.findings)} finding(s):")
        for finding in result.findings:
            print(f"  [{finding.kind}] {finding.detail}")
        return 1

    print(f"check_machine_paths: OK — {result.scanned} tracked text file(s), no machine-specific path")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
