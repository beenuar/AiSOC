#!/usr/bin/env python3
"""Tool-attribution gate.

AiSOC never attributes work to a development tool or AI assistant — not in code,
comments, docs, plan files, commit messages, commit trailers, PR bodies, release
notes or marketing copy. This gate fails CI when such an attribution appears in:

  * a commit message on the pull request's commits,
  * a file changed by the pull request (or the whole tree with --all),
  * the pull request body.

It reads its patterns from .githooks/attribution-patterns.txt — the same file
.githooks/commit-msg reads — so the client-side hook that strips attribution and
the server-side gate that blocks it cannot drift apart and start disagreeing.

Legitimate human `Co-authored-by:` trailers are untouched: a pattern only fires
when the trailer names a known tool, so a real contributor is never flagged. The
allowlist (.githooks/attribution-allowlist.txt) is the escape hatch for a human
whose name collides with a vendor string, and for prose that names a vendor
neutrally rather than as an attribution.

Usage:
    python3 scripts/check_attribution.py --self-test
    python3 scripts/check_attribution.py --all
    python3 scripts/check_attribution.py --diff-base origin/main
    python3 scripts/check_attribution.py --commits origin/main..HEAD
    python3 scripts/check_attribution.py --text-file pr-body.md
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATTERN_FILE = ROOT / ".githooks" / "attribution-patterns.txt"
ALLOWLIST_FILE = ROOT / ".githooks" / "attribution-allowlist.txt"
FIXTURES = ROOT / "scripts" / "attribution_fixtures.json"
HOOK = ROOT / ".githooks" / "commit-msg"

# Paths that legitimately contain the vendor strings because they are the
# machinery for detecting them, or a record of the cleanup. Scanning these would
# make the gate flag itself.
SELF_REFERENTIAL = {
    ".githooks/attribution-patterns.txt",
    ".githooks/attribution-allowlist.txt",
    ".githooks/commit-msg",
    "scripts/check_attribution.py",
    "scripts/attribution_fixtures.json",
    ".github/workflows/attribution.yml",
}

# Binary / generated paths that are never prose and would only produce noise.
SKIP_SUFFIXES = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".svg",
    ".ico",
    ".pdf",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".zip",
    ".gz",
    ".tar",
    ".jar",
    ".lock",
    ".bin",
    ".onnx",
    ".parquet",
)
SKIP_DIRS = ("node_modules/", ".git/", "dist/", "build/", ".next/", "vendor/")


def _load_patterns(path: Path) -> list[re.Pattern]:
    if not path.exists():
        sys.exit(f"check_attribution: missing pattern file {path}")
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            out.append(re.compile(line, re.IGNORECASE))
        except re.error as exc:
            sys.exit(f"check_attribution: bad pattern {line!r} in {path.name}: {exc}")
    if not out:
        sys.exit(f"check_attribution: {path.name} defines no patterns — refusing to run vacuously")
    return out


PATTERNS = _load_patterns(PATTERN_FILE)
ALLOWLIST = _load_patterns(ALLOWLIST_FILE) if ALLOWLIST_FILE.exists() else []


def is_attribution(line: str) -> bool:
    """True when a single line is tool attribution and not allowlisted."""
    if not any(p.search(line) for p in PATTERNS):
        return False
    return not any(a.search(line) for a in ALLOWLIST)


def scan_text(text: str, origin: str) -> list[tuple[str, int, str]]:
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        if is_attribution(line):
            hits.append((origin, n, line.strip()[:200]))
    return hits


def _git(*args: str) -> str:
    r = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"check_attribution: git {' '.join(args)} failed: {r.stderr.strip()[:300]}")
    return r.stdout


def _skip(rel: str) -> bool:
    return rel in SELF_REFERENTIAL or rel.endswith(SKIP_SUFFIXES) or any(d in rel for d in SKIP_DIRS)


def scan_files(paths: list[str]) -> list[tuple[str, int, str]]:
    hits = []
    for rel in paths:
        if _skip(rel):
            continue
        p = ROOT / rel
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        hits.extend(scan_text(text, rel))
    return hits


def scan_commits(rev_range: str) -> list[tuple[str, int, str]]:
    """Scan commit messages in a range. Merge commits are included: a squash
    merge composes its message from the branch commits, so a trailer on any of
    them is what lands on main."""
    out = _git("log", "--format=%H%x00%B%x00%x00", rev_range)
    hits = []
    for entry in out.split("\x00\x00"):
        if not entry.strip():
            continue
        sha, _, body = entry.partition("\x00")
        sha = sha.strip()
        if not sha:
            continue
        hits.extend(scan_text(body, f"commit {sha[:12]}"))
    return hits


def self_test() -> int:
    """Prove the gate is neither vacuous nor over-broad, in both directions, and
    that the hook and the gate agree on the same corpus."""
    data = json.loads(FIXTURES.read_text(encoding="utf-8"))
    bad, good = data["bad"], data["good"]
    failures: list[str] = []

    print(f"self-test: {len(PATTERNS)} patterns, {len(ALLOWLIST)} allowlist entries")
    print(f"self-test: {len(bad)} known-bad and {len(good)} known-good samples\n")

    # Direction 1 — the gate must DETECT every known-bad sample. Without this a
    # broken regex makes the gate pass everything, silently.
    for s in bad:
        if not is_attribution(s):
            failures.append(f"gate MISSED known-bad sample: {s!r}")

    # Direction 2 — the gate must NOT flag any known-good sample. Without this
    # the gate could pass direction 1 by flagging literally everything.
    for s in good:
        if is_attribution(s):
            failures.append(f"gate FLAGGED known-good sample: {s!r}")

    # Direction 3 + 4 — the hook must strip exactly what the gate flags. This is
    # the cross-check that keeps the two implementations honest about the same
    # pattern file; without it they can drift in opposite directions and both
    # look fine in isolation.
    if HOOK.exists():
        for s in bad:
            if _hook_keeps(s):
                failures.append(f"hook did NOT strip known-bad line: {s!r}")
        for s in good:
            if not _hook_keeps(s):
                failures.append(f"hook STRIPPED known-good line: {s!r}")
    else:
        failures.append(f"hook not found at {HOOK} — cannot cross-check")

    if failures:
        print("SELF-TEST FAILED")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("SELF-TEST PASSED")
    print("  gate detects every known-bad sample (not vacuous)")
    print("  gate flags no known-good sample (not over-broad)")
    print("  hook strips exactly what the gate flags (no hook/gate drift)")
    return 0


def _hook_keeps(line: str) -> bool:
    """Run the real hook over a message containing `line`; True if it survived."""
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".msg", delete=False, encoding="utf-8") as fh:
        fh.write(f"chore: fixture subject\n\nbody line that must survive\n\n{line}\n")
        path = fh.name
    try:
        subprocess.run(["sh", str(HOOK), path], capture_output=True, text=True, cwd=ROOT)
        result = Path(path).read_text(encoding="utf-8")
    finally:
        Path(path).unlink(missing_ok=True)
    if "body line that must survive" not in result:
        raise SystemExit(f"hook destroyed real content while processing {line!r}")
    return line in result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--self-test", action="store_true", help="prove the gate works, both directions")
    ap.add_argument("--all", action="store_true", help="scan every tracked file")
    ap.add_argument("--diff-base", help="scan files changed against this ref")
    ap.add_argument("--commits", help="scan commit messages in this rev range")
    ap.add_argument("--text-file", action="append", default=[], help="scan a text file (e.g. the PR body)")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    hits: list[tuple[str, int, str]] = []
    scanned: list[str] = []

    if args.all:
        files = [f for f in _git("ls-files").splitlines() if f]
        hits += scan_files(files)
        scanned.append(f"{len(files)} tracked files")

    if args.diff_base:
        files = [f for f in _git("diff", "--name-only", f"{args.diff_base}...HEAD").splitlines() if f]
        hits += scan_files(files)
        scanned.append(f"{len(files)} changed files vs {args.diff_base}")

    if args.commits:
        hits += scan_commits(args.commits)
        n = len([x for x in _git("rev-list", args.commits).splitlines() if x])
        scanned.append(f"{n} commit messages in {args.commits}")

    for tf in args.text_file:
        p = Path(tf)
        if p.is_file() and p.stat().st_size > 0:
            hits += scan_text(p.read_text(encoding="utf-8"), f"text:{p.name}")
            scanned.append(f"text file {p.name}")

    if not scanned:
        ap.error("nothing to scan — pass --all, --diff-base, --commits, --text-file or --self-test")

    # Name the repository that was actually inspected. Every git read below runs
    # against the checkout this script lives in, not the caller's cwd, so a run
    # launched from a different worktree would otherwise print a confident "OK"
    # about a tree it never looked at.
    print(f"check_attribution: repo {ROOT}")
    print("check_attribution: scanned " + ", ".join(scanned))

    if hits:
        print(f"\nFAIL — {len(hits)} tool-attribution violation(s):\n")
        for origin, n, line in hits:
            print(f"  {origin}:{n}: {line}")
        print(
            "\nAiSOC does not attribute work to a development tool or AI assistant.\n"
            "Remove the line. If it is a commit trailer, `sh scripts/setup_hooks.sh`\n"
            "installs the hook that strips it automatically, then amend the commit.\n"
            "If this is a false positive (a contributor whose name collides with a\n"
            "vendor string, or neutral prose), add a justified entry to\n"
            ".githooks/attribution-allowlist.txt so a reviewer sees it in the diff."
        )
        return 1

    print("OK — no tool attribution found.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
