#!/usr/bin/env python3
"""Assert every self-referential GitHub link in the docs points at a real path.

Why this exists as a separate gate from `link-check.yml`:

The lychee job already crawls the docs tree, but it cannot catch this class of
rot. It runs in observe mode (`fail: false`), and it passes
`--accept 200,206,301,302,307,308,403,429` — so a GitHub rate-limit response is
indistinguishable from a healthy page. A QA pass found seven links pointing at
three orgs that do not exist (`AiSOC-community/AiSOC`, `aisoc-community/aisoc`,
`aisoc-platform/aisoc`) plus one link to `services/api/app/api/deps.py`, a path
that moved under `v1/`. All eight were 404s that lychee never reported.

This gate is deliberately offline and deterministic: it resolves each path
against the checkout on disk instead of the network, so it cannot be rate
limited, cannot flake, and runs in well under a second.

Two properties are enforced:

1. A link into this project's own source must use the canonical `beenuar/AiSOC`
   coordinates. Any other org is a typo or a leftover from a rename.
2. The path after `blob/main/` or `tree/main/` must exist in the working tree.

Links pinned to a non-`main` ref are skipped: they may legitimately point at a
branch or tag that is not checked out.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# `scripts/` is on sys.path when this file is run as a program, but not when a
# test loads it by path with importlib. gate_toolkit sits beside it either way.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

REPO_ROOT = repo_root()
CANONICAL_OWNER = "beenuar"
CANONICAL_REPO = "AiSOC"

# `plans/cyble-aisoc/` is an archived prototype subtree kept for history; its
# links describe a repo that no longer exists and are not actionable. CodeQL
# excludes it for the same reason.
EXCLUDED_DIRS = {".git", "node_modules", "plans/cyble-aisoc"}

SEARCH_ROOTS = ("docs", "apps/docs/docs", ".")

# Matches https://github.com/<owner>/<repo>/(blob|tree)/<ref>/<path>
LINK_RE = re.compile(
    r"https://github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repo>[A-Za-z0-9_.-]+)/"
    r"(?P<kind>blob|tree)/"
    r"(?P<ref>[A-Za-z0-9_.\-/]+?)/"
    r"(?P<path>[A-Za-z0-9_.\-/]+)"
)

# Any casing of the project name is "ours" for the purposes of the owner check;
# a link to an unrelated third-party repo is legitimate and must not be flagged.
KNOWN_STALE_OWNERS = {"aisoc-community", "aisoc-platform", "aisoc"}


def _excluded(path: Path) -> bool:
    rel = path.relative_to(REPO_ROOT).as_posix()
    return any(rel == d or rel.startswith(f"{d}/") for d in EXCLUDED_DIRS)


def _markdown_files() -> list[Path]:
    seen: set[Path] = set()
    for root in SEARCH_ROOTS:
        base = REPO_ROOT / root
        if not base.is_dir():
            continue
        pattern = "*.md*" if root == "." else "**/*.md*"
        for path in base.glob(pattern):
            if path.suffix in (".md", ".mdx") and not _excluded(path):
                seen.add(path)
    return sorted(seen)


def _is_ours(owner: str, repo: str) -> bool:
    """True when the link is meant to point at this project."""
    if owner == CANONICAL_OWNER and repo == CANONICAL_REPO:
        return True
    return owner.lower() in KNOWN_STALE_OWNERS or repo.lower() == CANONICAL_REPO.lower()


def main() -> int:
    wrong_owner: list[tuple[Path, int, str]] = []
    missing_path: list[tuple[Path, int, str]] = []
    unreadable: list[str] = []
    links_examined = 0

    files = _markdown_files()
    for md in files:
        try:
            lines = md.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            # Skipping it silently means a file nobody can read is a file
            # nobody checks, reported as clean. This gate replaced a lychee
            # run that accepted 403 and 429 as healthy; inheriting the same
            # inability in a different costume is the thing to avoid.
            unreadable.append(md.relative_to(REPO_ROOT).as_posix())
            continue
        for lineno, line in enumerate(lines, start=1):
            for m in LINK_RE.finditer(line):
                links_examined += 1
                owner, repo = m.group("owner"), m.group("repo")
                if not _is_ours(owner, repo):
                    continue

                rel = md.relative_to(REPO_ROOT)
                if (owner, repo) != (CANONICAL_OWNER, CANONICAL_REPO):
                    wrong_owner.append((rel, lineno, f"{owner}/{repo}"))
                    continue

                # Only `main` can be resolved against the checkout.
                if m.group("ref") != "main":
                    continue

                target = m.group("path").split("#", 1)[0].rstrip("/.,);:")
                if not target:
                    continue
                if not (REPO_ROOT / target).exists():
                    missing_path.append((rel, lineno, target))

    # Say what was opened before saying it was clean. Zero markdown files and
    # zero broken links produce the same "OK" from the same branch, and the
    # eight wrong-org 404s that prompted this gate survived a link job that
    # was reporting healthy for exactly that reason.
    print(f"check_repo_self_links: {len(files)} markdown file(s), {links_examined} GitHub link(s) examined")
    if not files or not links_examined:
        print(
            f"\ncheck_repo_self_links: FAIL — scanned {len(files)} file(s) and found "
            f"{links_examined} link(s) to examine under {REPO_ROOT}. A clean result over "
            f"nothing is not a clean result; check SEARCH_ROOTS and LINK_RE.",
            file=sys.stderr,
        )
        return 1
    if unreadable:
        print(
            f"\n{len(unreadable)} file(s) could not be decoded and were therefore not checked:",
            file=sys.stderr,
        )
        for rel_path in unreadable:
            print(f"  {rel_path}", file=sys.stderr)
        return 1

    if not wrong_owner and not missing_path:
        print("check_repo_self_links: OK — every self-link resolves to a real path")
        return 0

    if wrong_owner:
        print(f"\n{len(wrong_owner)} link(s) use a non-canonical owner (expected {CANONICAL_OWNER}/{CANONICAL_REPO}):")
        for path, lineno, found in wrong_owner:
            print(f"  {path}:{lineno}  ->  {found}")

    if missing_path:
        print(f"\n{len(missing_path)} link(s) point at a path that does not exist:")
        for path, lineno, target in missing_path:
            print(f"  {path}:{lineno}  ->  {target}")

    print("\nThese render as 404s for every reader. Fix the link or the path.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
