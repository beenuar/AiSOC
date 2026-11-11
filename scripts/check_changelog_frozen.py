#!/usr/bin/env python3
"""A released CHANGELOG section must match the tag that published it.

Why this exists
---------------

``CHANGELOG.md`` accumulates entries under ``## [Unreleased]`` and a release
promotes them into a ``## [X.Y.Z]`` section, which the tag then freezes: the
GitHub Release body is extracted from that section *as tagged*, and the
section's claims describe that tag's tree. Nothing enforced the freeze.

The drift is not hypothetical — it happened three times in two days, through
the same innocent mechanism each time. A fix PR writes its entry under
``[Unreleased]`` while that section is empty; a release then promotes
``[Unreleased]`` and leaves a fresh empty one; when the fix PR merges *after*
the tag, git's three-way merge anchors the entry by context — and the nearest
context is now the top of the released section. Measured instances: the
Datadog cursor entry landed inside ``[23.0.0]`` (corrected by hand in #1805),
then the Cortex and Trend entries landed inside ``[23.1.0]`` the same way.
Each time, main's released notes claimed fixes the tagged artifact does not
contain — which reads as revisionism to anyone diffing the section against
the published release.

What this checks
----------------

The newest ``--sections`` (default 5) released sections in the working tree's
``CHANGELOG.md`` are compared byte-for-byte against the same section in
``vX.Y.Z``'s own committed ``CHANGELOG.md``. Only the newest few are checked
because that is where post-tag merges land by context; older sections cannot
acquire new neighbours. The tag is fetched (``--depth=1``) when the checkout
does not already have it, which a shallow CI clone does not.

Honest-failure rules, in keeping with the other gates here:

* a verified mismatch names the version and shows a unified diff;
* a tag that cannot be resolved after a fetch attempt is reported as
  UNVERIFIABLE with the reason — and fails the gate, because "could not
  check" recorded as clean is how gates in this repository have lied before;
* verifying zero sections is a failure, never a pass (the vacuous-pass rule).

``--self-test`` injects drift in every direction (entry added, removed,
edited, and a section missing from the tag side) against an in-memory tag
reader and fails if any injection goes undetected, then confirms the clean
fixture passes and the empty fixture refuses.
"""

from __future__ import annotations

import argparse
import difflib
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

_HEADER = re.compile(r"^## \[(?P<version>\d+\.\d+\.\d+)\][^\n]*$", re.M)


def released_sections(text: str) -> list[tuple[str, str]]:
    """``(version, section_text)`` for every released section, newest first.

    A section runs from its ``## [X.Y.Z]`` header up to the next ``## [``
    header or end of file — the same slicing the release workflow's body
    extraction performs, so the two cannot disagree about what a section is.
    ``[Unreleased]`` is not a released section and is not returned.
    """
    headers = [(m.start(), m.group("version")) for m in _HEADER.finditer(text)]
    bounds = [m.start() for m in re.finditer(r"^## \[", text, re.M)] + [len(text)]
    out: list[tuple[str, str]] = []
    for start, version in headers:
        end = min(b for b in bounds if b > start)
        out.append((version, text[start:end]))
    return out


def _git(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], capture_output=True, text=True)


def changelog_at_tag(version: str) -> tuple[str | None, str]:
    """The tag's committed CHANGELOG.md, or (None, reason)."""
    tag = f"v{version}"
    if _git(["rev-parse", "-q", "--verify", f"{tag}^{{commit}}"]).returncode != 0:
        fetch = _git(["fetch", "--depth=1", "origin", "tag", tag])
        if fetch.returncode != 0:
            return None, f"tag {tag} not found and fetch failed: {fetch.stderr.strip()[:200]}"
    show = _git(["show", f"{tag}:CHANGELOG.md"])
    if show.returncode != 0:
        return None, f"{tag} carries no CHANGELOG.md: {show.stderr.strip()[:200]}"
    return show.stdout, ""


def audit(
    text: str,
    *,
    sections: int,
    tag_reader: Callable[[str], tuple[str | None, str]],
) -> tuple[list[str], int]:
    """Returns (problems, verified_count)."""
    problems: list[str] = []
    verified = 0
    for version, tree_section in released_sections(text)[:sections]:
        tagged_changelog, reason = tag_reader(version)
        if tagged_changelog is None:
            problems.append(f"UNVERIFIABLE [{version}]: {reason}")
            continue
        tagged = dict(released_sections(tagged_changelog))
        if version not in tagged:
            problems.append(
                f"MISMATCH [{version}]: the tag v{version} has no [{version}] section in its "
                "CHANGELOG.md — the section was renamed or written after the tag"
            )
            continue
        if tagged[version] != tree_section:
            diff = "\n".join(
                difflib.unified_diff(
                    tagged[version].splitlines(),
                    tree_section.splitlines(),
                    fromfile=f"v{version} (as tagged)",
                    tofile=f"CHANGELOG.md [{version}] (working tree)",
                    lineterm="",
                    n=2,
                )
            )
            problems.append(
                f"MISMATCH [{version}]: the released section no longer matches the tag that "
                f"published it. A post-tag entry belongs under [Unreleased].\n{diff}"
            )
            continue
        verified += 1
    if verified == 0 and not problems:
        problems.append("VACUOUS: no released section could be compared — a gate that verified nothing must not pass")
    return problems, verified


def self_test() -> int:
    base = (
        "# Changelog\n\n## [Unreleased]\n\n## [2.0.0] - 2026-01-02\n\n### Fixed\n\n"
        "- **B.** b\n\n## [1.0.0] - 2026-01-01\n\n### Added\n\n- **A.** a\n"
    )

    def reader_for(tag_text: str | None, reason: str = "") -> Callable[[str], tuple[str | None, str]]:
        return lambda _version: (tag_text, reason)

    failures: list[str] = []

    def expect(name: str, problems: list[str], should_fail: bool) -> None:
        failed = bool(problems)
        status = "ok" if failed == should_fail else "MISSED"
        if failed != should_fail:
            failures.append(name)
        print(f"  self-test [{status}] {name}")

    clean, n = audit(base, sections=5, tag_reader=reader_for(base))
    expect("clean fixture passes", clean, should_fail=False)
    assert n == 2, f"expected 2 verified sections, got {n}"

    drifted = base.replace("- **B.** b", "- **B.** b\n\n- **C (post-tag).** c")
    added, _ = audit(drifted, sections=5, tag_reader=reader_for(base))
    expect("an entry added after the tag is detected", added, should_fail=True)

    removed, _ = audit(base.replace("- **B.** b\n\n", ""), sections=5, tag_reader=reader_for(base))
    expect("an entry removed after the tag is detected", removed, should_fail=True)

    edited, _ = audit(base.replace("- **B.** b", "- **B.** c"), sections=5, tag_reader=reader_for(base))
    expect("an entry edited after the tag is detected", edited, should_fail=True)

    missing, _ = audit(base, sections=5, tag_reader=reader_for(None, "tag v2.0.0 not found"))
    expect("an unresolvable tag refuses rather than passes", missing, should_fail=True)

    vacuous, _ = audit("# Changelog\n\n## [Unreleased]\n", sections=5, tag_reader=reader_for(base))
    expect("a changelog with nothing to compare refuses", vacuous, should_fail=True)

    if failures:
        print(f"check_changelog_frozen --self-test: FAIL ({len(failures)} undetected)")
        return 1
    print("check_changelog_frozen --self-test: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sections", type=int, default=5, help="newest released sections to verify")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    text = Path("CHANGELOG.md").read_text(encoding="utf-8")
    problems, verified = audit(text, sections=args.sections, tag_reader=changelog_at_tag)
    print(f"check_changelog_frozen: {verified} released section(s) verified against their tags (newest {args.sections} checked)")
    for problem in problems:
        print(f"  {problem}")
    if problems:
        print("check_changelog_frozen: FAIL")
        return 1
    print("check_changelog_frozen: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
