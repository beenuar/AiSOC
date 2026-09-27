#!/usr/bin/env python3
"""A major version requires a BREAKING section, and a BREAKING section requires a major version.

Two directions, deliberately
----------------------------
The failure mode this repository keeps finding is the one-directional gate: it
compares A against B and never B against A, so drift in the direction things
actually change slips through while the gate prints OK. A release-policy check
is unusually prone to it, because the obvious half is only the obvious half.

*A major bump with no BREAKING section* publishes a version number that tells
an operator to read the upgrade notes, and then has none. They upgrade
assuming the major was cosmetic.

*A BREAKING section with no major bump* is worse. Semantic versioning is the
only signal most automated upgrade tooling reads, and a minor is the version
people let a bot merge. The note exists, nobody is looking at it, and the
break arrives through an unattended dependency update.

Both are enforced here, and the self-test proves each arm fires by injecting
that exact violation rather than by asserting the gate has never complained.

The floor, stated rather than hidden
------------------------------------
The policy did not exist before ``10.0.0``, and six earlier majors carry no
BREAKING section. Rewriting them would be revisionism, and exempting them
silently would make the gate look like it had scanned a clean corpus. So the
first arm applies from ``POLICY_FLOOR`` onward and the pre-floor majors are
counted and named in the output every run.

The second arm applies to the whole file. No section below the floor carries a
BREAKING heading, so there is nothing to grandfather and no reason to weaken
it.

Usage::

    python3 scripts/check_release_policy.py                 # the whole changelog
    python3 scripts/check_release_policy.py --tag v12.0.0   # one tag, at release time
    python3 scripts/check_release_policy.py --previous-minor # print it and exit
    python3 scripts/check_release_policy.py --self-test
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import repo_root, self_test_main  # noqa: E402

CHANGELOG = Path("CHANGELOG.md")
VERSION_FILE = Path("VERSION")
POLICY = Path("apps/docs/docs/operations/release-policy.md")

#: The release from which "a major bump carries a BREAKING section" is
#: enforced. 10.0.0 is the first major that carried one. Raising this would
#: weaken the gate; lowering it would require rewriting published history.
POLICY_FLOOR = (10, 0, 0)

_SECTION_RE = re.compile(r"^## \[(\d+)\.(\d+)\.(\d+)\]", re.M)
_UNRELEASED_RE = re.compile(r"^## \[Unreleased\]", re.M)
#: `### BREAKING`, and the `### BREAKING CHANGES` spelling, and nothing that
#: merely mentions the word in prose.
_BREAKING_HEADING_RE = re.compile(r"^#{2,4}\s+BREAKING\b", re.M | re.I)


@dataclass(frozen=True)
class Section:
    major: int
    minor: int
    patch: int
    body: str

    @property
    def version(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def tuple(self) -> tuple[int, int, int]:
        return (self.major, self.minor, self.patch)

    @property
    def declares_breaking(self) -> bool:
        return bool(_BREAKING_HEADING_RE.search(self.body))


def parse_sections(text: str) -> list[Section]:
    """Released sections, newest first, as the file orders them.

    Non-semver headings such as ``## [7.0.x]`` are not releases and are
    skipped; they carry no version to compare.
    """
    matches = list(_SECTION_RE.finditer(text))
    sections: list[Section] = []
    for i, match in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        sections.append(
            Section(
                major=int(match.group(1)),
                minor=int(match.group(2)),
                patch=int(match.group(3)),
                body=text[match.end() : end],
            )
        )
    return sections


def unreleased_body(text: str) -> str:
    match = _UNRELEASED_RE.search(text)
    if not match:
        return ""
    following = _SECTION_RE.search(text, match.end())
    return text[match.end() : following.start() if following else len(text)]


def findings(text: str, *, floor: tuple[int, int, int] = POLICY_FLOOR) -> tuple[list[str], list[str]]:
    """Returns (findings, notes). Notes are things a reader must see even on a pass."""
    sections = parse_sections(text)
    if not sections:
        return (["CHANGELOG.md declares no released version, so there is no release policy to check"], [])

    problems: list[str] = []
    notes: list[str] = []

    # Newest first in the file, so the predecessor of sections[i] is
    # sections[i + 1]. The oldest release has no predecessor and cannot be a
    # bump of anything.
    exempt_majors: list[str] = []
    for i, section in enumerate(sections):
        previous = sections[i + 1] if i + 1 < len(sections) else None
        if previous is None:
            # The oldest section in the file. Whether it was a major bump is
            # unanswerable: there is nothing it bumped from. Judging it either
            # way would be inventing a predecessor.
            continue
        is_major_bump = section.major > previous.major

        if is_major_bump and not section.declares_breaking:
            if section.tuple < floor:
                exempt_majors.append(section.version)
            else:
                problems.append(
                    f"{section.version} is a major bump over {previous.version} and its changelog section "
                    "has no `### BREAKING` heading. A major tells an operator to read upgrade notes that "
                    "do not exist"
                )

        # The second arm, over the whole file: no grandfathering, because
        # nothing below the floor violates it.
        if section.declares_breaking and not is_major_bump:
            problems.append(
                f"{section.version} carries a `### BREAKING` heading but is not a major bump over "
                f"{previous.version}. Semantic versioning is the only signal automated upgrade tooling reads, "
                "and a minor is the version people let a bot merge unattended"
            )

    if exempt_majors:
        notes.append(
            f"{len(exempt_majors)} major release(s) below the {'.'.join(map(str, floor))} policy floor carry no "
            f"BREAKING section and are exempt: {', '.join(sorted(exempt_majors))}. The policy did not exist "
            "when they shipped and published history is not rewritten"
        )

    if _BREAKING_HEADING_RE.search(unreleased_body(text)):
        notes.append(
            "[Unreleased] carries a `### BREAKING` heading, so the next release must be a major. "
            "`--tag` enforces that at the moment the tag is pushed"
        )

    return problems, notes


def check_tag(text: str, tag: str, *, floor: tuple[int, int, int] = POLICY_FLOOR) -> list[str]:
    """The release-time question: is *this* tag consistent with its own notes?

    Run before anything publishes. A release whose version and notes disagree
    is cheaper to stop than to withdraw: images carry the tag, registries
    refuse a re-upload, and the note is what an operator reads first.
    """
    normalized = tag.lstrip("v")
    parts = normalized.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return [f"tag {tag!r} is not a three-part semantic version"]
    wanted = tuple(int(p) for p in parts)

    sections = parse_sections(text)
    match = next((s for s in sections if s.tuple == wanted), None)
    if match is None:
        return [f"CHANGELOG.md has no `## [{normalized}]` section, so this tag would publish notes for nothing"]

    index = sections.index(match)
    previous = sections[index + 1] if index + 1 < len(sections) else None
    if previous is None:
        return []

    problems: list[str] = []
    is_major_bump = match.major > previous.major
    if is_major_bump and not match.declares_breaking and match.tuple >= floor:
        problems.append(
            f"{normalized} is a major bump over {previous.version} with no `### BREAKING` section. "
            "Add one saying what an operator must do, or cut a minor instead"
        )
    if match.declares_breaking and not is_major_bump:
        problems.append(
            f"{normalized} carries a `### BREAKING` section but only bumps "
            f"{'minor' if match.minor > previous.minor else 'patch'} over {previous.version}. "
            "Cut a major instead, or move the note if it is not a break"
        )
    return problems


def previous_minor(text: str, current: str) -> str | None:
    """The release an upgrade test should start from.

    The highest released version strictly below ``current`` that is not a
    patch of it: the previous *line*, which is what an operator upgrading is
    actually coming from.
    """
    parts = current.lstrip("v").split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    cur = tuple(int(p) for p in parts)
    candidates = [s for s in parse_sections(text) if s.tuple < cur and (s.major, s.minor) != (cur[0], cur[1])]
    return max(candidates, key=lambda s: s.tuple).version if candidates else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="accepted for symmetry; this gate always renders a verdict")
    parser.add_argument("--tag", help="check one tag at release time, e.g. v12.0.0")
    parser.add_argument("--previous-minor", action="store_true", help="print the release an upgrade test should start from")
    args = parser.parse_args(argv)

    root = repo_root()
    changelog = root / CHANGELOG
    if not changelog.is_file():
        print("check_release_policy: no CHANGELOG.md in this tree, so there is no release history to judge", file=sys.stderr)
        return 2
    text = changelog.read_text(encoding="utf-8")

    if args.previous_minor:
        version_file = root / VERSION_FILE
        if not version_file.is_file():
            print("check_release_policy: no VERSION file", file=sys.stderr)
            return 2
        answer = previous_minor(text, version_file.read_text(encoding="utf-8").strip())
        if answer is None:
            print("check_release_policy: no earlier release line to upgrade from", file=sys.stderr)
            return 2
        print(answer)
        return 0

    if args.tag:
        problems = check_tag(text, args.tag)
        for problem in problems:
            print(f"  FAIL  {problem}")
        if problems:
            return 1
        print(f"OK: {args.tag} and its changelog section agree about whether this release breaks anything.")
        return 0

    problems, notes = findings(text)
    released = len(parse_sections(text))

    # A VERSION that disagrees with the newest section means the tag the
    # release workflow extracts notes for is not the version the tree claims.
    version_file = root / VERSION_FILE
    if version_file.is_file():
        declared = version_file.read_text(encoding="utf-8").strip()
        newest = parse_sections(text)[0].version if released else ""
        if declared and newest and declared != newest:
            notes.append(
                f"VERSION reads {declared} and the newest released section is {newest}. That is the normal state "
                "between a release and the next cut; it is a finding only if a tag is pushed in that state, "
                "which `--tag` catches"
            )

    for note in notes:
        print(f"  NOTE  {note}")
    if problems:
        print(f"\ncheck_release_policy: {len(problems)} finding(s) across {released} released version(s)\n")
        for problem in problems:
            print(f"  FAIL  {problem}")
        return 1
    if not (root / POLICY).is_file():
        print(f"  FAIL  {POLICY} does not exist, so the rule this gate enforces is written nowhere a reader can find it")
        return 1
    print(
        f"\nOK: {released} released version(s). Every major at or above {'.'.join(map(str, POLICY_FLOOR))} "
        "declares what it breaks, and no non-major declares a break."
    )
    return 0


def _self_test() -> int:
    """Both arms, each proven by injecting the violation it exists to catch."""
    clean = (
        "# Changelog\n\n"
        "## [Unreleased]\n\n### Added\n- a thing\n\n"
        "## [3.0.0] — 2026-01-03\n\n### BREAKING\n- the config file moved\n\n"
        "## [2.1.0] 2026-01-02\n\n### Added\n- a thing\n\n"
        "## [2.0.0] 2026-01-01\n\n### BREAKING\n- the port changed\n\n"
    )
    floor = (2, 0, 0)

    major_without_note = clean.replace(
        "## [3.0.0] — 2026-01-03\n\n### BREAKING\n- the config file moved", "## [3.0.0] — 2026-01-03\n\n### Added\n- the config file moved"
    )
    breaking_on_a_minor = clean.replace(
        "## [2.1.0] 2026-01-02\n\n### Added\n- a thing", "## [2.1.0] 2026-01-02\n\n### BREAKING\n- the port changed"
    )

    checks = [
        ("a changelog obeying both directions passes", not findings(clean, floor=floor)[0]),
        (
            "ARM ONE: a major bump whose section has no BREAKING heading fails",
            any("no `### BREAKING` heading" in f for f in findings(major_without_note, floor=floor)[0]),
        ),
        (
            "ARM TWO: a BREAKING heading on a minor fails",
            any("is not a major bump" in f for f in findings(breaking_on_a_minor, floor=floor)[0]),
        ),
        (
            "the two arms are independent: breaking the first leaves the second silent",
            len(findings(major_without_note, floor=floor)[0]) == 1,
        ),
        (
            "and breaking the second leaves the first silent",
            len(findings(breaking_on_a_minor, floor=floor)[0]) == 1,
        ),
        (
            "a pre-floor major with no BREAKING section is exempt, and the exemption is printed rather than hidden",
            (lambda r: not r[0] and any("policy floor" in n for n in r[1]))(findings(major_without_note, floor=(4, 0, 0))),
        ),
        (
            "at release time, tagging the major-without-a-note is refused",
            bool(check_tag(major_without_note, "v3.0.0", floor=floor)),
        ),
        (
            "at release time, tagging the minor-carrying-a-break is refused",
            bool(check_tag(breaking_on_a_minor, "v2.1.0", floor=floor)),
        ),
        ("at release time, a consistent tag is accepted", not check_tag(clean, "v3.0.0", floor=floor)),
        (
            "a tag with no changelog section is refused rather than passing over an absence",
            bool(check_tag(clean, "v9.9.9", floor=floor)),
        ),
        (
            "prose merely containing the word BREAKING is not a heading",
            not findings(
                clean.replace("- a thing\n\n## [2.0.0]", "- a thing, and nothing here is BREAKING\n\n## [2.0.0]"),
                floor=floor,
            )[0],
        ),
        (
            "the previous release line is the previous minor, not the previous patch",
            previous_minor(clean.replace("## [2.1.0]", "## [3.0.1]\n\n### Fixed\n- x\n\n## [2.1.0]"), "3.0.0") == "2.1.0",
        ),
        (
            "[Unreleased] carrying a break is reported as an obligation on the next release",
            any(
                "next release must be a major" in n
                for n in findings(clean.replace("## [Unreleased]\n\n### Added", "## [Unreleased]\n\n### BREAKING"), floor=floor)[1]
            ),
        ),
    ]

    ok = True
    for description, passed in checks:
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  {description}")
    print()
    print("check_release_policy.py: self-test " + ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(_self_test() or self_test_main("check_release_policy.py", ["--check"]))
    sys.exit(main())
