"""The frozen-changelog gate detects post-tag drift and refuses vacuous passes.

The gate's job: the newest released ``## [X.Y.Z]`` sections in
``CHANGELOG.md`` must be byte-identical to the same section in the
``CHANGELOG.md`` committed at tag ``vX.Y.Z``. These tests drive
``audit()`` through an injected tag reader so no git state is needed,
plus the section parser on the shapes the real file uses.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("check_changelog_frozen", REPO_ROOT / "scripts" / "check_changelog_frozen.py")
# spec_from_file_location returns None only for an unloadable path; the gate
# script is tracked right there, so narrow rather than ignore.
assert _SPEC is not None and _SPEC.loader is not None
check_changelog_frozen = importlib.util.module_from_spec(_SPEC)
sys.modules["check_changelog_frozen"] = check_changelog_frozen
_SPEC.loader.exec_module(check_changelog_frozen)

audit = check_changelog_frozen.audit
released_sections = check_changelog_frozen.released_sections

BASE = (
    "# Changelog\n\n"
    "## [Unreleased]\n\n### Fixed\n\n- **Pending.** p\n\n"
    "## [2.0.0] - 2026-01-02\n\n### Fixed\n\n- **B.** b\n\n"
    "## [1.0.0] - 2026-01-01\n\n### Added\n\n- **A.** a\n"
)


def _reader(text):
    return lambda _version: (text, "")


def test_released_sections_excludes_unreleased_and_orders_newest_first() -> None:
    sections = released_sections(BASE)
    assert [v for v, _ in sections] == ["2.0.0", "1.0.0"]
    assert sections[0][1].startswith("## [2.0.0]")
    assert "- **B.** b" in sections[0][1]
    # The Unreleased content belongs to no released section.
    assert all("Pending" not in body for _, body in sections)


def test_identical_sections_pass_and_are_counted() -> None:
    problems, verified = audit(BASE, sections=5, tag_reader=_reader(BASE))
    assert problems == []
    assert verified == 2


def test_post_tag_entry_in_a_released_section_fails_with_a_diff() -> None:
    drifted = BASE.replace("- **B.** b", "- **B.** b\n\n- **Post-tag.** sneaky")
    problems, _ = audit(drifted, sections=5, tag_reader=_reader(BASE))
    assert len(problems) == 1
    assert "MISMATCH [2.0.0]" in problems[0]
    assert "+- **Post-tag.** sneaky" in problems[0]


def test_an_entry_edited_after_the_tag_fails() -> None:
    edited = BASE.replace("- **A.** a", "- **A.** a, reworded")
    problems, _ = audit(edited, sections=5, tag_reader=_reader(BASE))
    assert len(problems) == 1
    assert "MISMATCH [1.0.0]" in problems[0]


def test_an_unresolvable_tag_is_a_failure_not_a_skip() -> None:
    problems, verified = audit(BASE, sections=5, tag_reader=lambda _v: (None, "tag not found and fetch failed"))
    assert verified == 0
    assert all("UNVERIFIABLE" in p for p in problems)
    assert len(problems) == 2


def test_only_the_newest_requested_sections_are_checked() -> None:
    # Drift the OLDER section; with sections=1 only [2.0.0] is compared.
    drifted_old = BASE.replace("- **A.** a", "- **A.** drifted")
    problems, verified = audit(drifted_old, sections=1, tag_reader=_reader(BASE))
    assert problems == []
    assert verified == 1


def test_nothing_to_compare_refuses() -> None:
    problems, verified = audit("# Changelog\n\n## [Unreleased]\n", sections=5, tag_reader=_reader(BASE))
    assert verified == 0
    assert any("VACUOUS" in p for p in problems)


def test_tag_missing_its_own_section_fails() -> None:
    tag_without_v2 = BASE.replace("## [2.0.0] - 2026-01-02", "## [2.1.0] - 2026-01-03")
    problems, _ = audit(BASE, sections=1, tag_reader=_reader(tag_without_v2))
    assert len(problems) == 1
    assert "has no [2.0.0] section" in problems[0]


def test_self_test_passes() -> None:
    assert check_changelog_frozen.self_test() == 0
