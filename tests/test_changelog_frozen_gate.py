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
    problems, verified, _ = audit(BASE, sections=5, tag_reader=_reader(BASE))
    assert problems == []
    assert verified == 2


def test_post_tag_entry_in_a_released_section_fails_with_a_diff() -> None:
    drifted = BASE.replace("- **B.** b", "- **B.** b\n\n- **Post-tag.** sneaky")
    problems, _, _ = audit(drifted, sections=5, tag_reader=_reader(BASE))
    assert len(problems) == 1
    assert "MISMATCH [2.0.0]" in problems[0]
    assert "+- **Post-tag.** sneaky" in problems[0]


def test_an_entry_edited_after_the_tag_fails() -> None:
    edited = BASE.replace("- **A.** a", "- **A.** a, reworded")
    problems, _, _ = audit(edited, sections=5, tag_reader=_reader(BASE))
    assert len(problems) == 1
    assert "MISMATCH [1.0.0]" in problems[0]


def test_an_unresolvable_tag_is_a_failure_not_a_skip() -> None:
    problems, verified, _ = audit(BASE, sections=5, tag_reader=lambda _v: (None, "tag not found and fetch failed"))
    assert verified == 0
    assert all("UNVERIFIABLE" in p for p in problems)
    assert len(problems) == 2


def test_only_the_newest_requested_sections_are_checked() -> None:
    # Drift the OLDER section; with sections=1 only [2.0.0] is compared.
    drifted_old = BASE.replace("- **A.** a", "- **A.** drifted")
    problems, verified, _ = audit(drifted_old, sections=1, tag_reader=_reader(BASE))
    assert problems == []
    assert verified == 1


def test_nothing_to_compare_refuses() -> None:
    problems, verified, _ = audit("# Changelog\n\n## [Unreleased]\n", sections=5, tag_reader=_reader(BASE))
    assert verified == 0
    assert any("VACUOUS" in p for p in problems)


def test_tag_missing_its_own_section_fails() -> None:
    tag_without_v2 = BASE.replace("## [2.0.0] - 2026-01-02", "## [2.1.0] - 2026-01-03")
    problems, _, _ = audit(BASE, sections=1, tag_reader=_reader(tag_without_v2))
    assert len(problems) == 1
    assert "has no [2.0.0] section" in problems[0]


CUTTING = BASE.replace("## [Unreleased]\n", "## [Unreleased]\n\n## [3.0.0] - 2026-01-03\n")


def _release_reader(version: str):
    """Resolves the already-tagged sections; the release being cut has no tag."""
    return (BASE, "") if version in {"2.0.0", "1.0.0"} else (None, f"tag v{version} not found")


def test_release_pr_pending_section_passes_with_explicit_note() -> None:
    problems, verified, pending = audit(CUTTING, sections=5, tag_reader=_release_reader, pending_version="3.0.0")
    assert problems == []
    assert verified == 2
    assert pending is not None and "PENDING [3.0.0]" in pending


def test_untagged_newest_section_not_matching_version_still_fails() -> None:
    problems, _, pending = audit(CUTTING, sections=5, tag_reader=_release_reader, pending_version="9.9.9")
    assert any("UNVERIFIABLE [3.0.0]" in p for p in problems)
    assert pending is None


def test_untagged_older_section_is_never_pending() -> None:
    reader = lambda v: (BASE, "") if v == "2.0.0" else (None, f"tag v{v} not found")  # noqa: E731
    problems, _, _ = audit(CUTTING, sections=5, tag_reader=reader, pending_version="3.0.0")
    assert any("UNVERIFIABLE [1.0.0]" in p for p in problems)


def test_pending_version_whose_tag_exists_is_compared_not_skipped() -> None:
    # The tag resolves, but its CHANGELOG.md has no [3.0.0] section — the
    # exception must not shadow a real comparison once the tag exists.
    problems, _, pending = audit(CUTTING, sections=5, tag_reader=_reader(BASE), pending_version="3.0.0")
    assert any("has no [3.0.0] section" in p for p in problems)
    assert pending is None


def test_self_test_passes() -> None:
    assert check_changelog_frozen.self_test() == 0
