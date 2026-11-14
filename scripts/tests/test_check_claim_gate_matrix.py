"""The matrix gate reads its own summary block back, in both directions.

The file closes by telling a reader the counts come from the gate and that
editing a number here is the wrong move. Nothing held it to that: `main()`
parsed the rows, printed totals it had just computed, and returned without
ever opening the written block. Two faults were invisible as a result, and
both were live on this branch when the arm was written:

  * a figure edited by hand drifts from the table above it, and
  * a conflict resolution that keeps both sides appends a second copy of the
    whole block rather than merging it, which reads as a union in a diff.

The real file is used as the positive case so that the arm cannot pass by
agreeing with a fixture the test also wrote.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_claim_gate_matrix.py"

#: The shape the matrix ends in: a heading, the four figures, then prose.
BLOCK = "## Summary\n\n- Total: 12\n- GATED: 9\n- PARTIAL: 3\n- NO GATE: 0\n\nCounts come from the gate.\n"
TRUTH = {"Total": 12, "GATED": 9, "PARTIAL": 3, "NO GATE": 0}


def _load():
    spec = importlib.util.spec_from_file_location("check_claim_gate_matrix", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load()


def _problems(text: str, counts: dict[str, int] | None = None) -> list[str]:
    return MODULE.check_summary_block(text, counts or TRUTH)


# ─── The block agreeing with the table is the only passing shape ─────────────


def test_a_block_that_matches_the_table_is_accepted() -> None:
    assert _problems(BLOCK) == []


def test_the_shipped_matrix_agrees_with_its_own_rows() -> None:
    """The real file, scored against counts derived from the real file.

    This is the arm that would fail if someone edited a figure in the tree
    and pushed without recomputing.
    """
    text = MODULE.MATRIX.read_text(encoding="utf-8")
    statuses = MODULE._parse_status_rows(text)
    counts = {
        "Total": len(statuses),
        "GATED": sum(1 for s in statuses if s.upper().startswith("GATED")),
        "PARTIAL": sum(1 for s in statuses if s.upper().startswith("PARTIAL")),
        "NO GATE": sum(1 for s in statuses if "NO GATE" in s.upper()),
    }
    assert _problems(text, counts) == []


# ─── Drift: a figure edited by hand ──────────────────────────────────────────


def test_a_single_edited_figure_is_named_with_both_numbers() -> None:
    problems = _problems(BLOCK.replace("- GATED: 9", "- GATED: 10"))
    assert len(problems) == 1
    # Naming both sides matters: "GATED is wrong" sends someone to the table
    # to work out which number moved.
    assert "GATED = 10" in problems[0] and "parses 9" in problems[0]


def test_every_field_is_checked_not_just_the_total() -> None:
    """A gate that only compared Total would pass three of these four."""
    for field, wrong in (("Total", 13), ("GATED", 8), ("PARTIAL", 4), ("NO GATE", 1)):
        broken = BLOCK.replace(f"- {field}: {TRUTH[field]}", f"- {field}: {wrong}")
        assert any(field in p for p in _problems(broken)), f"{field} drift was not caught"


def test_a_missing_figure_is_a_failure_rather_than_a_skip() -> None:
    """The duplicated block on this branch had lost two of its four lines."""
    problems = _problems(BLOCK.replace("- PARTIAL: 3\n", ""))
    assert any("does not state 'PARTIAL'" in p for p in problems)


# ─── Duplication: the shape a kept-both-sides merge produces ─────────────────


def test_two_summary_blocks_fail_even_when_both_are_correct() -> None:
    """The figures agreeing is exactly why this went unnoticed for so long."""
    problems = _problems(BLOCK + "\n" + BLOCK)
    assert any("2 '## Summary' blocks" in p for p in problems)


def test_the_duplicate_report_names_the_lines_so_it_can_be_fixed() -> None:
    problems = _problems(BLOCK + "\n" + BLOCK)
    duplicate = next(p for p in problems if "blocks" in p)
    assert "lines 1, 10" in duplicate, duplicate


def test_the_three_block_shape_this_branch_carried_is_caught() -> None:
    problems = _problems(BLOCK + "\n" + BLOCK + "\n" + BLOCK)
    assert any("3 '## Summary' blocks" in p for p in problems)


# ─── Refusals ────────────────────────────────────────────────────────────────


def test_a_file_with_no_summary_block_is_a_failure_not_a_pass() -> None:
    """An unknown bucket reading as a pass is how most of these gates failed."""
    problems = _problems("# Matrix\n\n| Claim | Status |\n")
    assert problems == ["no '## Summary' block found"]


def test_a_heading_that_merely_mentions_summary_is_not_a_block() -> None:
    """`## Summary of deferrals` is a different section and must not match."""
    assert _problems("## Summary of deferrals\n\n- Total: 99\n") == ["no '## Summary' block found"]


def test_prose_after_the_block_cannot_satisfy_a_missing_figure() -> None:
    """A sentence saying "NO GATE: 0" in running text is not the figure line."""
    without = BLOCK.replace("- NO GATE: 0\n", "") + "\nThe table has NO GATE: 0 rows.\n"
    assert any("does not state 'NO GATE'" in p for p in _problems(without))


# ─── `--write` restates the figure instead of a human editing three files ────
#
# The stanza is the only place in the matrix that repeats a number the table
# already holds, so it is the only thing that drifts: two pull requests each
# adding a row merge without conflicting, and the stanza is then stale by two
# while describing a tree neither of them produced. That is what took `main`
# red and reddened five open pull requests with it. The detector above has
# always reported it; nothing could fix it, and the prose asking the reader to
# "recompute rather than editing a number here" named no command that would.


def _rewrite(text: str, counts: dict[str, int] | None = None) -> str:
    return MODULE.rewrite_summary_block(text, counts or TRUTH)


def test_a_drifted_block_is_restated_from_the_table() -> None:
    stale = BLOCK.replace("- Total: 12", "- Total: 10").replace("- GATED: 9", "- GATED: 7")
    assert _problems(stale), "fixture is not actually drifted"
    assert _problems(_rewrite(stale)) == []


def test_rewriting_is_idempotent() -> None:
    once = _rewrite(BLOCK.replace("- Total: 12", "- Total: 10"))
    assert _rewrite(once) == once


def test_only_the_figures_change() -> None:
    """Prose around the stanza is left alone — this is not a formatter."""

    stale = BLOCK.replace("- Total: 12", "- Total: 10")
    rewritten = _rewrite(stale)
    assert "Counts come from the gate." in rewritten
    assert rewritten.count("## Summary") == 1
    assert len(rewritten.splitlines()) == len(stale.splitlines())


def test_a_duplicated_block_is_refused_rather_than_repaired() -> None:
    """A writer cannot know which copy was meant, so it must not choose."""

    try:
        _rewrite(BLOCK + "\n" + BLOCK)
    except ValueError as exc:
        assert "found 2" in str(exc)
    else:
        raise AssertionError("a duplicated stanza was silently rewritten")


def test_a_missing_figure_is_refused_rather_than_inserted() -> None:
    """Where a missing line belongs is a judgement about the document."""

    try:
        _rewrite(BLOCK.replace("- PARTIAL: 3\n", ""))
    except ValueError as exc:
        assert "does not state" in str(exc) and "PARTIAL" in str(exc)
    else:
        raise AssertionError("a missing figure was invented")


def test_a_file_with_no_block_is_refused() -> None:
    try:
        _rewrite("# Matrix\n\nno stanza here\n")
    except ValueError as exc:
        assert "found 0" in str(exc)
    else:
        raise AssertionError("a file with no stanza was rewritten")
