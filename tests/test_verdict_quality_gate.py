"""Depth plan 1.6: the published verdict-quality table must not be able to lie.

The table's failure mode is not a wrong number. It is an *absent* number
rendered as ``0.000``, which a reader cannot tell apart from a model that was
graded and scored zero. Every test here is a shape that would produce exactly
that, and each must be refused rather than rendered.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from check_verdict_quality import (  # noqa: E402
    NOT_MEASURED,
    VerdictQualityError,
    render_table,
    splice,
    validate_entry,
)

MEASURED = {
    "model": "llama3.2:3b-instruct-q4_K_M",
    "mode": "live",
    "llm_calls_placed": 72,
    "balanced_accuracy": 0.63,
    "matthews_corrcoef": 0.27,
    "malicious_recall": 0.70,
    "malicious_support": 30,
    "abstention_rate": 0.1,
    "hallucination_rate": 0.0,
}

UNMEASURED = {
    "model": "gpt-4o",
    "measured": False,
    "not_measured_reason": "no funded key for a hosted provider in this repository",
}


def test_unmeasured_row_must_carry_a_reason() -> None:
    with pytest.raises(VerdictQualityError, match="must say why"):
        validate_entry({"model": "gpt-4o", "measured": False})


def test_unmeasured_row_may_not_also_carry_a_score() -> None:
    """The contradiction must be refused, not resolved in favour of the number."""
    with pytest.raises(VerdictQualityError, match="measured=false"):
        validate_entry({**UNMEASURED, "balanced_accuracy": 0.0})


def test_live_row_that_placed_no_model_call_is_refused() -> None:
    """The defect this gate exists for.

    Triage catches a provider error and answers from its deterministic
    scorer, so a run against a dead endpoint produces a full set of
    confident verdicts and a scorecard that reads entirely normally.
    """
    with pytest.raises(VerdictQualityError, match="llm_calls_placed"):
        validate_entry({**MEASURED, "llm_calls_placed": 0})


def test_measured_row_without_an_accuracy_is_refused() -> None:
    entry = {k: v for k, v in MEASURED.items() if k != "balanced_accuracy"}
    with pytest.raises(VerdictQualityError, match="no balanced_accuracy"):
        validate_entry(entry)


def test_mode_outside_the_two_known_paths_is_refused() -> None:
    with pytest.raises(VerdictQualityError, match="must be 'live' or 'deterministic'"):
        validate_entry({**MEASURED, "mode": "offline"})


def test_deterministic_row_is_allowed_to_place_no_calls() -> None:
    """The floor is a legitimate published row: it is labelled as the floor."""
    validate_entry({**MEASURED, "mode": "deterministic", "llm_calls_placed": 0})


def test_unmeasured_renders_as_words_and_never_as_a_number() -> None:
    table = render_table({"entries": [MEASURED, UNMEASURED], "corpus": {"items": 72, "pairs": 36}})

    row = next(line for line in table.splitlines() if "gpt-4o" in line)
    assert NOT_MEASURED in row
    assert "no funded key" in row
    assert "0.000" not in row, "an unmeasured model must never render a score-shaped cell"


def test_recall_always_travels_with_its_support() -> None:
    """A rate over 30 cases and the same rate over four are different claims."""
    table = render_table({"entries": [MEASURED], "corpus": {"items": 72, "pairs": 36}})

    row = next(line for line in table.splitlines() if "llama3.2" in line)
    assert "0.700 / 30" in row


def test_empty_scorecard_is_refused_rather_than_rendered_blank() -> None:
    with pytest.raises(VerdictQualityError, match="no entries"):
        render_table({"entries": [], "corpus": {}})


def test_splice_refuses_a_page_with_no_block() -> None:
    with pytest.raises(VerdictQualityError, match="no .* block"):
        splice("# a page with no markers\n", "block")


def test_splice_leaves_the_rest_of_the_page_alone() -> None:
    page = "# head\n\n<!-- BEGIN:verdict-quality -->\nold\n<!-- END:verdict-quality -->\n\n# tail\n"
    out = splice(page, "<!-- BEGIN:verdict-quality -->\nnew\n<!-- END:verdict-quality -->")

    assert "# head" in out and "# tail" in out
    assert "old" not in out and "new" in out
