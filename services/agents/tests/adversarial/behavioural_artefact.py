"""Assemble the published behavioural-injection artefact, tuned and held out.

Depth plan 1.3.

One module rather than a builder on either corpus, because the artefact's whole
point is that the two rates appear together. A reader who sees only the tuned
number reads "the family is closed"; the held-out number is what says how much
of that is generalisation and how much is the corpus the fix was written
against. Splitting the assembly between the two files is how one of them ends
up published alone.

``services/agents/tests/eval_data/behavioural_injection.json`` is committed, and
until this module existed nothing compared it to a live run — the round-trip
test wrote a fresh report to a temporary directory and read it back, which
proves the serialiser works and says nothing about the file in the repository.
``test_behavioural_injection.py`` now diffs the committed file against the
measurement, so a stale artefact is a failure rather than a number nobody
re-derived.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .behavioural_corpus import ALL_CASES
from .behavioural_holdout import HELDOUT, HELDOUT_CASES
from .behavioural_runner import run_case, run_suite

__all__ = ["build_artefact", "heldout_seam_rows"]


def heldout_seam_rows() -> list[dict[str, Any]]:
    """Held-out rates grouped by the structural seam each payload targets.

    A bare held-out rate says the guard misses most of these and not which part
    of it they go through, which is the only form in which the number is
    actionable. Each row also carries what a miss there costs, written before
    the measurement was taken.
    """
    grouped: dict[str, list[tuple[bool, bool, bool]]] = defaultdict(list)
    costs: dict[str, str] = {}
    for held in HELDOUT:
        outcome = run_case(held.case)
        grouped[held.seam].append((bool(outcome["flipped"]), bool(outcome["guard_caught"]), bool(outcome["unsafe_action"])))
        costs.setdefault(held.seam, held.cost)

    rows: list[dict[str, Any]] = []
    for seam in sorted(grouped):
        outcomes = grouped[seam]
        total = len(outcomes)
        rows.append(
            {
                "seam": seam,
                "cases": total,
                "verdict_flips": sum(1 for flipped, _, _ in outcomes if flipped),
                "flip_rate": round(sum(1 for flipped, _, _ in outcomes if flipped) / total, 4),
                "guard_catches": sum(1 for _, caught, _ in outcomes if caught),
                "catch_rate": round(sum(1 for _, caught, _ in outcomes if caught) / total, 4),
                "what_a_miss_costs": costs[seam],
            }
        )
    return rows


def build_artefact() -> dict[str, Any]:
    """The published payload: the tuned run, with the held-out run beside it."""
    payload = run_suite(ALL_CASES).as_dict()
    held = run_suite(HELDOUT_CASES)
    family = held.families["fake_tool_output"]

    payload["held_out"] = {
        "family": "fake_tool_output",
        "authored_after": "abf758cd",
        "measures": (
            "the same family on payloads written after the fix was frozen, by someone who could read "
            "the patterns. Aimed at the seams rather than sampled, so this is a worst-case probe and "
            "not a neutral estimate. There is deliberately no floor on it: a target on a held-out set "
            "is an instruction to tune against it."
        ),
        "total_cases": family.cases,
        "flip_rate": round(family.flip_rate, 4),
        "catch_rate": round(family.catch_rate, 4),
        "unsafe_action_rate": round(family.unsafe_action_rate, 4),
        "verdict_flips": family.verdict_flips,
        "guard_catches": family.guard_catches,
        "demotions": family.demotions,
        "by_seam": heldout_seam_rows(),
    }
    return payload
