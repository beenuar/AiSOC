"""Frozen evaluation for the deterministic NL → ES|QL translator.

We score the translator on two axes:

* **Syntactic validity** — every emitted ES|QL string must parse against
  :mod:`app.nl_query.grammar`. Target: ≥85% of the eval set.
* **Semantic match** — the parsed :class:`QueryIntents` must align with
  the gold IR in ``tests/eval_data/nl_query_eval.json``. We score each
  case by per-axis accuracy (filters, group_by, aggregations, limit,
  time_range_hours) and require ≥70% mean semantic match across the set.

This file is intentionally a single test module rather than a parametrised
explosion of 50 tests: it lets us print a clean report on stdout while
still failing CI when the translator regresses.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.nl_query.grammar import GrammarError, validate_esql
from app.nl_query.translator import NLQuery, QueryIntents, parse_intents, translate

_EVAL_PATH = Path(__file__).parent / "eval_data" / "nl_query_eval.json"

# Acceptance thresholds from the future-release plan (Stage 2 #16).
_SYNTACTIC_THRESHOLD = 0.85
_SEMANTIC_THRESHOLD = 0.70


def _load_dataset() -> dict:
    return json.loads(_EVAL_PATH.read_text())


def _normalise_filters(items) -> set[tuple[str, str, str]]:
    return {(f, op, v) for f, op, v in items}


def _semantic_score(expected: dict, actual: QueryIntents) -> tuple[float, list[str]]:
    """Return (score in [0, 1], list of axis-level mismatch notes)."""

    notes: list[str] = []
    axes_checked = 0
    axes_passed = 0

    if "filters" in expected:
        axes_checked += 1
        want = _normalise_filters(expected["filters"])
        got = _normalise_filters(actual.filters)
        # Allow extra filters in the actual output (the parser is generous);
        # we just require the gold set to be a subset of what we emitted.
        if want.issubset(got):
            axes_passed += 1
        else:
            missing = want - got
            notes.append(f"filters missing: {sorted(missing)} (got {sorted(got)})")

    if "group_by" in expected:
        axes_checked += 1
        if list(expected["group_by"]) == list(actual.group_by):
            axes_passed += 1
        else:
            notes.append(f"group_by want={expected['group_by']} got={actual.group_by}")

    if "aggregations" in expected:
        axes_checked += 1
        want_aggs = {(f, a) for f, a, _ in expected["aggregations"]}
        got_aggs = {(f, a) for f, a, _ in actual.aggregations}
        if want_aggs.issubset(got_aggs):
            axes_passed += 1
        else:
            notes.append(f"aggregations missing {sorted(want_aggs - got_aggs)} (got {sorted(got_aggs)})")

    if "limit" in expected:
        axes_checked += 1
        if expected["limit"] == actual.limit:
            axes_passed += 1
        else:
            notes.append(f"limit want={expected['limit']} got={actual.limit}")

    if "time_range_hours" in expected:
        # Time range lives on the rendered query, not on intents — we'll
        # check it via the round-trip in the test below.
        pass

    if axes_checked == 0:
        return 1.0, notes
    return axes_passed / axes_checked, notes


def test_nl_query_eval_syntactic_validity() -> None:
    dataset = _load_dataset()
    cases = dataset["cases"]
    valid = 0
    failures: list[str] = []
    for case in cases:
        try:
            translated = translate(case["question"])
            validate_esql(translated.esql)
            valid += 1
        except (GrammarError, ValueError) as exc:
            failures.append(f"{case['id']}: {exc}")

    rate = valid / len(cases)
    print(f"\n[nl_query] syntactic validity: {valid}/{len(cases)} = {rate:.1%} (threshold {_SYNTACTIC_THRESHOLD:.0%})")
    if failures:
        print("[nl_query] syntactic failures:")
        for f in failures:
            print(f"  - {f}")

    assert rate >= _SYNTACTIC_THRESHOLD, f"syntactic validity {rate:.1%} below {_SYNTACTIC_THRESHOLD:.0%}; failures: {failures[:5]}"


def test_nl_query_eval_semantic_match() -> None:
    dataset = _load_dataset()
    cases = dataset["cases"]
    default_hours = dataset.get("time_range_hours_default", 24)
    default_index = dataset.get("index_pattern_default", "logs-*")

    per_case_scores: list[tuple[str, float, list[str]]] = []
    for case in cases:
        intents = parse_intents(
            NLQuery(
                question=case["question"],
                index_pattern=default_index,
                time_range_hours=default_hours,
            )
        )
        # Render once to observe the effective time range (the renderer
        # extracts it from the question text).
        translated = translate(case["question"])

        score, notes = _semantic_score(case["expected"], intents)

        # Time-range axis is checked against the rendered ES|QL.
        if "time_range_hours" in case["expected"]:
            want_hours = case["expected"]["time_range_hours"]
            wanted_phrase = f"NOW() - {want_hours}h"
            if wanted_phrase in translated.esql:
                # Promote the score: average in a passing time-range axis.
                score = (score + 1.0) / 2 if notes else 1.0
            else:
                notes.append(f"time_range want={want_hours}h not found in ESQL")
                score = score / 2 if score > 0 else 0.0

        per_case_scores.append((case["id"], score, notes))

    mean_score = sum(s for _, s, _ in per_case_scores) / len(per_case_scores)
    perfect = sum(1 for _, s, _ in per_case_scores if s == 1.0)
    near = sum(1 for _, s, _ in per_case_scores if 0.5 <= s < 1.0)

    print(f"\n[nl_query] semantic mean: {mean_score:.1%} (threshold {_SEMANTIC_THRESHOLD:.0%})")
    print(f"[nl_query] perfect={perfect}/{len(per_case_scores)} partial={near}/{len(per_case_scores)}")
    failing = [(cid, s, n) for cid, s, n in per_case_scores if s < 1.0]
    if failing:
        print(f"[nl_query] cases with imperfect score ({len(failing)}):")
        for cid, s, notes in failing[:25]:
            print(f"  - {cid} ({s:.0%})")
            for note in notes:
                print(f"      · {note}")

    assert mean_score >= _SEMANTIC_THRESHOLD, f"semantic mean {mean_score:.1%} below {_SEMANTIC_THRESHOLD:.0%}"


def test_nl_query_eval_dataset_size() -> None:
    """Hard-fail if anyone shrinks the eval set below the contracted 50 pairs."""

    dataset = _load_dataset()
    assert len(dataset["cases"]) >= 50, f"eval set only has {len(dataset['cases'])} cases; the plan requires 50"
    seen_ids = {c["id"] for c in dataset["cases"]}
    assert len(seen_ids) == len(dataset["cases"]), "duplicate case ids in eval set"
