"""Vendored ``match_when`` matcher for the live detection engine (Phase A2).

The canonical matcher lives in ``scripts/generate_detections.py`` (repo root) and
is used by CI fixture-replay. Services only ship their ``app/`` subtree, so the
fusion detection engine cannot import it at runtime. This module is a
**byte-faithful vendored copy** of that matcher's evaluation core
(``OPERATORS`` / ``_split_op`` / ``_check`` / ``_eval_clause`` / ``matches``).

``services/fusion/tests/test_detection_matcher_parity.py`` imports BOTH this
copy and the repo-root original and asserts identical verdicts over every
committed detection fixture, so the two can never silently diverge — the same
"vendored + parity-gated" convention the repo uses for the narrative builder.

Do not hand-edit the operator semantics here; change ``generate_detections.py``
and re-sync (the parity test will fail until they match).
"""

from __future__ import annotations

import re
from typing import Any

# (suffix, op_name, condition_token) — sorted longest-suffix-first so `_not_in`
# is not eaten by `_in`. Kept identical to scripts/generate_detections.py.
OPERATORS: list[tuple[str, str, str]] = sorted(
    [
        ("_pattern_match_any", "pattern_match_any", "PATTERN_MATCH_ANY"),
        ("_not_endswith_any", "not_endswith_any", "NOT ENDSWITH_ANY"),
        ("_not_contains_any", "not_contains_any", "NOT CONTAINS_ANY"),
        ("_pattern_match", "pattern_match", "PATTERN_MATCH"),
        ("_not_startswith", "not_startswith", "NOT STARTSWITH"),
        ("_startswith_any", "startswith_any", "STARTSWITH_ANY"),
        ("_endswith_any", "endswith_any", "ENDSWITH_ANY"),
        ("_contains_any", "contains_any", "CONTAINS_ANY"),
        ("_contains_all", "contains_all", "CONTAINS_ALL"),
        ("_startswith", "startswith", "STARTSWITH"),
        ("_match_any", "match_any", "MATCH_ANY"),
        ("_endswith", "endswith", "ENDSWITH"),
        ("_contains", "contains", "CONTAINS"),
        ("_has_any", "has_any", "HAS_ANY"),
        ("_not_in", "not_in", "NOT IN"),
        ("_match", "match", "MATCH"),
        ("_gte", "gte", ">="),
        ("_lte", "lte", "<="),
        ("_in", "in", "IN"),
        ("_gt", "gt", ">"),
        ("_lt", "lt", "<"),
    ],
    key=lambda x: -len(x[0]),
)


def _split_op(key: str) -> tuple[str, str]:
    """Return (field, op_name). Plain equality / null check => op == 'eq'."""
    for suffix, op_name, _ in OPERATORS:
        if key.endswith(suffix):
            return key[: -len(suffix)], op_name
    return key, "eq"


def _to_lc_str(value: Any) -> str:
    return str(value).lower() if value is not None else ""


def _check(field: str, op: str, expected: Any, event: dict[str, Any]) -> bool:
    actual = event.get(field)

    if op == "eq":
        if expected is None:
            return actual is None
        return actual == expected

    if op in {"gt", "gte", "lt", "lte"}:
        if not isinstance(actual, int | float) or isinstance(actual, bool):
            return False
        if op == "gt":
            return actual > expected
        if op == "gte":
            return actual >= expected
        if op == "lt":
            return actual < expected
        return actual <= expected

    if op == "in":
        return actual in expected if isinstance(expected, list) else False

    if op == "not_in":
        return actual not in expected if isinstance(expected, list) else False

    if op == "contains_any":
        if isinstance(actual, list):
            actual_lc = {_to_lc_str(x) for x in actual}
            return any(_to_lc_str(n) in actual_lc for n in expected)
        haystack = _to_lc_str(actual)
        return any(_to_lc_str(n) in haystack for n in expected)

    if op == "contains_all":
        if isinstance(actual, list):
            actual_lc = {_to_lc_str(x) for x in actual}
            return all(_to_lc_str(n) in actual_lc for n in expected)
        haystack = _to_lc_str(actual)
        return all(_to_lc_str(n) in haystack for n in expected)

    if op == "match_any":
        if not isinstance(expected, list):
            return False
        actual_str = "" if actual is None else str(actual)
        for pat in expected:
            pat_str = str(pat)
            if "*" in pat_str:
                regex = "^" + re.escape(pat_str).replace(r"\*", ".*") + "$"
                if re.match(regex, actual_str):
                    return True
            elif actual_str == pat_str:
                return True
        return False

    if op == "pattern_match_any":
        if not isinstance(expected, list) or actual is None:
            return False
        actual_str = str(actual)
        for pat in expected:
            try:
                if re.search(str(pat), actual_str, re.IGNORECASE):
                    return True
            except re.error:
                if str(pat).lower() in actual_str.lower():
                    return True
        return False

    if op == "endswith":
        return isinstance(actual, str) and actual.endswith(str(expected))

    if op == "endswith_any":
        if not isinstance(expected, list) or not isinstance(actual, str):
            return False
        return any(actual.endswith(str(s)) for s in expected)

    if op == "startswith":
        return isinstance(actual, str) and actual.startswith(str(expected))

    if op == "startswith_any":
        if not isinstance(expected, list) or not isinstance(actual, str):
            return False
        return any(actual.startswith(str(s)) for s in expected)

    if op == "not_startswith":
        if not isinstance(actual, str):
            return False
        return not actual.startswith(str(expected))

    if op == "contains":
        if isinstance(actual, list):
            return expected in actual
        if isinstance(actual, str):
            return str(expected) in actual
        return False

    if op == "has_any":
        if not isinstance(expected, list) or not isinstance(actual, list):
            return False
        actual_lc = {_to_lc_str(x) for x in actual}
        return any(_to_lc_str(n) in actual_lc for n in expected)

    if op == "match":
        if actual is None:
            return False
        try:
            return bool(re.search(str(expected), str(actual), re.IGNORECASE))
        except re.error:
            return str(expected).lower() in str(actual).lower()

    if op == "pattern_match":
        if actual is None:
            return False
        try:
            return bool(re.search(str(expected), str(actual), re.IGNORECASE))
        except re.error:
            return str(expected).lower() in str(actual).lower()

    if op == "not_endswith_any":
        if not isinstance(expected, list) or not isinstance(actual, str):
            return False
        return not any(actual.endswith(str(s)) for s in expected)

    if op == "not_contains_any":
        if not isinstance(expected, list):
            return False
        if isinstance(actual, list):
            actual_lc = {_to_lc_str(x) for x in actual}
            return not any(_to_lc_str(n) in actual_lc for n in expected)
        haystack = _to_lc_str(actual)
        return not any(_to_lc_str(n) in haystack for n in expected)

    return False


def _eval_clause(clause: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate a clause dict (possibly nested) against an event."""
    for key, expected in clause.items():
        if key == "any_of":
            if not isinstance(expected, list) or not any(_eval_clause(sub, event) for sub in expected):
                return False
            continue
        if key == "all_of":
            if not isinstance(expected, list) or not all(_eval_clause(sub, event) for sub in expected):
                return False
            continue
        field, op = _split_op(key)
        if not _check(field, op, expected, event):
            return False
    return True


def matches(match_when: dict[str, Any], event: dict[str, Any]) -> bool:
    """Return True if ``event`` satisfies every clause in ``match_when``."""
    return _eval_clause(match_when, event)
