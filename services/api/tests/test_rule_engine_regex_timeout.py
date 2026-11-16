"""SEC-4: analyst-authored patterns in the rule engine are bounded (#1943).

The stdlib `re` is a backtracker: one catastrophic pattern in an analyst- or
LLM-authored rule body pins a CPU for the lifetime of the process, and
`/detection/test`, `/rules/{id}/execute` and `run_hunt` all compile such
bodies. Two sites execute analyst input:

* `_run_regex` — the regex rule runner; now compiled on the `regex` engine
  and searched with `timeout=`, failing closed on TimeoutError.
* `_kql_match` — the KQL wildcard branch; the value was dropped into the
  engine raw (regex injection *and* unbounded backtracking) and is now
  escaped-then-globbed, the same construction the module's wildcard rule
  branch already used.
"""

from __future__ import annotations

import time

import pytest
from app.services import rule_engine

#: A classic catastrophic-backtracking pattern over an input chosen so the
#: stdlib engine would spend minutes, not milliseconds.
CATASTROPHIC = r"(a|a)*$"
PAYLOAD_EVENT = {"message": "a" * 48 + "b"}


def test_a_catastrophic_pattern_returns_within_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """The live ReDoS proof: bounded return, honest error, no hang.

    The budget is dropped to 0.2s so the suite stays fast; the assertion
    gives generous slack for a loaded CI worker while still proving the
    return is budget-shaped, not backtracking-shaped (minutes).
    """
    monkeypatch.setattr(rule_engine, "REGEX_TIMEOUT_SECONDS", 0.2)
    started = time.monotonic()
    matched, err = rule_engine._run_regex(CATASTROPHIC, [PAYLOAD_EVENT])
    elapsed = time.monotonic() - started

    assert matched == []
    assert err is not None and "timed out" in err
    assert elapsed < 5.0, f"bounded search still took {elapsed:.1f}s — the timeout is not being applied"


def test_a_benign_pattern_still_matches() -> None:
    matched, err = rule_engine._run_regex(r"ssh.*failed", [{"message": "SSH login FAILED for root"}, {"message": "ok"}])
    assert err is None
    assert len(matched) == 1


def test_an_invalid_pattern_is_an_error_not_a_raise() -> None:
    matched, err = rule_engine._run_regex(r"(unclosed", [{"x": 1}])
    assert matched == []
    assert err is not None


def test_timeout_is_env_tunable(monkeypatch: pytest.MonkeyPatch) -> None:
    """The budget is read from AISOC_REGEX_TIMEOUT_SECONDS at import; pin the
    default and the env override path."""
    import importlib

    monkeypatch.setenv("AISOC_REGEX_TIMEOUT_SECONDS", "7.5")
    reloaded = importlib.reload(rule_engine)
    try:
        assert reloaded.REGEX_TIMEOUT_SECONDS == 7.5
    finally:
        monkeypatch.delenv("AISOC_REGEX_TIMEOUT_SECONDS")
        importlib.reload(rule_engine)
    assert rule_engine.REGEX_TIMEOUT_SECONDS == 2.0


# ─────────────────────────────────────────────────────────────────────────────
# The KQL wildcard branch (carry review addition)
# ─────────────────────────────────────────────────────────────────────────────


def test_kql_wildcard_is_a_glob_not_a_regex() -> None:
    """Metacharacters in a KQL value must match literally; only `*` globs."""
    # `.` must not be a wildcard: "a.c" must not match "abc".
    assert rule_engine._kql_match('field:"a.c"', {"field": "a.c"}) is True
    assert rule_engine._kql_match('field:"a.c*"', {"field": "a.cxx"}) is True
    assert rule_engine._kql_match('field:"a.c*"', {"field": "abcxx"}) is False


def test_kql_wildcard_catastrophic_value_cannot_backtrack() -> None:
    """The pre-fix code compiled the raw value, so `(a+)+$...` was a live
    ReDoS; escaped, it is a cheap literal non-match."""
    query = 'field:"(a+)+$zzz*"'
    event = {"field": "a" * 64}
    started = time.monotonic()
    result = rule_engine._kql_match(query, event)
    elapsed = time.monotonic() - started
    assert result is False
    assert elapsed < 1.0, f"KQL wildcard match took {elapsed:.1f}s — the value is still being compiled raw"
