"""SEC-4: the regex rule runner must bound execution time.

The stdlib `re` is a backtracker: one catastrophic pattern in an analyst- or
LLM-authored rule body pins a CPU for the lifetime of the process, and
`/detection/test`, `/rules/{id}/execute` and `run_hunt` all compile such
bodies. The runner now uses the `regex` engine's bounded `.search(timeout=)`
and fails closed on a timeout rather than hanging the worker.
"""

from __future__ import annotations

import inspect

from app.services import rule_engine


def test_runner_uses_the_bounded_regex_engine():
    # The module aliases `re` to the `regex` engine so every call site gains
    # the timeout; verify the alias is in place and not stdlib.
    assert rule_engine.re.__name__ == "regex", "rule_engine did not swap in the bounded regex engine"


def test_run_regex_passes_a_timeout_to_search():
    src = inspect.getsource(rule_engine._run_regex)
    assert "timeout=REGEX_TIMEOUT_SECONDS" in src, "_run_regex does not bound the search"


def test_run_regex_fails_closed_on_timeout(monkeypatch):
    """A pattern that outruns the budget returns an error, not a hang."""

    class _Boom:
        def search(self, payload, timeout=None):  # noqa: ARG002
            raise TimeoutError

    monkeypatch.setattr(rule_engine.re, "compile", lambda *a, **k: _Boom())
    matched, err = rule_engine._run_regex("(a+)+$", [{"x": "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"}])
    assert matched == []
    assert err is not None and "timed out" in err


def test_timeout_is_env_tunable():
    import os

    assert hasattr(rule_engine, "REGEX_TIMEOUT_SECONDS")
    assert rule_engine.REGEX_TIMEOUT_SECONDS == float(os.environ.get("AISOC_REGEX_TIMEOUT_SECONDS", "2.0"))
