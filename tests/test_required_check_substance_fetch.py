"""Unit tests for `fetch_successful_push_runs` in `scripts/check_required_check_substance.py`.

The staleness refusal and the grading window used to share one query: the
runs endpoint was asked for *successful* push runs only, and "none of the
newest five matches a recent commit" was read as a stale API snapshot. A
workflow that genuinely failed on 30+ consecutive commits produced the same
signature, and for `grading-integrity.yml` itself that was self-locking —
each push run failing the staleness check was the reason no recent
successful run existed, so no future run could ever pass. Measured on
`main`: green through 2026-10-05T06:31Z, then every push run red, with the
original trigger being a merge burst that outran `ci.yml`'s successful runs.

These tests hold the two directions apart:

- a failure streak whose *failed* runs are for recent commits is graded
  (the successful runs in the page are returned), not refused;
- a snapshot containing no run of any conclusion for a recent commit is
  still refused, because that is the stale read the refusal exists for.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "check_required_check_substance",
    Path(__file__).resolve().parent.parent / "scripts" / "check_required_check_substance.py",
)
assert _SPEC and _SPEC.loader
gate = importlib.util.module_from_spec(_SPEC)
sys.modules["check_required_check_substance"] = gate
_SPEC.loader.exec_module(gate)


def _run(run_id: int, created_at: str, head_sha: str, conclusion: str | None) -> dict:
    return {"id": run_id, "created_at": created_at, "head_sha": head_sha, "conclusion": conclusion}


def _serve(monkeypatch: pytest.MonkeyPatch, runs: list[dict]) -> None:
    monkeypatch.setattr(gate, "_get", lambda url, token: {"workflow_runs": runs})
    monkeypatch.setattr(gate, "FETCH_RETRY_SECONDS", 0)


FRESH = {f"fresh-{i:02d}" for i in range(30)}


def test_a_failure_streak_is_graded_not_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """Failed runs for recent commits prove the read is fresh; the successes are graded.

    This is the exact shape that locked `main`: every push run since the
    burst red, every successful run older than the 30-commit window. The old
    query (successes only) could not see the failures, called the read stale,
    and raised — which kept the streak going.
    """
    streak = [_run(100 + i, f"2026-10-07T00:{59 - i:02d}:00Z", f"fresh-{i:02d}", "failure") for i in range(10)]
    older = [_run(50 + i, f"2026-10-05T0{2 + i}:00:00Z", f"old-{i}", "success") for i in range(4)]
    _serve(monkeypatch, streak + older)

    runs = gate.fetch_successful_push_runs("o/r", "tok", "wf.yml", "main", 80, set(FRESH))

    assert [r["id"] for r in runs] == [53, 52, 51, 50]
    assert all(r["conclusion"] == "success" for r in runs)


def test_an_in_progress_run_for_head_proves_freshness(monkeypatch: pytest.MonkeyPatch) -> None:
    """On a push event the run executing the gate is itself in the list.

    Its conclusion is still null, so a success-only query never saw it; it is
    the strongest freshness proof there is, because a stale snapshot cannot
    contain the run that is reading it.
    """
    me = _run(200, "2026-10-07T01:00:00Z", "fresh-00", None)
    older = [_run(50 + i, f"2026-10-05T0{2 + i}:00:00Z", f"old-{i}", "success") for i in range(3)]
    _serve(monkeypatch, [me, *older])

    runs = gate.fetch_successful_push_runs("o/r", "tok", "wf.yml", "main", 80, set(FRESH))

    assert [r["id"] for r in runs] == [52, 51, 50]


def test_a_stale_snapshot_is_still_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """No run of any conclusion for a recent commit is the stale read the refusal exists for."""
    stale = [_run(10 + i, f"2026-08-11T0{i}:00:00Z", f"ancient-{i}", c) for i, c in enumerate(["success", "failure", "success"])]
    _serve(monkeypatch, stale)

    with pytest.raises(gate.GateError, match="stale read"):
        gate.fetch_successful_push_runs("o/r", "tok", "wf.yml", "main", 80, set(FRESH))


def test_only_successes_are_graded_and_newest_first(monkeypatch: pytest.MonkeyPatch) -> None:
    mixed = [
        _run(1, "2026-10-07T00:10:00Z", "fresh-00", "failure"),
        _run(2, "2026-10-07T00:09:00Z", "fresh-01", "success"),
        _run(3, "2026-10-07T00:08:00Z", "fresh-02", "cancelled"),
        _run(4, "2026-10-07T00:07:00Z", "fresh-03", "success"),
        _run(5, "2026-10-07T00:06:00Z", "fresh-04", "success"),
    ]
    _serve(monkeypatch, list(reversed(mixed)))  # the endpoint's order is not trusted

    runs = gate.fetch_successful_push_runs("o/r", "tok", "wf.yml", "main", 2, set(FRESH))

    assert [r["id"] for r in runs] == [2, 4]


def test_no_oracle_returns_successes_without_the_check(monkeypatch: pytest.MonkeyPatch) -> None:
    """A path-filtered workflow legitimately has no run for a recent commit."""
    _serve(
        monkeypatch,
        [
            _run(1, "2026-09-01T00:00:00Z", "whatever", "success"),
            _run(2, "2026-09-02T00:00:00Z", "whatever", "failure"),
        ],
    )

    runs = gate.fetch_successful_push_runs("o/r", "tok", "wf.yml", "main", 80, None)

    assert [r["id"] for r in runs] == [1]
