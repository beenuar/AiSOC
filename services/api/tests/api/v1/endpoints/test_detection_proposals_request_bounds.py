"""Pydantic bounds tests for ``EvalAttachRequest`` / ``RunEvalRequest`` (H-7).

These pin the *first* line of defence against runaway eval subprocesses:
- ``max_regression_pp`` is capped at 50pp. Anything above that is
  indistinguishable from disabling the regression gate, so it MUST be
  rejected at the API boundary.
- ``timeout_seconds`` is capped at 600s (10 min). The synthetic benchmark
  completes in under 60s on commodity hardware; anything longer is almost
  certainly a stuck process and we don't want callers pinning a worker for
  15 minutes.

The matching server-side defence is in ``scripts/run_evals.py``, which also
imposes a wall-clock timeout via ``subprocess.run(timeout=...)``.
"""

from __future__ import annotations

import pytest
from app.api.v1.endpoints.detection_proposals import (
    EvalAttachRequest,
    RunEvalRequest,
)
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# max_regression_pp bounds (shared by both request models)
# ---------------------------------------------------------------------------


class TestMaxRegressionPpBounds:
    def test_default_is_one_pp(self) -> None:
        req = RunEvalRequest()
        assert req.max_regression_pp == 1.0

    def test_zero_is_inclusive(self) -> None:
        req = RunEvalRequest(max_regression_pp=0.0)
        assert req.max_regression_pp == 0.0

    def test_negative_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RunEvalRequest(max_regression_pp=-0.1)

    def test_in_range_value_is_accepted(self) -> None:
        req = RunEvalRequest(max_regression_pp=5.0)
        assert req.max_regression_pp == 5.0

    def test_at_cap_is_inclusive(self) -> None:
        req = RunEvalRequest(max_regression_pp=50.0)
        assert req.max_regression_pp == 50.0

    def test_above_cap_is_rejected_run_eval(self) -> None:
        with pytest.raises(ValidationError) as exc:
            RunEvalRequest(max_regression_pp=50.1)
        assert "less than or equal" in str(exc.value).lower()

    def test_above_cap_is_rejected_eval_attach(self) -> None:
        with pytest.raises(ValidationError):
            EvalAttachRequest(eval_report={"x": 1}, max_regression_pp=99.9)

    def test_pathological_value_is_rejected(self) -> None:
        # 1000pp would effectively disable the gate entirely.
        with pytest.raises(ValidationError):
            RunEvalRequest(max_regression_pp=1000.0)

    def test_eval_attach_in_range_value_is_accepted(self) -> None:
        req = EvalAttachRequest(eval_report={"score": 0.9}, max_regression_pp=2.5)
        assert req.max_regression_pp == 2.5


# ---------------------------------------------------------------------------
# timeout_seconds bounds (RunEvalRequest only)
# ---------------------------------------------------------------------------


class TestTimeoutSecondsBounds:
    def test_default_is_180_seconds(self) -> None:
        req = RunEvalRequest()
        assert req.timeout_seconds == 180

    def test_minimum_is_ten_seconds(self) -> None:
        req = RunEvalRequest(timeout_seconds=10)
        assert req.timeout_seconds == 10

    def test_below_minimum_is_rejected(self) -> None:
        # 1s is unreasonable — the runner can't even import its deps in 1s.
        with pytest.raises(ValidationError):
            RunEvalRequest(timeout_seconds=5)

    def test_zero_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RunEvalRequest(timeout_seconds=0)

    def test_negative_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RunEvalRequest(timeout_seconds=-1)

    def test_in_range_value_is_accepted(self) -> None:
        req = RunEvalRequest(timeout_seconds=300)
        assert req.timeout_seconds == 300

    def test_at_cap_is_inclusive(self) -> None:
        req = RunEvalRequest(timeout_seconds=600)
        assert req.timeout_seconds == 600

    def test_above_cap_is_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            RunEvalRequest(timeout_seconds=601)
        assert "less than or equal" in str(exc.value).lower()

    def test_pathological_value_is_rejected(self) -> None:
        # 1 day — the classic DoS payload against a subprocess endpoint.
        with pytest.raises(ValidationError):
            RunEvalRequest(timeout_seconds=86_400)

    def test_legacy_900s_cap_is_now_rejected(self) -> None:
        """The pre-H-7 cap was 900s; this test pins the new tighter cap.

        Anyone bumping the cap back up needs to update this test and
        explain why in the PR — the eval suite completes in <60s, so
        anything longer than 10 min is almost certainly a stuck process.
        """
        with pytest.raises(ValidationError):
            RunEvalRequest(timeout_seconds=900)


# ---------------------------------------------------------------------------
# Combined: both fields at extremes
# ---------------------------------------------------------------------------


class TestCombined:
    def test_both_at_cap_accepted(self) -> None:
        req = RunEvalRequest(max_regression_pp=50.0, timeout_seconds=600)
        assert req.max_regression_pp == 50.0
        assert req.timeout_seconds == 600

    def test_both_above_cap_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RunEvalRequest(max_regression_pp=51.0, timeout_seconds=601)

    def test_eval_attach_does_not_accept_timeout_seconds(self) -> None:
        """EvalAttachRequest is the *report-attach* path — there is no
        subprocess to time out, so it should not accept timeout_seconds.

        This is a regression guard: if someone refactors the two request
        models into a shared base, they MUST consciously decide whether
        EvalAttachRequest should also be timeout-bounded.
        """
        # Pydantic v2 ignores unknown fields by default unless extra='forbid'.
        # Either behaviour is fine; what matters is the field isn't *active*.
        req = EvalAttachRequest(eval_report={"score": 0.9})
        assert not hasattr(req, "timeout_seconds")
