"""Pydantic validation tests for PlaybookStep bounds (H-7 / Batch 10).

The Pydantic field cap is the *first* line of defence — well-formed playbooks
that exceed the cap should fail to load instead of silently running.
"""

from __future__ import annotations

import pytest
from app.playbook.bounds import (
    ABSOLUTE_MAX_RETRIES,
    ABSOLUTE_MAX_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
)
from app.playbook.models import PlaybookStep, StepType
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# timeout_seconds bounds
# ---------------------------------------------------------------------------


class TestTimeoutSecondsField:
    def test_default_is_30_seconds(self) -> None:
        step = PlaybookStep(name="x", type=StepType.NOTIFY)
        assert step.timeout_seconds == 30

    def test_in_range_value_is_accepted(self) -> None:
        step = PlaybookStep(name="x", type=StepType.NOTIFY, timeout_seconds=120)
        assert step.timeout_seconds == 120

    def test_minimum_is_inclusive(self) -> None:
        step = PlaybookStep(
            name="x",
            type=StepType.NOTIFY,
            timeout_seconds=MIN_TIMEOUT_SECONDS,
        )
        assert step.timeout_seconds == MIN_TIMEOUT_SECONDS

    def test_below_minimum_is_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            PlaybookStep(name="x", type=StepType.NOTIFY, timeout_seconds=0)
        # Validation message should mention the bound to aid debugging.
        assert "greater than or equal" in str(exc.value).lower()

    def test_negative_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PlaybookStep(name="x", type=StepType.NOTIFY, timeout_seconds=-1)

    def test_maximum_is_inclusive(self) -> None:
        # 920s approval-wait timeouts (e.g. phishing-investigation playbook)
        # MUST still load — that scenario is exactly why the field cap is 1h
        # rather than the tighter 15-min runtime cap.
        step = PlaybookStep(
            name="approval",
            type=StepType.APPROVAL,
            timeout_seconds=920,
        )
        assert step.timeout_seconds == 920

    def test_at_absolute_max_is_accepted(self) -> None:
        step = PlaybookStep(
            name="x",
            type=StepType.APPROVAL,
            timeout_seconds=ABSOLUTE_MAX_TIMEOUT_SECONDS,
        )
        assert step.timeout_seconds == ABSOLUTE_MAX_TIMEOUT_SECONDS

    def test_above_absolute_max_is_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            PlaybookStep(
                name="x",
                type=StepType.NOTIFY,
                timeout_seconds=ABSOLUTE_MAX_TIMEOUT_SECONDS + 1,
            )
        assert "less than or equal" in str(exc.value).lower()

    def test_pathologically_large_is_rejected(self) -> None:
        # 1 day — the classic DoS payload.
        with pytest.raises(ValidationError):
            PlaybookStep(name="x", type=StepType.NOTIFY, timeout_seconds=86_400)


# ---------------------------------------------------------------------------
# retry_max bounds
# ---------------------------------------------------------------------------


class TestRetryMaxField:
    def test_default_is_zero(self) -> None:
        step = PlaybookStep(name="x", type=StepType.NOTIFY)
        assert step.retry_max == 0

    def test_zero_is_accepted(self) -> None:
        step = PlaybookStep(name="x", type=StepType.NOTIFY, retry_max=0)
        assert step.retry_max == 0

    def test_in_range_value_is_accepted(self) -> None:
        step = PlaybookStep(name="x", type=StepType.NOTIFY, retry_max=3)
        assert step.retry_max == 3

    def test_negative_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PlaybookStep(name="x", type=StepType.NOTIFY, retry_max=-1)

    def test_at_absolute_max_is_accepted(self) -> None:
        step = PlaybookStep(
            name="x",
            type=StepType.NOTIFY,
            retry_max=ABSOLUTE_MAX_RETRIES,
        )
        assert step.retry_max == ABSOLUTE_MAX_RETRIES

    def test_above_absolute_max_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PlaybookStep(
                name="x",
                type=StepType.NOTIFY,
                retry_max=ABSOLUTE_MAX_RETRIES + 1,
            )

    def test_pathologically_large_is_rejected(self) -> None:
        # Without a cap, retry_max=1_000_000 with a retry-on-failure step
        # would effectively never abort.
        with pytest.raises(ValidationError):
            PlaybookStep(name="x", type=StepType.NOTIFY, retry_max=1_000_000)


# ---------------------------------------------------------------------------
# Params bypass — Pydantic does NOT validate these. This pins the contract
# that the runtime clamp (in bounds.clamp_timeout) is the only defence.
# ---------------------------------------------------------------------------


class TestParamsAreNotValidated:
    """Document the field-vs-params split so anyone refactoring sees the gap."""

    def test_params_timeout_seconds_is_not_validated_by_pydantic(self) -> None:
        # An attacker could declare params.timeout_seconds=86400. Pydantic
        # cannot stop them because ``params`` is an untyped ``dict[str, Any]``.
        # This is the exact scenario that the runtime clamp in
        # ``engine._handle_osquery_live_query`` must catch.
        step = PlaybookStep(
            name="x",
            type=StepType.OSQUERY_LIVE_QUERY,
            params={"timeout_seconds": 86_400},  # pathological value
        )
        # No exception — Pydantic happily accepts arbitrary params content.
        assert step.params["timeout_seconds"] == 86_400
        # ...so the runtime clamp is load-bearing. See
        # ``test_osquery_live_query_step.py`` for the matching enforcement test.

    def test_params_retry_max_is_not_validated_by_pydantic(self) -> None:
        step = PlaybookStep(
            name="x",
            type=StepType.NOTIFY,
            params={"retry_max": 1_000_000},
        )
        assert step.params["retry_max"] == 1_000_000
