"""Unit tests for the playbook runtime bounds module (H-7 / Batch 10).

These tests pin the contract that *both* Pydantic field bounds and runtime
``clamp_*`` calls must honour, so the security guarantee survives refactors
to either side of the layered defence (handlers vs. model).
"""

from __future__ import annotations

import importlib

import pytest
from app.playbook import bounds

# ---------------------------------------------------------------------------
# Constants — these are part of the security contract; if anyone tightens or
# loosens them they should have to update a test.
# ---------------------------------------------------------------------------


class TestConstants:
    def test_min_timeout_is_positive(self) -> None:
        assert bounds.MIN_TIMEOUT_SECONDS >= 1

    def test_pydantic_field_cap_above_param_cap(self) -> None:
        """Pydantic field cap must be >= runtime param cap.

        Pydantic field covers approval-step human-waits (≤1h). Param cap is
        the tighter ceiling enforced at runtime for handler-driven values
        (≤15min). Inverting these would either break approval playbooks or
        defeat the runtime guard.
        """
        assert bounds.ABSOLUTE_MAX_TIMEOUT_SECONDS >= bounds.ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS

    def test_param_cap_is_tighter_than_field_cap(self) -> None:
        # If these ever become equal, delete one — the layering loses meaning.
        assert bounds.ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS < bounds.ABSOLUTE_MAX_TIMEOUT_SECONDS

    def test_defaults_within_absolute_bounds(self) -> None:
        assert bounds.MIN_TIMEOUT_SECONDS <= bounds.DEFAULT_MAX_TIMEOUT_SECONDS <= bounds.ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS
        assert 0 <= bounds.DEFAULT_MAX_RETRIES <= bounds.ABSOLUTE_MAX_RETRIES


# ---------------------------------------------------------------------------
# clamp_timeout
# ---------------------------------------------------------------------------


class TestClampTimeout:
    def test_in_range_value_passes_through(self) -> None:
        assert bounds.clamp_timeout(60) == 60

    def test_value_at_default_max_passes_through(self) -> None:
        # No env override → ceiling is DEFAULT_MAX_TIMEOUT_SECONDS.
        assert bounds.clamp_timeout(bounds.DEFAULT_MAX_TIMEOUT_SECONDS) == (bounds.DEFAULT_MAX_TIMEOUT_SECONDS)

    def test_value_above_default_max_is_clamped(self) -> None:
        result = bounds.clamp_timeout(86400)  # 1 day — pathological
        assert result == bounds.DEFAULT_MAX_TIMEOUT_SECONDS

    def test_negative_value_is_clamped_to_min(self) -> None:
        assert bounds.clamp_timeout(-1) == bounds.MIN_TIMEOUT_SECONDS

    def test_zero_is_clamped_to_min(self) -> None:
        assert bounds.clamp_timeout(0) == bounds.MIN_TIMEOUT_SECONDS

    def test_none_uses_fallback(self) -> None:
        assert bounds.clamp_timeout(None, default=45) == 45

    def test_none_without_fallback_uses_step_default(self) -> None:
        # Mirrors PlaybookStep.timeout_seconds default (30).
        assert bounds.clamp_timeout(None) == 30

    def test_bool_true_does_not_become_one(self) -> None:
        """Bools must NOT be coerced to int.

        ``int(True) == 1`` would otherwise silently set timeout=1 for any
        truthy misconfiguration, which is both surprising and DoS-prone
        because it short-circuits long-running queries.
        """
        result = bounds.clamp_timeout(True, default=60)
        assert result == 60

    def test_bool_false_uses_fallback(self) -> None:
        result = bounds.clamp_timeout(False, default=45)
        assert result == 45

    def test_non_numeric_string_uses_fallback(self) -> None:
        assert bounds.clamp_timeout("forever", default=42) == 42

    def test_numeric_string_is_parsed(self) -> None:
        # Operators sometimes pass numeric strings from YAML.
        assert bounds.clamp_timeout("90") == 90

    def test_float_is_truncated_to_int(self) -> None:
        assert bounds.clamp_timeout(12.7) == 12

    def test_env_override_raises_ceiling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS", "600")
        # 500 should now pass through (was previously clamped to 300).
        assert bounds.clamp_timeout(500) == 500

    def test_env_override_cannot_exceed_param_absolute_max(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Env override must itself be clamped to ABSOLUTE_MAX_PARAM_*.

        Otherwise an operator typo (``AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS=86400``)
        would silently uncap the runtime guard and re-introduce the very DoS
        this module exists to prevent.
        """
        monkeypatch.setenv("AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS", "100000")
        # The effective ceiling should be ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS,
        # not 100000 or the Pydantic field cap.
        result = bounds.clamp_timeout(50000)
        assert result == bounds.ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS

    def test_env_override_garbage_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS", "not-a-number")
        # 500 must still be clamped to DEFAULT_MAX_TIMEOUT_SECONDS since the
        # env value is unusable.
        assert bounds.clamp_timeout(500) == bounds.DEFAULT_MAX_TIMEOUT_SECONDS

    def test_env_override_below_min_is_clamped_up(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS", "-10")
        # Ceiling clamped to MIN_TIMEOUT_SECONDS, so any value above that
        # collapses to MIN.
        assert bounds.clamp_timeout(100) == bounds.MIN_TIMEOUT_SECONDS


# ---------------------------------------------------------------------------
# clamp_retries
# ---------------------------------------------------------------------------


class TestClampRetries:
    def test_in_range_value_passes_through(self) -> None:
        assert bounds.clamp_retries(3) == 3

    def test_zero_is_allowed(self) -> None:
        # 0 means "no retries"; must not be coerced to MIN of 1.
        assert bounds.clamp_retries(0) == 0

    def test_negative_value_is_clamped_to_zero(self) -> None:
        assert bounds.clamp_retries(-5) == 0

    def test_value_above_default_max_is_clamped(self) -> None:
        assert bounds.clamp_retries(9999) == bounds.DEFAULT_MAX_RETRIES

    def test_none_uses_default(self) -> None:
        assert bounds.clamp_retries(None) == 0
        assert bounds.clamp_retries(None, default=2) == 2

    def test_bool_uses_fallback(self) -> None:
        # Same anti-coercion guarantee as clamp_timeout.
        assert bounds.clamp_retries(True, default=4) == 4

    def test_non_numeric_string_uses_fallback(self) -> None:
        assert bounds.clamp_retries("nope", default=1) == 1

    def test_env_override_cannot_exceed_absolute_max(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AISOC_PLAYBOOK_MAX_RETRIES", "1000")
        # Ceiling is hard-clamped to ABSOLUTE_MAX_RETRIES.
        assert bounds.clamp_retries(500) == bounds.ABSOLUTE_MAX_RETRIES


# ---------------------------------------------------------------------------
# Effective ceilings
# ---------------------------------------------------------------------------


class TestEffectiveCeilings:
    def test_max_timeout_seconds_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS", raising=False)
        assert bounds.max_timeout_seconds() == bounds.DEFAULT_MAX_TIMEOUT_SECONDS

    def test_max_timeout_seconds_clamped_to_param_absolute(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(
            "AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS",
            str(bounds.ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS + 10_000),
        )
        # Even with a huge env value, the function clamps to the param cap,
        # NOT the looser Pydantic field cap.
        assert bounds.max_timeout_seconds() == bounds.ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS

    def test_max_retries_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AISOC_PLAYBOOK_MAX_RETRIES", raising=False)
        assert bounds.max_retries() == bounds.DEFAULT_MAX_RETRIES

    def test_empty_env_value_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Empty string (e.g. ``AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS=``) must be
        # treated as unset, not as invalid int.
        monkeypatch.setenv("AISOC_PLAYBOOK_MAX_TIMEOUT_SECONDS", "")
        assert bounds.max_timeout_seconds() == bounds.DEFAULT_MAX_TIMEOUT_SECONDS


# ---------------------------------------------------------------------------
# Module-level invariants
# ---------------------------------------------------------------------------


def test_module_reload_is_safe() -> None:
    """The module must not have any startup side effects that break reloads."""
    importlib.reload(bounds)
    assert callable(bounds.clamp_timeout)
    assert callable(bounds.clamp_retries)


def test_all_export_is_complete() -> None:
    """``__all__`` should expose every public symbol used by callers."""
    required = {
        "ABSOLUTE_MAX_PARAM_TIMEOUT_SECONDS",
        "ABSOLUTE_MAX_RETRIES",
        "ABSOLUTE_MAX_TIMEOUT_SECONDS",
        "DEFAULT_MAX_RETRIES",
        "DEFAULT_MAX_TIMEOUT_SECONDS",
        "MIN_TIMEOUT_SECONDS",
        "clamp_retries",
        "clamp_timeout",
        "max_retries",
        "max_timeout_seconds",
    }
    assert required.issubset(set(bounds.__all__))
