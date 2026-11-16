"""Tests for the resolved->closed auto-close sweep (pure logic)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.workers.case_auto_close import AutoCloseSweepResult, cutoff


def test_cutoff_is_days_in_the_past():
    now = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    assert cutoff(now, 7) == datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
    assert cutoff(now, 0) == now


def test_cutoff_selects_only_past_window():
    now = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    boundary = cutoff(now, 7)
    assert (now - timedelta(days=7)) <= boundary
    assert (now - timedelta(days=7, hours=-1)) > boundary


def test_sweep_result_defaults_empty():
    result = AutoCloseSweepResult()
    assert result.closed == 0
    assert result.failed == 0
    assert result.by_tenant == {}


@pytest.mark.parametrize("days", [1, 7, 30])
def test_cutoff_monotonic_in_days(days):
    now = datetime(2026, 11, 16, tzinfo=UTC)
    assert cutoff(now, days) == now - timedelta(days=days)
