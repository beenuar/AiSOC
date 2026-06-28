"""Cron-parsing tests for the hunt scheduler — Phase 4.5.

These tests pin the behaviour of the croniter-backed cron parser that
replaced the bespoke 5-field parser. We exercise both ``_is_due`` and
``_next_fire_at`` directly so a regression in the parsing surface
fails *here* rather than in the slower end-to-end ``run_once`` tests.

The fallback branch (``_CRONITER_AVAILABLE = False``) is exercised by
:func:`test_fallback_path_handles_classic_cadences` — we monkeypatch
the module flag to simulate a deployment where the dependency hasn't
landed yet.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from app.workers import hunt_scheduler


def _make_hunt(*, schedule: str | None, last_run_at: datetime | None = None) -> Any:
    """Stand-in for :class:`app.models.saved_hunt.SavedHunt`."""
    hunt = MagicMock()
    hunt.id = uuid.uuid4()
    hunt.schedule = schedule
    hunt.last_run_at = last_run_at
    hunt.created_at = datetime(2026, 1, 1, tzinfo=UTC)
    return hunt


@pytest.mark.skipif(
    not hunt_scheduler._CRONITER_AVAILABLE,
    reason="croniter not installed in this environment; full-grammar tests are skipped",
)
class TestCronGrammarCoverage:
    """Cadences the bespoke parser never understood now work."""

    def test_weekday_only_schedule_fires_on_weekday(self) -> None:
        # Monday at 09:00 UTC, anchored on a Saturday so the parser
        # has to step forward through the weekend.
        hunt = _make_hunt(
            schedule="0 9 * * 1",
            last_run_at=datetime(2026, 1, 3, 0, 0, tzinfo=UTC),  # Sat
        )
        # Not yet due on Sunday at 23:59
        assert not hunt_scheduler._is_due(hunt, datetime(2026, 1, 4, 23, 59, tzinfo=UTC))
        # Due on Monday at 09:01
        assert hunt_scheduler._is_due(hunt, datetime(2026, 1, 5, 9, 1, tzinfo=UTC))

    def test_minute_range_schedule(self) -> None:
        """Cron schedule '5-10 * * * *' fires once per minute in [05..10]."""
        hunt = _make_hunt(
            schedule="5-10 * * * *",
            last_run_at=datetime(2026, 5, 15, 12, 5, tzinfo=UTC),
        )
        assert hunt_scheduler._is_due(hunt, datetime(2026, 5, 15, 12, 6, tzinfo=UTC))
        assert not hunt_scheduler._is_due(hunt, datetime(2026, 5, 15, 12, 5, 30, tzinfo=UTC))

    def test_minute_list_schedule(self) -> None:
        """Cron '0,15,30,45 * * * *' fires four times an hour."""
        hunt = _make_hunt(
            schedule="0,15,30,45 * * * *",
            last_run_at=datetime(2026, 5, 15, 12, 0, tzinfo=UTC),
        )
        assert not hunt_scheduler._is_due(hunt, datetime(2026, 5, 15, 12, 14, tzinfo=UTC))
        assert hunt_scheduler._is_due(hunt, datetime(2026, 5, 15, 12, 15, tzinfo=UTC))


class TestNextFireAt:
    """The helper used by ``_is_due`` to step a single tick forward."""

    def test_basic_hourly(self) -> None:
        next_at = hunt_scheduler._next_fire_at(
            "0 * * * *",
            after=datetime(2026, 5, 15, 12, 30, tzinfo=UTC),
        )
        assert next_at is not None
        assert next_at == datetime(2026, 5, 15, 13, 0, tzinfo=UTC)

    def test_invalid_schedule_returns_none(self) -> None:
        assert hunt_scheduler._next_fire_at("not a schedule", after=datetime.now(UTC)) is None


class TestIsDue:
    """The scheduler's go/no-go gate per hunt."""

    def test_empty_schedule_is_never_due(self) -> None:
        hunt = _make_hunt(schedule=None)
        assert not hunt_scheduler._is_due(hunt, datetime.now(UTC))

    def test_invalid_schedule_is_never_due(self) -> None:
        hunt = _make_hunt(schedule="garbage garbage garbage garbage garbage")
        assert not hunt_scheduler._is_due(hunt, datetime.now(UTC))

    def test_uses_created_at_when_last_run_at_missing(self) -> None:
        """A brand-new hunt should fire on the next matching minute,
        not 'one full cadence after save'."""
        hunt = _make_hunt(
            schedule="* * * * *",
            last_run_at=None,
        )
        hunt.created_at = datetime(2026, 5, 15, 12, 0, tzinfo=UTC)
        assert hunt_scheduler._is_due(hunt, datetime(2026, 5, 15, 12, 1, tzinfo=UTC))


class TestFallbackBehaviour:
    """Even without croniter the worker must recognise the historical cadences."""

    def test_fallback_path_handles_classic_cadences(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(hunt_scheduler, "_CRONITER_AVAILABLE", False)
        # Hourly.
        assert hunt_scheduler._fallback_interval_seconds_for("0 * * * *") == 3600
        # Every 5 minutes.
        assert hunt_scheduler._fallback_interval_seconds_for("*/5 * * * *") == 300
        # Daily at midnight.
        assert hunt_scheduler._fallback_interval_seconds_for("0 0 * * *") == 86400
        # Unknown cadence — returns None so the worker skips quietly.
        assert hunt_scheduler._fallback_interval_seconds_for("5-10 * * * *") is None
